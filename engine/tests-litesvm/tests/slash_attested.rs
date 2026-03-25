//! Real-SVM integration test for the M9 identifiable-abort slash.
//!
//! The program's unit tests prove the *pure logic* (digest identity, Ed25519
//! parser, threshold math). This test proves the thing those cannot: that
//! `slash_operator_attested`, run inside a real Solana VM transaction, with a
//! real Ed25519 native-program sibling instruction the runtime actually
//! verifies, ACTUALLY MOVES A BOND from the protocol vault into the slash pool
//! and jails the culprit — and that a minority (sub-threshold) attestation is
//! REJECTED on-chain with the right error.
//!
//! Framework choice: litesvm (solana-2.x native, in-process, no validator
//! process, bundles the Ed25519 + Token-2022 native programs). It lives in a
//! separate crate/lock so it cannot churn the program's pinned SBF build lock.

use litesvm::LiteSVM;
use solana_sdk::{
    account::Account as SolAccount,
    instruction::{AccountMeta, Instruction},
    program_pack::Pack,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    sysvar,
    transaction::Transaction,
};
use spl_token_2022::state::{Account as TokenAccount, AccountState, Mint};

// ── Program constants mirrored from the on-chain code (kept in sync by the
//    asserts below, which would fail loudly if a seed/discriminator drifted). ──

const PROGRAM_ID: Pubkey =
    solana_sdk::pubkey!("4xy9dYHfAzi7cAcX5JHxNR6EoMJ9PGfeQDMHx6YUQQM6");

// Anchor instruction discriminators, lifted from target/idl/distin.json.
const D_INITIALIZE: [u8; 8] = [175, 175, 109, 31, 13, 152, 155, 237];
const D_REGISTER: [u8; 8] = [49, 242, 151, 125, 212, 136, 31, 89];
const D_SLASH_ATTESTED: [u8; 8] = [210, 62, 213, 104, 28, 222, 98, 77];

const PROTOCOL_SEED: &[u8] = b"protocol";
const BOND_VAULT_SEED: &[u8] = b"bond_vault";
const SLASH_POOL_SEED: &[u8] = b"slash_pool";
const OPERATOR_SEED: &[u8] = b"operator";

const DECIMALS: u8 = 9;
const MIN_BOND: u64 = 1_000_000_000; // 1 token
const BOND: u64 = 5_000_000_000; // 5 tokens per operator
const SLASH_AMT: u64 = 3_000_000_000; // 3 tokens slashed
// 5000 bps over 3 operators ⇒ required_attesters = ceil(3*5000/10000) = 2.
// A culprit cannot attest against itself, so the two remaining honest operators
// (op1 + op2) are exactly the quorum; a single attester (1 < 2) is rejected.
// Note: at 6667 bps the required count would be ceil(2.0001)=3, which a 3-op set
// can never reach for a culprit-excluded report — that is a genuine
// parameterization constraint, called out in DEPLOY.md / SECURITY.md.
const THRESHOLD_BPS: u16 = 5_000;

fn token_program_id() -> Pubkey {
    spl_token_2022::id()
}

// ── Token-2022 account injection. We pack real Token-2022 `Mint`/`Account`
//    state and drop it straight into the SVM, so the program's
//    `transfer_checked` CPI runs against genuine Token-2022 accounts. ──

fn pack_mint(svm: &mut LiteSVM, mint: &Pubkey, authority: &Pubkey) {
    let mut data = vec![0u8; Mint::LEN];
    Mint {
        mint_authority: Some(*authority).into(),
        supply: 1_000_000_000_000_000,
        decimals: DECIMALS,
        is_initialized: true,
        freeze_authority: None.into(),
    }
    .pack_into_slice(&mut data);
    svm.set_account(
        *mint,
        SolAccount {
            lamports: 1_000_000_000,
            data,
            owner: token_program_id(),
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
}

fn pack_token_account(
    svm: &mut LiteSVM,
    addr: &Pubkey,
    mint: &Pubkey,
    owner: &Pubkey,
    amount: u64,
) {
    let mut data = vec![0u8; TokenAccount::LEN];
    TokenAccount {
        mint: *mint,
        owner: *owner,
        amount,
        delegate: None.into(),
        state: AccountState::Initialized,
        is_native: None.into(),
        delegated_amount: 0,
        close_authority: None.into(),
    }
    .pack_into_slice(&mut data);
    svm.set_account(
        *addr,
        SolAccount {
            lamports: 1_000_000_000,
            data,
            owner: token_program_id(),
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
}

fn token_amount(svm: &LiteSVM, addr: &Pubkey) -> u64 {
    let acc = svm.get_account(addr).expect("token account exists");
    TokenAccount::unpack(&acc.data).expect("valid token account").amount
}

// ── The on-chain `Operator` account layout (state.rs), so we can read the
//    culprit's bond/jailed flag after the slash. Anchor prefixes 8 disc bytes. ──

struct OperatorView {
    bonded_amount: u64,
    jailed: bool,
    slash_count: u32,
}

fn read_operator(svm: &LiteSVM, op: &Pubkey) -> OperatorView {
    let acc = svm.get_account(op).expect("operator account");
    let d = &acc.data[8..]; // skip Anchor discriminator
    // protocol 32 | authority 32 | group_pubkey 33 | attestation_pubkey 32 |
    // bonded_amount u64 | stake_weight u64 | partials_submitted u64 |
    // slash_count u32 | jailed bool | unbonding_at u64 | joined_slot u64 | bump u8
    let mut off = 32 + 32 + 33 + 32;
    let bonded_amount = u64::from_le_bytes(d[off..off + 8].try_into().unwrap());
    off += 8 + 8 + 8; // stake_weight + partials_submitted
    let slash_count = u32::from_le_bytes(d[off..off + 4].try_into().unwrap());
    off += 4;
    let jailed = d[off] != 0;
    OperatorView { bonded_amount, jailed, slash_count }
}

// ── The fault-report digest — byte-identical to `FaultReport.digest32` in
//    engine/kobe-ecdsa/net/fault.go AND to `fault_report_digest` in the
//    program. The cross-language identity is pinned in the program's unit test
//    (`fault_digest_matches_go_vector`); here we reproduce the encoder so the
//    Ed25519 signatures we feed in are over exactly what the program checks. ──

fn fault_report_digest(
    session: &[u8],
    message_hash: &[u8; 32],
    round: u32,
    culprit_global: u32,
    culprit_pubkey: &[u8; 32],
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"distin-fault-report-v1\x00");
    h.update((session.len() as u32).to_be_bytes());
    h.update(session);
    h.update((message_hash.len() as u32).to_be_bytes());
    h.update(message_hash);
    h.update(round.to_be_bytes());
    h.update(culprit_global.to_be_bytes());
    h.update((culprit_pubkey.len() as u32).to_be_bytes());
    h.update(culprit_pubkey);
    h.finalize().into()
}

// ── Instruction builders ──

fn pda(seeds: &[&[u8]]) -> (Pubkey, u8) {
    Pubkey::find_program_address(seeds, &PROGRAM_ID)
}

#[allow(clippy::too_many_arguments)]
fn ix_initialize(
    admin: &Pubkey,
    protocol: &Pubkey,
    bond_mint: &Pubkey,
    bond_vault: &Pubkey,
    slash_pool: &Pubkey,
    lst_price_feed: &Pubkey,
) -> Instruction {
    let mut data = D_INITIALIZE.to_vec();
    data.extend_from_slice(&THRESHOLD_BPS.to_le_bytes());
    data.extend_from_slice(&MIN_BOND.to_le_bytes());
    data.extend_from_slice(&100u64.to_le_bytes()); // unbonding_slots
    data.extend_from_slice(&0u64.to_le_bytes()); // request_fee
    data.extend_from_slice(&1000u64.to_le_bytes()); // max_validity_slots
    data.extend_from_slice(lst_price_feed.as_ref());
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*admin, true),
            AccountMeta::new(*protocol, false),
            AccountMeta::new_readonly(*bond_mint, false),
            AccountMeta::new(*bond_vault, false),
            AccountMeta::new(*slash_pool, false),
            AccountMeta::new_readonly(token_program_id(), false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(sysvar::rent::id(), false),
        ],
        data,
    }
}

#[allow(clippy::too_many_arguments)]
fn ix_register(
    authority: &Pubkey,
    protocol: &Pubkey,
    operator: &Pubkey,
    bond_mint: &Pubkey,
    operator_token: &Pubkey,
    bond_vault: &Pubkey,
    lst_price_feed: &Pubkey,
    attestation_pubkey: [u8; 32],
) -> Instruction {
    let mut data = D_REGISTER.to_vec();
    data.extend_from_slice(&[0u8; 33]); // group_pubkey (unused by this path)
    data.extend_from_slice(&attestation_pubkey);
    data.extend_from_slice(&BOND.to_le_bytes());
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*authority, true),
            AccountMeta::new(*protocol, false),
            AccountMeta::new(*operator, false),
            AccountMeta::new_readonly(*bond_mint, false),
            AccountMeta::new(*operator_token, false),
            AccountMeta::new(*bond_vault, false),
            AccountMeta::new_readonly(*lst_price_feed, false),
            AccountMeta::new_readonly(token_program_id(), false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
        data,
    }
}

#[allow(clippy::too_many_arguments)]
fn ix_slash_attested(
    relayer: &Pubkey,
    protocol: &Pubkey,
    culprit_op: &Pubkey,
    bond_mint: &Pubkey,
    bond_vault: &Pubkey,
    slash_pool: &Pubkey,
    lst_price_feed: &Pubkey,
    attester_ops: &[Pubkey],
    amount: u64,
    session: &str,
    message_hash: [u8; 32],
    round: u32,
    culprit_global: u32,
) -> Instruction {
    let mut data = D_SLASH_ATTESTED.to_vec();
    data.extend_from_slice(&amount.to_le_bytes());
    data.extend_from_slice(&(session.len() as u32).to_le_bytes()); // Borsh String len
    data.extend_from_slice(session.as_bytes());
    data.extend_from_slice(&message_hash);
    data.extend_from_slice(&round.to_le_bytes());
    data.extend_from_slice(&culprit_global.to_le_bytes());

    let mut accounts = vec![
        AccountMeta::new(*relayer, true),
        AccountMeta::new(*protocol, false),
        AccountMeta::new(*culprit_op, false),
        AccountMeta::new_readonly(*bond_mint, false),
        AccountMeta::new(*bond_vault, false),
        AccountMeta::new(*slash_pool, false),
        AccountMeta::new_readonly(*lst_price_feed, false),
        AccountMeta::new_readonly(token_program_id(), false),
        AccountMeta::new_readonly(sysvar::instructions::id(), false),
    ];
    // Attester Operator accounts ride in remaining_accounts.
    for op in attester_ops {
        accounts.push(AccountMeta::new_readonly(*op, false));
    }
    Instruction { program_id: PROGRAM_ID, accounts, data }
}

/// Build a real Ed25519 native-program instruction that verifies a signature
/// from each `signer` over `digest`. `ed25519_instruction::new_ed25519_instruction`
/// only supports one signature, so we assemble the multi-signature payload the
/// same way the SDK does (and the same layout the program's parser reads).
fn ed25519_verify_ix(signers: &[(&ed25519_dalek::SigningKey, [u8; 32])], digest: &[u8; 32]) -> Instruction {
    use ed25519_dalek::Signer as _;
    const HEADER: usize = 2;
    const OFFSETS: usize = 14; // Ed25519SignatureOffsets
    let n = signers.len();
    let mut data = vec![0u8; HEADER + n * OFFSETS];
    data[0] = n as u8; // num_signatures
                       // data[1] padding stays 0
    for (i, (sk, _pk)) in signers.iter().enumerate() {
        let sig = sk.sign(digest).to_bytes();
        let pk = sk.verifying_key().to_bytes();

        let sig_off = data.len() as u16;
        data.extend_from_slice(&sig);
        let pk_off = data.len() as u16;
        data.extend_from_slice(&pk);
        let msg_off = data.len() as u16;
        data.extend_from_slice(digest);

        let base = HEADER + i * OFFSETS;
        let here: u16 = 0xffff; // "this instruction"
        data[base..base + 2].copy_from_slice(&sig_off.to_le_bytes());
        data[base + 2..base + 4].copy_from_slice(&here.to_le_bytes());
        data[base + 4..base + 6].copy_from_slice(&pk_off.to_le_bytes());
        data[base + 6..base + 8].copy_from_slice(&here.to_le_bytes());
        data[base + 8..base + 10].copy_from_slice(&msg_off.to_le_bytes());
        data[base + 10..base + 12].copy_from_slice(&(digest.len() as u16).to_le_bytes());
        data[base + 12..base + 14].copy_from_slice(&here.to_le_bytes());
    }
    Instruction { program_id: solana_sdk::ed25519_program::id(), accounts: vec![], data }
}

// ── Fixture: bootstrap protocol + 3 bonded operators, return everything. ──

struct Fixture {
    svm: LiteSVM,
    payer: Keypair,
    protocol: Pubkey,
    bond_mint: Pubkey,
    bond_vault: Pubkey,
    slash_pool: Pubkey,
    lst_price_feed: Pubkey,
    operators: Vec<Pubkey>,              // operator PDAs
    attest_keys: Vec<ed25519_dalek::SigningKey>, // attestation signing keys
}

/// Register one extra operator with a CALLER-CHOSEN attestation key (so a test
/// can register two distinct operators that share an attestation key). Returns
/// the new operator PDA.
fn register_extra(fx: &mut Fixture, attest_pk: [u8; 32]) -> Pubkey {
    let authority = Keypair::new();
    fx.svm.airdrop(&authority.pubkey(), 10_000_000_000).unwrap();
    let operator_token = Pubkey::new_unique();
    pack_token_account(&mut fx.svm, &operator_token, &fx.bond_mint, &authority.pubkey(), BOND);
    let (operator, _) = pda(&[OPERATOR_SEED, fx.protocol.as_ref(), authority.pubkey().as_ref()]);
    let ix = ix_register(
        &authority.pubkey(),
        &fx.protocol,
        &operator,
        &fx.bond_mint,
        &operator_token,
        &fx.bond_vault,
        &fx.lst_price_feed,
        attest_pk,
    );
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&fx.payer.pubkey()),
        &[&fx.payer, &authority],
        fx.svm.latest_blockhash(),
    );
    fx.svm.send_transaction(tx).expect("register extra operator");
    operator
}

fn send(svm: &mut LiteSVM, ixs: &[Instruction], payer: &Keypair, extra: &[&Keypair]) -> Result<(), String> {
    let mut signers: Vec<&Keypair> = vec![payer];
    signers.extend_from_slice(extra);
    let tx = Transaction::new_signed_with_payer(
        ixs,
        Some(&payer.pubkey()),
        &signers,
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).map(|_| ()).map_err(|e| format!("{:?}", e.err))
}

fn setup() -> Fixture {
    let mut svm = LiteSVM::new();
    // Load the freshly-built program.
    let so = concat!(env!("CARGO_MANIFEST_DIR"), "/../target/deploy/distin.so");
    svm.add_program_from_file(PROGRAM_ID, so).expect("load distin.so");

    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();

    let bond_mint = Pubkey::new_unique();
    let lst_price_feed = Pubkey::new_unique(); // any non-default key (oracle 1:1 path)
    pack_mint(&mut svm, &bond_mint, &payer.pubkey());

    let (protocol, _) = pda(&[PROTOCOL_SEED]);
    let (bond_vault, _) = pda(&[BOND_VAULT_SEED, protocol.as_ref()]);
    let (slash_pool, _) = pda(&[SLASH_POOL_SEED, protocol.as_ref()]);

    send(
        &mut svm,
        &[ix_initialize(&payer.pubkey(), &protocol, &bond_mint, &bond_vault, &slash_pool, &lst_price_feed)],
        &payer,
        &[],
    )
    .expect("initialize");

    // 3 operators, each bonds BOND.
    let mut operators = Vec::new();
    let mut attest_keys = Vec::new();
    for i in 0..3u8 {
        let authority = Keypair::new();
        svm.airdrop(&authority.pubkey(), 10_000_000_000).unwrap();
        // Deterministic attestation keys (distinct per operator) so the run is
        // reproducible; the value of the secret is irrelevant, only that each
        // operator holds a distinct Ed25519 keypair.
        let mut seed = [0u8; 32];
        seed[0] = i + 1;
        let attest = ed25519_dalek::SigningKey::from_bytes(&seed);
        let attest_pk = attest.verifying_key().to_bytes();

        let operator_token = Pubkey::new_unique();
        pack_token_account(&mut svm, &operator_token, &bond_mint, &authority.pubkey(), BOND);

        let (operator, _) = pda(&[OPERATOR_SEED, protocol.as_ref(), authority.pubkey().as_ref()]);
        send(
            &mut svm,
            &[ix_register(
                &authority.pubkey(),
                &protocol,
                &operator,
                &bond_mint,
                &operator_token,
                &bond_vault,
                &lst_price_feed,
                attest_pk,
            )],
            &payer,
            &[&authority],
        )
        .expect("register_operator");

        operators.push(operator);
        attest_keys.push(attest);
    }

    Fixture { svm, payer, protocol, bond_mint, bond_vault, slash_pool, lst_price_feed, operators, attest_keys }
}

#[test]
fn slash_attested_moves_bond_on_quorum_and_rejects_minority() {
    let mut fx = setup();

    // Three operators bonded BOND each → vault holds 3*BOND.
    assert_eq!(token_amount(&fx.svm, &fx.bond_vault), 3 * BOND, "vault funded by registrations");
    assert_eq!(token_amount(&fx.svm, &fx.slash_pool), 0, "slash pool empty pre-slash");

    // op0 is the culprit. The honest attesters are op1 and op2.
    let culprit = fx.operators[0];
    let culprit_pk = fx.attest_keys[0].verifying_key().to_bytes();
    let session = "distin-sign";
    let message_hash = {
        let mut m = [0u8; 32];
        for (i, b) in m.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(1);
        }
        m
    };
    let round = 3u32;
    let culprit_global = 0u32;

    let digest = fault_report_digest(session.as_bytes(), &message_hash, round, culprit_global, &culprit_pk);

    // ── NEGATIVE: a single honest attester (op1 only) must NOT reach the 2-of-3
    //    quorum → on-chain revert. The bond must not move. ──
    {
        let ed_ix = ed25519_verify_ix(&[(&fx.attest_keys[1], fx.attest_keys[1].verifying_key().to_bytes())], &digest);
        let slash_ix = ix_slash_attested(
            &fx.payer.pubkey(),
            &fx.protocol,
            &culprit,
            &fx.bond_mint,
            &fx.bond_vault,
            &fx.slash_pool,
            &fx.lst_price_feed,
            &[fx.operators[1]], // only one attester account
            SLASH_AMT,
            session,
            message_hash,
            round,
            culprit_global,
        );
        let res = send(&mut fx.svm, &[ed_ix, slash_ix], &fx.payer, &[]);
        assert!(res.is_err(), "minority attestation must be rejected on-chain");
        let err = res.unwrap_err();
        // Anchor ThresholdNotMet = 6000 + ordinal(10) = 6010.
        assert!(
            err.contains("6010") || err.to_lowercase().contains("threshold"),
            "expected ThresholdNotMet (6010), got: {err}"
        );
        // Bond untouched.
        assert_eq!(token_amount(&fx.svm, &fx.bond_vault), 3 * BOND, "vault unchanged after rejected minority slash");
        assert_eq!(token_amount(&fx.svm, &fx.slash_pool), 0, "slash pool unchanged after rejected minority slash");
        let op = read_operator(&fx.svm, &culprit);
        assert_eq!(op.bonded_amount, BOND, "culprit bond intact after rejected slash");
        assert_eq!(op.slash_count, 0, "no slash recorded for minority");
        println!("NEGATIVE OK: 1-of-3 attestation rejected on-chain with `{err}`; bond untouched.");
    }

    // ── NEGATIVE (wrong message): a FULL 2-of-3 quorum, but the operators sign
    //    a digest for a DIFFERENT session. The runtime verifies the signatures
    //    fine, but the on-chain parser only counts signers over the digest the
    //    program reconstructs from THIS instruction's args — so none count and
    //    the slash is rejected. This proves a valid signature over an unrelated
    //    statement cannot be repurposed to slash. ──
    {
        let wrong_digest =
            fault_report_digest(b"other-session", &message_hash, round, culprit_global, &culprit_pk);
        let signers: Vec<(&ed25519_dalek::SigningKey, [u8; 32])> = vec![
            (&fx.attest_keys[1], fx.attest_keys[1].verifying_key().to_bytes()),
            (&fx.attest_keys[2], fx.attest_keys[2].verifying_key().to_bytes()),
        ];
        let ed_ix = ed25519_verify_ix(&signers, &wrong_digest);
        // ...but the slash instruction still claims `session` ("distin-sign").
        let slash_ix = ix_slash_attested(
            &fx.payer.pubkey(),
            &fx.protocol,
            &culprit,
            &fx.bond_mint,
            &fx.bond_vault,
            &fx.slash_pool,
            &fx.lst_price_feed,
            &[fx.operators[1], fx.operators[2]],
            SLASH_AMT,
            session,
            message_hash,
            round,
            culprit_global,
        );
        let res = send(&mut fx.svm, &[ed_ix, slash_ix], &fx.payer, &[]);
        assert!(res.is_err(), "signatures over a different digest must not slash");
        // MissingAttestationSignatures (6022) — no signer over the right digest —
        // or ThresholdNotMet (6010); either way the bond is untouched.
        assert_eq!(token_amount(&fx.svm, &fx.bond_vault), 3 * BOND, "vault untouched on wrong-digest quorum");
        println!(
            "NEGATIVE OK: full quorum over the WRONG digest rejected (`{}`); bond untouched.",
            res.unwrap_err()
        );
    }

    // ── POSITIVE: a 2-of-3 quorum (op1 + op2) over the identical digest → the
    //    bond actually moves vault→slash_pool and the culprit is jailed. ──
    {
        let signers: Vec<(&ed25519_dalek::SigningKey, [u8; 32])> = vec![
            (&fx.attest_keys[1], fx.attest_keys[1].verifying_key().to_bytes()),
            (&fx.attest_keys[2], fx.attest_keys[2].verifying_key().to_bytes()),
        ];
        let ed_ix = ed25519_verify_ix(&signers, &digest);
        let slash_ix = ix_slash_attested(
            &fx.payer.pubkey(),
            &fx.protocol,
            &culprit,
            &fx.bond_mint,
            &fx.bond_vault,
            &fx.slash_pool,
            &fx.lst_price_feed,
            &[fx.operators[1], fx.operators[2]],
            SLASH_AMT,
            session,
            message_hash,
            round,
            culprit_global,
        );
        send(&mut fx.svm, &[ed_ix, slash_ix], &fx.payer, &[]).expect("quorum slash must succeed");

        // The bond MOVED: vault down by SLASH_AMT, slash pool up by SLASH_AMT.
        let vault_after = token_amount(&fx.svm, &fx.bond_vault);
        let pool_after = token_amount(&fx.svm, &fx.slash_pool);
        assert_eq!(vault_after, 3 * BOND - SLASH_AMT, "vault debited by slash amount");
        assert_eq!(pool_after, SLASH_AMT, "slash pool credited by slash amount");

        // The culprit's on-chain accounting reflects the slash and the jail
        // (residual bond 2 < min_bond 1? no — 2 tokens >= 1 min; jailed only if
        // below min_bond, so here NOT jailed; slash_count incremented).
        let op = read_operator(&fx.svm, &culprit);
        assert_eq!(op.bonded_amount, BOND - SLASH_AMT, "culprit bond reduced by slash amount");
        assert_eq!(op.slash_count, 1, "slash recorded exactly once");
        // residual 2 tokens >= MIN_BOND(1) → not jailed by amount; confirm flag.
        assert!(!op.jailed, "2 tokens residual is above min_bond, so not jailed by this slash");
        println!(
            "POSITIVE OK: 2-of-3 quorum slash MOVED {} -> slash_pool (vault {}->{}, pool {}->{}), culprit bond {}->{}, slash_count {}.",
            SLASH_AMT, 3 * BOND, vault_after, 0, pool_after, BOND, op.bonded_amount, op.slash_count
        );
    }

    // ── NEGATIVE 2: replaying the SAME quorum bundle but slashing op0 down to
    //    below min_bond jails it. Slash the remaining 2 tokens (>= residual).
    //    This confirms the jail path fires through a real transaction too. ──
    {
        let signers: Vec<(&ed25519_dalek::SigningKey, [u8; 32])> = vec![
            (&fx.attest_keys[1], fx.attest_keys[1].verifying_key().to_bytes()),
            (&fx.attest_keys[2], fx.attest_keys[2].verifying_key().to_bytes()),
        ];
        let ed_ix = ed25519_verify_ix(&signers, &digest);
        let remaining = BOND - SLASH_AMT; // 2 tokens left
        let slash_ix = ix_slash_attested(
            &fx.payer.pubkey(),
            &fx.protocol,
            &culprit,
            &fx.bond_mint,
            &fx.bond_vault,
            &fx.slash_pool,
            &fx.lst_price_feed,
            &[fx.operators[1], fx.operators[2]],
            remaining,
            session,
            message_hash,
            round,
            culprit_global,
        );
        send(&mut fx.svm, &[ed_ix, slash_ix], &fx.payer, &[]).expect("second quorum slash");
        let op = read_operator(&fx.svm, &culprit);
        assert_eq!(op.bonded_amount, 0, "culprit fully slashed");
        assert!(op.jailed, "culprit below min_bond is jailed");
        assert_eq!(op.slash_count, 2, "two slashes recorded");
        println!("JAIL OK: culprit slashed to 0 and jailed (slash_count={}).", op.slash_count);
    }
}

/// FROST on-chain slash: proves a misbehaving FROST operator is slashable through
/// the SAME `slash_operator_attested` instruction GG20 uses — no fork. The only
/// difference from the GG20 positive case is the fault tag the honest operators
/// signed: FROST has no multi-round transcript, so a signature-share fault carries
/// the reserved session "distin-frost-sign" and round 1001 (mirrored from
/// `SessionFrostSign` / `FaultRoundFrostShare` in engine/kobe-ecdsa/net/fault.go).
/// The program treats `session`/`round` as opaque inputs hashed into the digest,
/// so a FROST quorum slashes the culprit's bond exactly like GG20, and a minority
/// is rejected. This is the on-chain half of the FROST identifiable-abort path
/// proven networked in engine/kobe-ecdsa/net `TestFrostIdentifiableAbort`.
#[test]
fn frost_fault_quorum_slashes_culprit_and_rejects_minority() {
    let mut fx = setup();

    // FROST fault tags — byte-identical to the Go constants the operators use.
    const FROST_SESSION: &str = "distin-frost-sign";
    const FROST_ROUND: u32 = 1001;

    assert_eq!(token_amount(&fx.svm, &fx.bond_vault), 3 * BOND, "vault funded by registrations");

    // op0 is the FROST culprit (broadcast a tampered signature share); op1 + op2
    // are the honest operators that independently verified the shares and attested.
    let culprit = fx.operators[0];
    let culprit_pk = fx.attest_keys[0].verifying_key().to_bytes();
    // The 32-byte message the FROST quorum was signing (any nonzero value).
    let message_hash = {
        let mut m = [0u8; 32];
        for (i, b) in m.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        m
    };
    let culprit_global = 0u32;
    let digest = fault_report_digest(FROST_SESSION.as_bytes(), &message_hash, FROST_ROUND, culprit_global, &culprit_pk);

    // ── NEGATIVE: one honest FROST attester (op1) does not reach the 2-of-3
    //    quorum → on-chain revert, bond untouched. ──
    {
        let ed_ix = ed25519_verify_ix(&[(&fx.attest_keys[1], fx.attest_keys[1].verifying_key().to_bytes())], &digest);
        let slash_ix = ix_slash_attested(
            &fx.payer.pubkey(),
            &fx.protocol,
            &culprit,
            &fx.bond_mint,
            &fx.bond_vault,
            &fx.slash_pool,
            &fx.lst_price_feed,
            &[fx.operators[1]],
            SLASH_AMT,
            FROST_SESSION,
            message_hash,
            FROST_ROUND,
            culprit_global,
        );
        let res = send(&mut fx.svm, &[ed_ix, slash_ix], &fx.payer, &[]);
        assert!(res.is_err(), "a single FROST attester must be rejected on-chain");
        assert_eq!(token_amount(&fx.svm, &fx.bond_vault), 3 * BOND, "vault unchanged after rejected FROST minority");
        assert_eq!(read_operator(&fx.svm, &culprit).slash_count, 0, "no slash recorded for FROST minority");
        println!("FROST NEGATIVE OK: 1-of-3 attestation rejected (`{}`); bond untouched.", res.unwrap_err());
    }

    // ── POSITIVE: the 2-of-3 honest FROST quorum (op1 + op2) over the identical
    //    FROST-tagged digest → the culprit's bond actually MOVES vault→slash_pool. ──
    {
        let signers: Vec<(&ed25519_dalek::SigningKey, [u8; 32])> = vec![
            (&fx.attest_keys[1], fx.attest_keys[1].verifying_key().to_bytes()),
            (&fx.attest_keys[2], fx.attest_keys[2].verifying_key().to_bytes()),
        ];
        let ed_ix = ed25519_verify_ix(&signers, &digest);
        let slash_ix = ix_slash_attested(
            &fx.payer.pubkey(),
            &fx.protocol,
            &culprit,
            &fx.bond_mint,
            &fx.bond_vault,
            &fx.slash_pool,
            &fx.lst_price_feed,
            &[fx.operators[1], fx.operators[2]],
            SLASH_AMT,
            FROST_SESSION,
            message_hash,
            FROST_ROUND,
            culprit_global,
        );
        send(&mut fx.svm, &[ed_ix, slash_ix], &fx.payer, &[]).expect("FROST quorum slash must succeed");

        let vault_after = token_amount(&fx.svm, &fx.bond_vault);
        let pool_after = token_amount(&fx.svm, &fx.slash_pool);
        assert_eq!(vault_after, 3 * BOND - SLASH_AMT, "vault debited by FROST slash amount");
        assert_eq!(pool_after, SLASH_AMT, "slash pool credited by FROST slash amount");
        let op = read_operator(&fx.svm, &culprit);
        assert_eq!(op.bonded_amount, BOND - SLASH_AMT, "FROST culprit bond reduced by slash amount");
        assert_eq!(op.slash_count, 1, "FROST slash recorded exactly once");
        println!(
            "FROST POSITIVE OK: 2-of-3 quorum slash MOVED {} -> slash_pool (vault {}->{}, pool 0->{}), culprit bond {}->{}.",
            SLASH_AMT, 3 * BOND, vault_after, pool_after, BOND, op.bonded_amount
        );
    }

    // ── NEGATIVE (cross-scheme replay): the SAME honest signatures, but assembled
    //    over the GG20 session/round instead of the FROST tags, must NOT slash —
    //    the digest the program reconstructs from the FROST args won't match a GG20
    //    signature, so a fault report from one scheme cannot be replayed into the
    //    other. ──
    {
        // op1 + op2 sign a GG20-tagged digest (session "distin-sign", round 3)…
        let gg20_digest = fault_report_digest(b"distin-sign", &message_hash, 3, culprit_global, &culprit_pk);
        let signers: Vec<(&ed25519_dalek::SigningKey, [u8; 32])> = vec![
            (&fx.attest_keys[1], fx.attest_keys[1].verifying_key().to_bytes()),
            (&fx.attest_keys[2], fx.attest_keys[2].verifying_key().to_bytes()),
        ];
        let ed_ix = ed25519_verify_ix(&signers, &gg20_digest);
        // …but the slash instruction claims the FROST tags, so the program rebuilds
        // the FROST digest and none of the GG20 signatures count.
        let slash_ix = ix_slash_attested(
            &fx.payer.pubkey(),
            &fx.protocol,
            &culprit,
            &fx.bond_mint,
            &fx.bond_vault,
            &fx.slash_pool,
            &fx.lst_price_feed,
            &[fx.operators[1], fx.operators[2]],
            SLASH_AMT,
            FROST_SESSION,
            message_hash,
            FROST_ROUND,
            culprit_global,
        );
        let res = send(&mut fx.svm, &[ed_ix, slash_ix], &fx.payer, &[]);
        assert!(res.is_err(), "GG20-tagged signatures must not slash under FROST tags");
        // Bond unchanged from the single successful slash above.
        assert_eq!(token_amount(&fx.svm, &fx.bond_vault), 3 * BOND - SLASH_AMT, "vault untouched on cross-scheme replay");
        println!("FROST NEGATIVE OK: GG20-tagged quorum rejected under FROST tags (`{}`); no cross-scheme replay.", res.unwrap_err());
    }
}

/// Quorum-integrity regression: the per-attester dedup must key on the
/// ATTESTATION PUBLIC KEY actually verified, not the operator PDA. Otherwise a
/// party that controls two operator accounts sharing one attestation key could
/// have a SINGLE Ed25519 signature counted twice and reach the quorum with fewer
/// distinct witnesses than required.
///
/// Setup: required_attesters = 2 (3 ops at 5000 bps after the extra registers
/// it becomes 4 ops → ceil(4*5000/10000)=2). The culprit is op0; op1 and a NEW
/// operator both register op1's attestation key. We provide ONE signature (op1's)
/// and pass BOTH op1 and the duplicate as attesters. With the fix this is one
/// distinct key → 1 < 2 → ThresholdNotMet; the bond must NOT move.
#[test]
fn duplicate_attestation_key_cannot_double_count() {
    let mut fx = setup();

    let culprit = fx.operators[0];
    let culprit_pk = fx.attest_keys[0].verifying_key().to_bytes();
    let session = "distin-sign";
    let message_hash = [9u8; 32];
    let round = 3u32;
    let culprit_global = 0u32;

    // A second operator that re-uses op1's attestation key.
    let dup_key = fx.attest_keys[1].verifying_key().to_bytes();
    let dup_operator = register_extra(&mut fx, dup_key);

    // required is now 2 (4 operators at 5000 bps).
    let digest = fault_report_digest(session.as_bytes(), &message_hash, round, culprit_global, &culprit_pk);
    // Only ONE real signature (op1's). op1 and dup share that key.
    let ed_ix = ed25519_verify_ix(
        &[(&fx.attest_keys[1], dup_key)],
        &digest,
    );
    let slash_ix = ix_slash_attested(
        &fx.payer.pubkey(),
        &fx.protocol,
        &culprit,
        &fx.bond_mint,
        &fx.bond_vault,
        &fx.slash_pool,
        &fx.lst_price_feed,
        &[fx.operators[1], dup_operator], // two PDAs, one shared key, one signature
        SLASH_AMT,
        session,
        message_hash,
        round,
        culprit_global,
    );
    let res = send(&mut fx.svm, &[ed_ix, slash_ix], &fx.payer, &[]);
    assert!(res.is_err(), "one signature under a shared key must not satisfy a 2-attester quorum");
    assert_eq!(token_amount(&fx.svm, &fx.bond_vault), 4 * BOND, "vault untouched: double-count rejected");
    assert_eq!(read_operator(&fx.svm, &culprit).slash_count, 0, "no slash from a double-counted single signature");
    println!(
        "DEDUP OK: a single signature under a shared attestation key counted ONCE (`{}`); bond untouched.",
        res.unwrap_err()
    );
}
