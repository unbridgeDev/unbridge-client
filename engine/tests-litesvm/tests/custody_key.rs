//! Real-SVM integration test for the per-user custody-key binding.
//!
//! `register_custody_key` binds a user's Solana identity to their FROST group
//! public key. The guardrail under test is the same seed-derivation property as
//! the wallet gate: the CustodyKey PDA derives from the signer's own key, so a
//! user can register (and close) only their own binding, never someone else's.

use litesvm::LiteSVM;
use sha2::{Digest, Sha256};
use solana_sdk::{
    account::Account as SolAccount,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};

const PROGRAM_ID: Pubkey = solana_sdk::pubkey!("4xy9dYHfAzi7cAcX5JHxNR6EoMJ9PGfeQDMHx6YUQQM6");
const PROTOCOL_SEED: &[u8] = b"protocol";
const CUSTODY_SEED: &[u8] = b"custody";

fn disc(name: &str) -> [u8; 8] {
    Sha256::digest(format!("global:{name}").as_bytes())[..8].try_into().unwrap()
}

fn setup() -> (LiteSVM, Pubkey) {
    let mut svm = LiteSVM::new();
    let so = concat!(env!("CARGO_MANIFEST_DIR"), "/../target/deploy/distin.so");
    svm.add_program_from_file(PROGRAM_ID, so).expect("load distin.so");

    let admin = Keypair::new();
    svm.airdrop(&admin.pubkey(), 100_000_000_000).unwrap();
    let (protocol, _) = Pubkey::find_program_address(&[PROTOCOL_SEED], &PROGRAM_ID);

    // Minimal protocol init: only the singleton config is needed for custody
    // registration (no operators/vaults). Reuse the full initialize path.
    let (bond_vault, _) =
        Pubkey::find_program_address(&[b"bond_vault", protocol.as_ref()], &PROGRAM_ID);
    let (slash_pool, _) =
        Pubkey::find_program_address(&[b"slash_pool", protocol.as_ref()], &PROGRAM_ID);
    let mint = Pubkey::new_unique();
    let feed = Pubkey::new_unique();
    // pack a minimal Token-2022 mint + a positive Pyth-ish feed
    pack_mint(&mut svm, &mint, &admin.pubkey());
    pack_feed(&mut svm, &feed);

    let mut data = disc("initialize").to_vec();
    data.extend_from_slice(&5_000u16.to_le_bytes()); // threshold_bps
    data.extend_from_slice(&1_000_000_000u64.to_le_bytes()); // min_bond
    data.extend_from_slice(&100u64.to_le_bytes()); // unbonding_slots
    data.extend_from_slice(&0u64.to_le_bytes()); // request_fee
    data.extend_from_slice(&1_000u64.to_le_bytes()); // max_validity_slots
    data.extend_from_slice(feed.as_ref());
    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(protocol, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(bond_vault, false),
            AccountMeta::new(slash_pool, false),
            AccountMeta::new_readonly(spl_token_2022::id(), false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
        ],
        data,
    };
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&admin.pubkey()),
        &[&admin],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).expect("initialize");
    (svm, protocol)
}

fn pack_mint(svm: &mut LiteSVM, mint: &Pubkey, authority: &Pubkey) {
    use solana_sdk::program_pack::Pack;
    use spl_token_2022::state::Mint;
    let mut data = vec![0u8; Mint::LEN];
    Mint {
        mint_authority: Some(*authority).into(),
        supply: 0,
        decimals: 9,
        is_initialized: true,
        freeze_authority: None.into(),
    }
    .pack_into_slice(&mut data);
    svm.set_account(*mint, SolAccount { lamports: 1_000_000_000, data, owner: spl_token_2022::id(), executable: false, rent_epoch: 0 }).unwrap();
}

fn pack_feed(svm: &mut LiteSVM, feed: &Pubkey) {
    let mut data = vec![0u8; 96];
    data[73..81].copy_from_slice(&150_000_000i64.to_le_bytes());
    svm.set_account(*feed, SolAccount { lamports: 1_000_000_000, data, owner: Pubkey::new_unique(), executable: false, rent_epoch: 0 }).unwrap();
}

fn custody_pda(protocol: &Pubkey, authority: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[CUSTODY_SEED, protocol.as_ref(), authority.as_ref()], &PROGRAM_ID).0
}

fn register_ix(protocol: &Pubkey, authority: &Pubkey, group_pk: [u8; 32]) -> Instruction {
    let mut data = disc("register_custody_key").to_vec();
    data.extend_from_slice(&group_pk);
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*authority, true),
            AccountMeta::new_readonly(*protocol, false),
            AccountMeta::new(custody_pda(protocol, authority), false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
        data,
    }
}

fn send(svm: &mut LiteSVM, payer: &Keypair, ix: Instruction) -> Result<(), String> {
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[payer], svm.latest_blockhash());
    svm.send_transaction(tx).map(|_| ()).map_err(|e| format!("{:?}", e.err))
}

#[test]
fn user_binds_own_group_key_and_cannot_bind_anothers() {
    let (mut svm, protocol) = setup();
    let user = Keypair::new();
    let stranger = Keypair::new();
    svm.airdrop(&user.pubkey(), 10_000_000_000).unwrap();
    svm.airdrop(&stranger.pubkey(), 10_000_000_000).unwrap();

    let group_pk = [7u8; 32];

    // 1. user registers their own custody key.
    send(&mut svm, &user, register_ix(&protocol, &user.pubkey(), group_pk)).expect("register");
    let acc = svm.get_account(&custody_pda(&protocol, &user.pubkey())).expect("custody exists");
    assert_eq!(acc.owner, PROGRAM_ID);
    // layout: disc 8 + protocol 32 + authority 32 + group_pubkey 32 + slot 8 + bump 1
    assert_eq!(&acc.data[8 + 32..8 + 64], user.pubkey().as_ref(), "authority");
    assert_eq!(&acc.data[8 + 64..8 + 96], &group_pk, "group_pubkey");

    // 2. an all-zero group key is rejected.
    let user2 = Keypair::new();
    svm.airdrop(&user2.pubkey(), 10_000_000_000).unwrap();
    let err = send(&mut svm, &user2, register_ix(&protocol, &user2.pubkey(), [0u8; 32]))
        .expect_err("zero key rejected");
    assert!(err.contains("Custom(601"), "expected EmptyMessageHash-ish, got: {err}");

    // 3. a stranger cannot register a binding at the user's PDA: signing as the
    //    stranger while passing the user's custody account fails seed derivation.
    let mut ix = register_ix(&protocol, &stranger.pubkey(), group_pk);
    ix.accounts[2] = AccountMeta::new(custody_pda(&protocol, &user.pubkey()), false);
    let err = send(&mut svm, &stranger, ix).expect_err("cannot bind at another's PDA");
    assert!(err.contains("Custom(2006)"), "expected ConstraintSeeds, got: {err}");

    // 4. the user can close their own binding; rent returns.
    let data = disc("close_custody_key").to_vec();
    let close = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(user.pubkey(), true),
            AccountMeta::new_readonly(protocol, false),
            AccountMeta::new(custody_pda(&protocol, &user.pubkey()), false),
        ],
        data,
    };
    send(&mut svm, &user, close).expect("close");
    assert!(
        svm.get_account(&custody_pda(&protocol, &user.pubkey()))
            .is_none_or(|a| a.data.is_empty() || a.lamports == 0),
        "custody PDA closed"
    );
}
