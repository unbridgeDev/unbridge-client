//! Real-SVM integration test for the wallet-gated request path.
//!
//! The guardrail under test: a third party must NOT be able to have a message
//! signed through the wallet path against someone else's identity. On-chain
//! that is enforced purely by account constraints (PDA derivation from the
//! requester's own key + stored-authority check + admin-gated registration),
//! which unit tests cannot exercise — so this drives real transactions through
//! litesvm against the built program:
//!
//!   1. admin registers a wallet for user A            → OK
//!   2. non-admin tries to register a wallet           → rejected (has_one)
//!   3. A posts a wallet-gated request                 → OK, fields verified
//!   4. stranger B posts a wallet-gated request        → rejected (no wallet PDA)
//!   5. B's legacy permissionless request still works  → OK (migration compat)
//!   6. admin revokes A's wallet                       → A's next gated request rejected

use litesvm::LiteSVM;
use sha2::{Digest, Sha256};
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

const PROGRAM_ID: Pubkey = solana_sdk::pubkey!("4xy9dYHfAzi7cAcX5JHxNR6EoMJ9PGfeQDMHx6YUQQM6");

const PROTOCOL_SEED: &[u8] = b"protocol";
const BOND_VAULT_SEED: &[u8] = b"bond_vault";
const SLASH_POOL_SEED: &[u8] = b"slash_pool";
const OPERATOR_SEED: &[u8] = b"operator";
const REQUEST_SEED: &[u8] = b"request";
const WALLET_SEED: &[u8] = b"wallet";

const DECIMALS: u8 = 9;
const MIN_BOND: u64 = 1_000_000_000;
const BOND: u64 = 5_000_000_000;
const THRESHOLD_BPS: u16 = 5_000;

/// Anchor instruction discriminator: sha256("global:<name>")[..8].
fn disc(name: &str) -> [u8; 8] {
    let h = Sha256::digest(format!("global:{name}").as_bytes());
    h[..8].try_into().unwrap()
}

fn token_program_id() -> Pubkey {
    spl_token_2022::id()
}

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

fn pack_token(svm: &mut LiteSVM, addr: &Pubkey, mint: &Pubkey, owner: &Pubkey, amount: u64) {
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

/// Fake Pyth PriceUpdateV2 push feed: `compute_stake_weight` reads a positive
/// i64 price at offset 8+32+1+32 and requires len >= that + 8.
fn pack_price_feed(svm: &mut LiteSVM, feed: &Pubkey) {
    let mut data = vec![0u8; 96];
    let price: i64 = 150_000_000; // any positive value
    data[73..81].copy_from_slice(&price.to_le_bytes());
    svm.set_account(
        *feed,
        SolAccount {
            lamports: 1_000_000_000,
            data,
            owner: Pubkey::new_unique(), // owner is not checked, only the address binding
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
}

struct Env {
    svm: LiteSVM,
    admin: Keypair,
    protocol: Pubkey,
}

fn send(svm: &mut LiteSVM, payer: &Keypair, signers: &[&Keypair], ix: Instruction) -> Result<(), String> {
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&[payer].as_slice(), signers].concat(),
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).map(|_| ()).map_err(|e| format!("{:?}", e.err))
}

/// Bootstrap protocol + one bonded operator so request creation passes the
/// `NoActiveOperators` gate.
fn setup() -> Env {
    let mut svm = LiteSVM::new();
    let so = concat!(env!("CARGO_MANIFEST_DIR"), "/../target/deploy/distin.so");
    svm.add_program_from_file(PROGRAM_ID, so).expect("load distin.so");

    let admin = Keypair::new();
    svm.airdrop(&admin.pubkey(), 100_000_000_000).unwrap();

    let (protocol, _) = Pubkey::find_program_address(&[PROTOCOL_SEED], &PROGRAM_ID);
    let (bond_vault, _) =
        Pubkey::find_program_address(&[BOND_VAULT_SEED, protocol.as_ref()], &PROGRAM_ID);
    let (slash_pool, _) =
        Pubkey::find_program_address(&[SLASH_POOL_SEED, protocol.as_ref()], &PROGRAM_ID);

    let mint = Pubkey::new_unique();
    let feed = Pubkey::new_unique();
    pack_mint(&mut svm, &mint, &admin.pubkey());
    pack_price_feed(&mut svm, &feed);

    // initialize(threshold_bps, min_bond, unbonding_slots, request_fee, max_validity_slots, lst_price_feed)
    let mut data = disc("initialize").to_vec();
    data.extend_from_slice(&THRESHOLD_BPS.to_le_bytes());
    data.extend_from_slice(&MIN_BOND.to_le_bytes());
    data.extend_from_slice(&100u64.to_le_bytes());
    data.extend_from_slice(&0u64.to_le_bytes()); // request_fee = 0
    data.extend_from_slice(&1_000u64.to_le_bytes());
    data.extend_from_slice(feed.as_ref());
    send(
        &mut svm,
        &admin,
        &[],
        Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(protocol, false),
                AccountMeta::new_readonly(mint, false),
                AccountMeta::new(bond_vault, false),
                AccountMeta::new(slash_pool, false),
                AccountMeta::new_readonly(token_program_id(), false),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                AccountMeta::new_readonly(sysvar::rent::id(), false),
            ],
            data,
        },
    )
    .expect("initialize");

    // register one operator so operator_count > 0.
    let op = Keypair::new();
    svm.airdrop(&op.pubkey(), 10_000_000_000).unwrap();
    let op_token = Pubkey::new_unique();
    pack_token(&mut svm, &op_token, &mint, &op.pubkey(), BOND * 2);
    let (operator, _) = Pubkey::find_program_address(
        &[OPERATOR_SEED, protocol.as_ref(), op.pubkey().as_ref()],
        &PROGRAM_ID,
    );
    let mut data = disc("register_operator").to_vec();
    data.extend_from_slice(&[2u8; 33]); // group_pubkey
    data.extend_from_slice(&BOND.to_le_bytes());
    send(
        &mut svm,
        &op,
        &[],
        Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new(op.pubkey(), true),
                AccountMeta::new(protocol, false),
                AccountMeta::new(operator, false),
                AccountMeta::new_readonly(mint, false),
                AccountMeta::new(op_token, false),
                AccountMeta::new(bond_vault, false),
                AccountMeta::new_readonly(feed, false),
                AccountMeta::new_readonly(token_program_id(), false),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            ],
            data,
        },
    )
    .expect("register_operator");

    Env { svm, admin, protocol }
}

fn wallet_pda(protocol: &Pubkey, authority: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[WALLET_SEED, protocol.as_ref(), authority.as_ref()],
        &PROGRAM_ID,
    )
    .0
}

fn request_pda(requester: &Pubkey, client_nonce: u64) -> Pubkey {
    Pubkey::find_program_address(
        &[REQUEST_SEED, requester.as_ref(), client_nonce.to_le_bytes().as_ref()],
        &PROGRAM_ID,
    )
    .0
}

fn register_wallet_ix(env: &Env, authority: &Pubkey) -> Instruction {
    let mut data = disc("register_wallet").to_vec();
    data.extend_from_slice(authority.as_ref());
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(env.admin.pubkey(), true),
            AccountMeta::new_readonly(env.protocol, false),
            AccountMeta::new(wallet_pda(&env.protocol, authority), false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
        data,
    }
}

fn request_args(client_nonce: u64) -> Vec<u8> {
    let mut args = Vec::new();
    args.extend_from_slice(&client_nonce.to_le_bytes());
    args.push(0); // scheme = FrostEd25519
    args.push(0); // target_vm = Svm
    args.extend_from_slice(&1u64.to_le_bytes()); // target_chain_id
    args.extend_from_slice(&[7u8; 32]); // message_hash
    args.extend_from_slice(&1u16.to_le_bytes()); // threshold
    args.extend_from_slice(&500u64.to_le_bytes()); // validity_slots
    args
}

fn wallet_request_ix(env: &Env, requester: &Pubkey, client_nonce: u64) -> Instruction {
    let mut data = disc("create_wallet_request").to_vec();
    data.extend_from_slice(&request_args(client_nonce));
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*requester, true),
            AccountMeta::new(env.protocol, false),
            AccountMeta::new_readonly(wallet_pda(&env.protocol, requester), false),
            AccountMeta::new(request_pda(requester, client_nonce), false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
        data,
    }
}

fn legacy_request_ix(env: &Env, requester: &Pubkey, client_nonce: u64) -> Instruction {
    let mut data = disc("create_signing_request").to_vec();
    data.extend_from_slice(&request_args(client_nonce));
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*requester, true),
            AccountMeta::new(env.protocol, false),
            AccountMeta::new(request_pda(requester, client_nonce), false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
        data,
    }
}

#[test]
fn wallet_gate_authorizes_owner_and_rejects_third_party() {
    let mut env = setup();

    let user_a = Keypair::new();
    let user_b = Keypair::new();
    env.svm.airdrop(&user_a.pubkey(), 10_000_000_000).unwrap();
    env.svm.airdrop(&user_b.pubkey(), 10_000_000_000).unwrap();

    // 1. admin registers a wallet identity for A.
    let ix = register_wallet_ix(&env, &user_a.pubkey());
    let admin = env.admin.insecure_clone();
    send(&mut env.svm, &admin, &[], ix).expect("admin register_wallet");

    // The wallet PDA stores {protocol, authority}.
    let w = env
        .svm
        .get_account(&wallet_pda(&env.protocol, &user_a.pubkey()))
        .expect("wallet account exists");
    assert_eq!(w.owner, PROGRAM_ID);
    assert_eq!(&w.data[8..40], env.protocol.as_ref(), "wallet.protocol");
    assert_eq!(&w.data[40..72], user_a.pubkey().as_ref(), "wallet.authority");

    // 2. a non-admin cannot register wallets (has_one = admin).
    let mallory = Keypair::new();
    env.svm.airdrop(&mallory.pubkey(), 10_000_000_000).unwrap();
    let mut ix = register_wallet_ix(&env, &mallory.pubkey());
    ix.accounts[0] = AccountMeta::new(mallory.pubkey(), true);
    let err = send(&mut env.svm, &mallory, &[], ix).expect_err("non-admin register must fail");
    assert!(err.contains("Custom(6001)"), "expected Unauthorized, got: {err}");

    // 3. A posts a wallet-gated request.
    let ix = wallet_request_ix(&env, &user_a.pubkey(), 1);
    send(&mut env.svm, &user_a, &[], ix).expect("A's gated request");
    let req = env
        .svm
        .get_account(&request_pda(&user_a.pubkey(), 1))
        .expect("request exists");
    assert_eq!(&req.data[40..72], user_a.pubkey().as_ref(), "request.requester");

    // 4. B (no registered wallet) cannot post through the gated path: the
    //    wallet PDA for B's own key does not exist, and B cannot substitute A's
    //    wallet because the seeds re-derive from the requester signer.
    let ix = wallet_request_ix(&env, &user_b.pubkey(), 2);
    send(&mut env.svm, &user_b, &[], ix).expect_err("B without wallet must fail");

    //    ...even if B explicitly passes A's wallet account.
    let mut ix = wallet_request_ix(&env, &user_b.pubkey(), 3);
    ix.accounts[2] = AccountMeta::new_readonly(wallet_pda(&env.protocol, &user_a.pubkey()), false);
    let err = send(&mut env.svm, &user_b, &[], ix).expect_err("B with A's wallet must fail");
    assert!(err.contains("Custom(2006)"), "expected ConstraintSeeds, got: {err}");

    // 5. migration compat: the legacy permissionless path still works for B.
    let ix = legacy_request_ix(&env, &user_b.pubkey(), 4);
    send(&mut env.svm, &user_b, &[], ix).expect("legacy request still permissionless");

    // 6. revoke A's wallet; A's next gated request must fail.
    let data = disc("revoke_wallet").to_vec();
    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(env.admin.pubkey(), true),
            AccountMeta::new_readonly(env.protocol, false),
            AccountMeta::new(wallet_pda(&env.protocol, &user_a.pubkey()), false),
        ],
        data,
    };
    let admin = env.admin.insecure_clone();
    send(&mut env.svm, &admin, &[], ix).expect("revoke_wallet");
    assert!(
        env.svm
            .get_account(&wallet_pda(&env.protocol, &user_a.pubkey()))
            .is_none_or(|a| a.data.is_empty() || a.lamports == 0),
        "wallet PDA closed"
    );
    let ix = wallet_request_ix(&env, &user_a.pubkey(), 5);
    send(&mut env.svm, &user_a, &[], ix).expect_err("gated request after revoke must fail");
}
