//! Distin — Milestone 3: the FULL end-to-end MPC loop on localnet.
//!
//! This binary is the off-chain **coordinator/operator service**. It proves that
//! an on-chain signing request drives the off-chain FROST MPC to produce a REAL
//! Ed25519 signature, and that the on-chain state records the completed signing.
//!
//! Flow (all against a local `solana-test-validator`):
//!   0. trusted-dealer FROST keygen for a 2-of-3 operator group (kobe::KeySet);
//!      the 32-byte group public key is what gets registered on-chain.
//!   1. bootstrap the protocol: Token-2022 LST mint, `initialize`,
//!      `register_operator` x3 (each carrying the SAME group public key).
//!   2. a user posts a `create_signing_request` (FrostEd25519 / SVM) whose
//!      `message_hash` is the 32-byte message to sign.
//!   3. the coordinator READS that request back off-chain, runs the real FROST
//!      round 1/2 + aggregate over the request's `message_hash` with a 2-of-3
//!      quorum, and submits:
//!         - `submit_partial_signature` per participating operator (the on-chain
//!           participation receipt + staked-weight accounting), then
//!         - `aggregate_and_emit(aggregate_sig)` recording the REAL aggregate.
//!   4. it re-reads the finalized request from chain and INDEPENDENTLY verifies
//!      the recorded signature with `ed25519-dalek` against the group key, and
//!      that it is bound to this request's `message_hash`.
//!
//! What is REAL: the FROST cryptography (audited ZF crate), the Ed25519
//! signature, the on-chain program + all its instructions/PDAs/threshold gates,
//! and the independent verification of the recorded signature.
//! What is SIMULATED: the N operators run in one process (no real network), one
//! keypair pays/authorizes everything, and the LST oracle is a placeholder.

// solana-sdk 2.x relocated `system_program` / `system_instruction` into the
// `solana-system-interface` crate; the re-exports still work and pulling in an
// extra crate just for the demo isn't worth it.
#![allow(deprecated)]

use std::str::FromStr;

use ed25519_dalek::{Signature as DalekSig, Verifier, VerifyingKey as DalekKey};
use kobe::KeySet;
use sha2::{Digest, Sha256};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    program_pack::Pack,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_program,
    sysvar::rent,
    transaction::Transaction,
};
use spl_associated_token_account::get_associated_token_address_with_program_id;

const RPC_URL: &str = "http://127.0.0.1:8899";
const PROGRAM_ID: &str = "4xy9dYHfAzi7cAcX5JHxNR6EoMJ9PGfeQDMHx6YUQQM6";

// Anchor instruction discriminators (first 8 bytes of sha256("global:<name>")).
const DISC_INITIALIZE: [u8; 8] = [175, 175, 109, 31, 13, 152, 155, 237];
const DISC_REGISTER_OPERATOR: [u8; 8] = [49, 242, 151, 125, 212, 136, 31, 89];
const DISC_CREATE_REQUEST: [u8; 8] = [81, 124, 188, 129, 112, 241, 32, 39];
const DISC_SUBMIT_PARTIAL: [u8; 8] = [226, 18, 202, 183, 167, 26, 196, 50];
const DISC_AGGREGATE_EMIT: [u8; 8] = [66, 189, 125, 18, 115, 114, 117, 74];

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn pid() -> Pubkey {
    Pubkey::from_str(PROGRAM_ID).unwrap()
}

fn send(rpc: &RpcClient, ix: Instruction, payer: &Keypair, extra: &[&Keypair]) -> String {
    let bh = rpc.get_latest_blockhash().unwrap();
    let mut signers: Vec<&Keypair> = vec![payer];
    signers.extend_from_slice(extra);
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &signers, bh);
    rpc.send_and_confirm_transaction(&tx).unwrap().to_string()
}

fn main() {
    let rpc = RpcClient::new_with_commitment(RPC_URL.to_string(), CommitmentConfig::confirmed());
    let program = pid();
    let token_2022 = spl_token_2022::id();

    println!("Distin / Milestone 3 — full end-to-end MPC loop on localnet");
    println!("program: {program}\n");

    // ---- Actors. One funded keypair plays admin / operators / requester. ----
    let admin = Keypair::new();
    let op_auths: Vec<Keypair> = (0..3).map(|_| Keypair::new()).collect();
    println!("airdropping SOL to actors...");
    airdrop(&rpc, &admin.pubkey(), 100);
    for k in &op_auths {
        airdrop(&rpc, &k.pubkey(), 10);
    }

    // ---- 0. FROST keygen for the 2-of-3 group. ----
    let keyset = KeySet::generate(3, 2).expect("FROST keygen failed");
    let group_pk = keyset.group_public_key().unwrap();
    println!("\n[0] FROST trusted-dealer keygen: 2-of-3");
    println!("    group public key (Ed25519, 32B): {}", hex(&group_pk));

    // The on-chain operator record holds a 33-byte `group_pubkey`. We store the
    // 32-byte Ed25519 group key prefixed with 0x00 (an unused SEC1-style tag
    // byte for the Ed25519 branch) so the registered value carries the real key.
    let mut group_pk_33 = [0u8; 33];
    group_pk_33[1..].copy_from_slice(&group_pk);

    // ---- 1. Token-2022 LST mint + bootstrap the protocol. ----
    let mint = create_token2022_mint(&rpc, &admin);
    println!("\n[1] bond mint (Token-2022): {mint}");

    let (protocol, _) = Pubkey::find_program_address(&[b"protocol"], &program);
    let (bond_vault, _) =
        Pubkey::find_program_address(&[b"bond_vault", protocol.as_ref()], &program);
    let (slash_pool, _) =
        Pubkey::find_program_address(&[b"slash_pool", protocol.as_ref()], &program);
    let oracle = Keypair::new().pubkey(); // non-default placeholder feed

    // initialize
    {
        let mut data = DISC_INITIALIZE.to_vec();
        // 60%: with 3 equally-bonded operators, a 2-of-3 quorum carries 66.7% of
        // the staked weight, which clears this economic-security target.
        data.extend_from_slice(&6000u16.to_le_bytes()); // threshold_bps 60%
        data.extend_from_slice(&1_000_000u64.to_le_bytes()); // min_bond
        data.extend_from_slice(&10u64.to_le_bytes()); // unbonding_slots
        data.extend_from_slice(&0u64.to_le_bytes()); // request_fee
        data.extend_from_slice(&216_000u64.to_le_bytes()); // max_validity_slots
        data.extend_from_slice(oracle.as_ref()); // lst_price_feed
        let ix = Instruction {
            program_id: program,
            accounts: vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(protocol, false),
                AccountMeta::new_readonly(mint, false),
                AccountMeta::new(bond_vault, false),
                AccountMeta::new(slash_pool, false),
                AccountMeta::new_readonly(token_2022, false),
                AccountMeta::new_readonly(system_program::id(), false),
                AccountMeta::new_readonly(rent::id(), false),
            ],
            data,
        };
        let sig = send(&rpc, ix, &admin, &[]);
        println!("    initialize tx: {sig}");
    }

    // register 3 operators, each bonding the LST and carrying the group key.
    for (i, op) in op_auths.iter().enumerate() {
        let op_ata = create_and_fund_ata(&rpc, &admin, &mint, &op.pubkey(), 10_000_000);
        let (operator, _) = Pubkey::find_program_address(
            &[b"operator", protocol.as_ref(), op.pubkey().as_ref()],
            &program,
        );
        let mut data = DISC_REGISTER_OPERATOR.to_vec();
        data.extend_from_slice(&group_pk_33); // group_pubkey [u8;33]
        data.extend_from_slice(&10_000_000u64.to_le_bytes()); // bond_amount
        let ix = Instruction {
            program_id: program,
            accounts: vec![
                AccountMeta::new(op.pubkey(), true),
                AccountMeta::new(protocol, false),
                AccountMeta::new(operator, false),
                AccountMeta::new_readonly(mint, false),
                AccountMeta::new(op_ata, false),
                AccountMeta::new(bond_vault, false),
                AccountMeta::new_readonly(oracle, false),
                AccountMeta::new_readonly(token_2022, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data,
        };
        let sig = send(&rpc, ix, op, &[]);
        println!("    register_operator[{}] tx: {sig}", i + 1);
    }

    // ---- 2. User posts a signing request (FrostEd25519 / SVM). ----
    // The message to sign: a 32-byte hash. This is the on-chain `message_hash`.
    let message_hash: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(b"distin::m3 -> transfer 1.0 SOL on a foreign SVM chain");
        h.finalize().into()
    };
    let proto = rpc.get_account(&protocol).unwrap();
    let request_nonce = read_request_nonce(&proto.data);
    let (request, _) = Pubkey::find_program_address(
        &[b"request", protocol.as_ref(), &request_nonce.to_le_bytes()],
        &program,
    );
    {
        let mut data = DISC_CREATE_REQUEST.to_vec();
        data.push(0); // scheme: FrostEd25519 (enum index 0)
        data.push(0); // target_vm: Svm (enum index 0)
        data.extend_from_slice(&0u64.to_le_bytes()); // target_chain_id
        data.extend_from_slice(&message_hash); // message_hash [u8;32]
        data.extend_from_slice(&2u16.to_le_bytes()); // threshold (2-of-3)
        data.extend_from_slice(&1000u64.to_le_bytes()); // validity_slots
        let ix = Instruction {
            program_id: program,
            accounts: vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(protocol, false),
                AccountMeta::new(request, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data,
        };
        let sig = send(&rpc, ix, &admin, &[]);
        println!("\n[2] create_signing_request (the on-chain INTENT) tx: {sig}");
    }

    // === Show the ON-CHAIN REQUEST exactly as the coordinator reads it. ===
    let req = decode_request(&rpc.get_account(&request).unwrap().data);
    println!("\n    --- ON-CHAIN SigningRequest (read back by the coordinator) ---");
    println!("    request PDA      : {request}");
    println!("    request_id       : {}", req.request_id);
    println!("    scheme           : {} (0=FrostEd25519)", req.scheme);
    println!("    message_hash     : {}", hex(&req.message_hash));
    println!("    threshold        : {}", req.threshold);
    println!("    status           : {} (0=Pending)", req.status);
    println!("    aggregate_sig    : {} (zero before finalize)", hex(&req.aggregate_sig));
    assert_eq!(req.message_hash, message_hash, "on-chain message mismatch");
    assert_eq!(req.status, 0, "request not Pending");

    // ---- 3a. Coordinator runs the REAL FROST MPC over the on-chain message. ----
    println!("\n[3] coordinator runs FROST round 1/2 + aggregate over the");
    println!("    on-chain message_hash with the 2-of-3 quorum {{operators 1,2}}...");
    let quorum_indices = [1u16, 2];
    let ts = keyset
        .threshold_sign(&quorum_indices, &req.message_hash)
        .expect("FROST signing failed");
    println!("    aggregate signature (64B): {}", hex(&ts.signature));
    // Sanity: same group key as registered on-chain.
    assert_eq!(ts.group_public_key, group_pk);

    // ---- 3b. Submit participation receipts for the 2 signing operators. ----
    // The on-chain `share` is a participation receipt (the program records who
    // signed + their stake; it does NOT recombine shares). We post a non-zero,
    // scheme-shaped receipt per participating operator so the threshold gate
    // (distinct count + staked weight) is satisfied truthfully.
    for &idx in &quorum_indices {
        let op = &op_auths[(idx - 1) as usize];
        let (operator, _) = Pubkey::find_program_address(
            &[b"operator", protocol.as_ref(), op.pubkey().as_ref()],
            &program,
        );
        let (partial, _) = Pubkey::find_program_address(
            &[b"partial", request.as_ref(), operator.as_ref()],
            &program,
        );
        // Receipt material: the operator's commitment to having participated in
        // signing THIS message. Bound to operator+message so it is non-trivial.
        let receipt = participation_receipt(&op.pubkey(), &req.message_hash);
        let mut data = DISC_SUBMIT_PARTIAL.to_vec();
        data.extend_from_slice(&receipt); // share [u8;64]
        let ix = Instruction {
            program_id: program,
            accounts: vec![
                AccountMeta::new(op.pubkey(), true),
                AccountMeta::new_readonly(protocol, false),
                AccountMeta::new(request, false),
                AccountMeta::new(operator, false),
                AccountMeta::new(partial, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data,
        };
        let sig = send(&rpc, ix, op, &[]);
        println!("    submit_partial_signature[op {idx}] tx: {sig}");
    }

    // ---- 3c. Record the REAL aggregate on-chain via aggregate_and_emit. ----
    {
        let mut data = DISC_AGGREGATE_EMIT.to_vec();
        data.extend_from_slice(&ts.signature); // aggregate_sig [u8;64]
        let ix = Instruction {
            program_id: program,
            accounts: vec![
                AccountMeta::new_readonly(admin.pubkey(), true), // relayer (any signer)
                AccountMeta::new_readonly(protocol, false),
                AccountMeta::new(request, false),
            ],
            data,
        };
        let sig = send(&rpc, ix, &admin, &[]);
        println!("    aggregate_and_emit (records the REAL signature) tx: {sig}");
    }

    // ---- 4. Re-read the FINALIZED request and verify independently. ----
    let fin = decode_request(&rpc.get_account(&request).unwrap().data);
    println!("\n[4] --- ON-CHAIN SigningRequest (FINAL state) ---");
    println!("    status           : {} (1=Aggregated)", fin.status);
    println!("    partials_collected: {}", fin.partials_collected);
    println!("    aggregate_sig    : {}", hex(&fin.aggregate_sig));

    assert_eq!(fin.status, 1, "request did not finalize to Aggregated");
    assert_eq!(
        fin.aggregate_sig, ts.signature,
        "on-chain recorded sig != the real FROST aggregate"
    );

    // Independent standard Ed25519 verification of the ON-CHAIN-RECORDED sig
    // against the registered group key and the request's own message_hash.
    let dalek_key = DalekKey::from_bytes(&group_pk).expect("group key not a valid Ed25519 point");
    let dalek_sig = DalekSig::from_bytes(&fin.aggregate_sig);
    dalek_key
        .verify(&fin.message_hash, &dalek_sig)
        .expect("INDEPENDENT ed25519 verify of the ON-CHAIN sig FAILED");

    // Negative control: the same sig must NOT verify over a different message.
    let mut tampered = fin.message_hash;
    tampered[0] ^= 0xFF;
    assert!(
        dalek_key.verify(&tampered, &dalek_sig).is_err(),
        "sig wrongly verified over a different message"
    );

    println!("\n=== END-TO-END VERIFIED ===");
    println!("The signature RECORDED ON-CHAIN at the request PDA is a valid");
    println!("standard Ed25519 signature against the group key, over the EXACT");
    println!("message_hash the on-chain request carried. 2 of 3 operators produced");
    println!("it via real FROST; the group secret was never reconstructed.");
    println!("\nrequest PDA      : {request}");
    println!("group public key : {}", hex(&group_pk));
    println!("on-chain message : {}", hex(&fin.message_hash));
    println!("on-chain sig     : {}", hex(&fin.aggregate_sig));
}

// ---------- helpers ----------

fn airdrop(rpc: &RpcClient, pk: &Pubkey, sol: u64) {
    let sig = rpc.request_airdrop(pk, sol * 1_000_000_000).unwrap();
    loop {
        if rpc.confirm_transaction(&sig).unwrap_or(false) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

fn create_token2022_mint(rpc: &RpcClient, admin: &Keypair) -> Pubkey {
    use solana_sdk::system_instruction;
    let mint = Keypair::new();
    let mint_len = spl_token_2022::state::Mint::LEN;
    let rent_lamports = rpc.get_minimum_balance_for_rent_exemption(mint_len).unwrap();
    let create = system_instruction::create_account(
        &admin.pubkey(),
        &mint.pubkey(),
        rent_lamports,
        mint_len as u64,
        &spl_token_2022::id(),
    );
    let init = spl_token_2022::instruction::initialize_mint(
        &spl_token_2022::id(),
        &mint.pubkey(),
        &admin.pubkey(),
        None,
        9,
    )
    .unwrap();
    let bh = rpc.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[create, init],
        Some(&admin.pubkey()),
        &[admin, &mint],
        bh,
    );
    rpc.send_and_confirm_transaction(&tx).unwrap();
    mint.pubkey()
}

fn create_and_fund_ata(
    rpc: &RpcClient,
    admin: &Keypair,
    mint: &Pubkey,
    owner: &Pubkey,
    amount: u64,
) -> Pubkey {
    let ata = get_associated_token_address_with_program_id(owner, mint, &spl_token_2022::id());
    let create = spl_associated_token_account::instruction::create_associated_token_account(
        &admin.pubkey(),
        owner,
        mint,
        &spl_token_2022::id(),
    );
    let mint_to = spl_token_2022::instruction::mint_to(
        &spl_token_2022::id(),
        mint,
        &ata,
        &admin.pubkey(),
        &[],
        amount,
    )
    .unwrap();
    let bh = rpc.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[create, mint_to],
        Some(&admin.pubkey()),
        &[admin],
        bh,
    );
    rpc.send_and_confirm_transaction(&tx).unwrap();
    ata
}

/// Deterministic non-zero participation receipt with the FROST scheme shape
/// (nonce-commitment half non-zero), bound to the operator and the message.
fn participation_receipt(op: &Pubkey, message_hash: &[u8; 32]) -> [u8; 64] {
    let mut h = Sha256::new();
    h.update(b"distin::participation::frost-ed25519");
    h.update(op.as_ref());
    h.update(message_hash);
    let first: [u8; 32] = h.finalize().into();
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&first); // nonce-commitment half non-zero
    out[32..].copy_from_slice(message_hash); // response half non-zero
    out
}

// Protocol.request_nonce offset after the 8-byte discriminator.
fn read_request_nonce(buf: &[u8]) -> u64 {
    let off = 8 + 32 * 6 + 2 + 8 * 4 + 4 + 8;
    u64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
}

struct ReqView {
    request_id: u64,
    scheme: u8,
    message_hash: [u8; 32],
    threshold: u16,
    partials_collected: u16,
    status: u8,
    aggregate_sig: [u8; 64],
}

// SigningRequest layout after the 8-byte discriminator:
// protocol 32 + requester 32 + request_id 8 + scheme 1 + target_vm 1
// + target_chain_id 8 + message_hash 32 + threshold 2 + partials_collected 2
// + stake_weight_collected 8 + required_stake_weight 8 + created_slot 8
// + expiry_slot 8 + status 1 + aggregate_sig 64 + bump 1
fn decode_request(buf: &[u8]) -> ReqView {
    let mut o = 8 + 32 + 32;
    let request_id = u64::from_le_bytes(buf[o..o + 8].try_into().unwrap());
    o += 8;
    let scheme = buf[o];
    o += 1; // scheme
    o += 1; // target_vm
    o += 8; // target_chain_id
    let mut message_hash = [0u8; 32];
    message_hash.copy_from_slice(&buf[o..o + 32]);
    o += 32;
    let threshold = u16::from_le_bytes(buf[o..o + 2].try_into().unwrap());
    o += 2;
    let partials_collected = u16::from_le_bytes(buf[o..o + 2].try_into().unwrap());
    o += 2;
    o += 8; // stake_weight_collected
    o += 8; // required_stake_weight
    o += 8; // created_slot
    o += 8; // expiry_slot
    let status = buf[o];
    o += 1;
    let mut aggregate_sig = [0u8; 64];
    aggregate_sig.copy_from_slice(&buf[o..o + 64]);
    ReqView {
        request_id,
        scheme,
        message_hash,
        threshold,
        partials_collected,
        status,
        aggregate_sig,
    }
}
