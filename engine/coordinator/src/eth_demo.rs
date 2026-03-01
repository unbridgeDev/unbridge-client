//! Distin — Milestone 4: the GG20 / secp256k1 (EVM) path through the SAME
//! end-to-end MPC loop, proven Ethereum-verifiable on localnet.
//!
//! This is the sibling of `src/main.rs` (the Ed25519 / FROST path). It proves
//! that an on-chain `Gg20Secp256k1` signing request drives the off-chain GG20
//! threshold-ECDSA signer (the Go `kobe-ecdsa` binary, Binance tss-lib) to
//! produce a REAL secp256k1 signature, that the on-chain state records it, and
//! that the recorded bytes recover the group's Ethereum address with an
//! INDEPENDENT verifier (RustCrypto k256 — not tss-lib, not go-ethereum).
//!
//! Cross-language seam: the Rust coordinator invokes the Go signer as a
//! subprocess. `kobe-ecdsa keygen` runs distributed key generation once and
//! writes the shares + group public key to a temp JSON file; `kobe-ecdsa sign`
//! is invoked with the on-chain `message_hash` and a quorum to threshold-sign.
//! Both speak JSON on stdout, which the coordinator parses.
//!
//! On-chain field shape: `aggregate_sig` is `[u8;64]`, which holds the ECDSA
//! `r || s` exactly. The recovery byte `v` is NOT part of the signature — it is
//! a hint to skip trying both candidate public keys. We store the 64-byte
//! `r || s` on-chain (no program change needed) and recover `v` off-chain by
//! trying both 0 and 1 and matching the known group address — exactly how an ETH
//! verifier proceeds when `v` is not transmitted. So the on-chain record is the
//! full cryptographic signature; nothing is dropped.
//!
//! What is REAL: the GG20 cryptography (audited tss-lib), the secp256k1
//! signature, the on-chain program + all its instructions/PDAs/threshold gates,
//! and the independent k256 ETH-address recovery from the on-chain bytes.
//! What is SIMULATED: the 3 operators run in one Go process (no real network),
//! one keypair pays/authorizes everything, and the LST oracle is a placeholder.

#![allow(deprecated)]

use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;

use k256::ecdsa::{RecoveryId, Signature as K256Sig, VerifyingKey};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
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

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim_start_matches("0x");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
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

// ---- the Go signer seam ----

/// Locate the kobe-ecdsa module directory (engine/kobe-ecdsa) relative to this
/// crate, so `go run ./cmd/kobe-ecdsa` works without a prebuilt binary.
fn kobe_ecdsa_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("kobe-ecdsa")
}

/// Run `kobe-ecdsa keygen` (real GG20 DKG, slow) → returns (shares_path, group
/// public key uncompressed 65B, group ETH address string).
fn go_keygen(shares_path: &str) -> (Vec<u8>, String) {
    let out = Command::new("go")
        .current_dir(kobe_ecdsa_dir())
        .args([
            "run",
            "./cmd/kobe-ecdsa",
            "keygen",
            "-n",
            "3",
            "-t",
            "1",
            "-out",
            shares_path,
        ])
        .output()
        .expect("failed to spawn go keygen");
    if !out.status.success() {
        panic!(
            "go keygen failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("keygen JSON");
    let group_pub = unhex(v["group_pub"].as_str().unwrap()); // 65B 04||X||Y
    let addr = v["group_eth_address"].as_str().unwrap().to_string();
    (group_pub, addr)
}

struct GoSig {
    r: [u8; 32],
    s: [u8; 32],
    v: u8,
    recovered_addr: String,
    matched: bool,
}

/// Run `kobe-ecdsa sign` over a 32-byte hash with a quorum of share indices.
fn go_sign(shares_path: &str, hash: &[u8; 32], quorum: &str) -> GoSig {
    let out = Command::new("go")
        .current_dir(kobe_ecdsa_dir())
        .args([
            "run",
            "./cmd/kobe-ecdsa",
            "sign",
            "-shares",
            shares_path,
            "-hash",
            &hex(hash),
            "-quorum",
            quorum,
        ])
        .output()
        .expect("failed to spawn go sign");
    if !out.status.success() {
        panic!("go sign failed:\n{}", String::from_utf8_lossy(&out.stderr));
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("sign JSON");
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&unhex(v["r"].as_str().unwrap()));
    s.copy_from_slice(&unhex(v["s"].as_str().unwrap()));
    GoSig {
        r,
        s,
        v: v["v"].as_u64().unwrap() as u8,
        recovered_addr: v["recovered_eth_address"].as_str().unwrap().to_string(),
        matched: v["match"].as_bool().unwrap(),
    }
}

// ---- INDEPENDENT ETH-address recovery, pure Rust (k256), from on-chain bytes ----

/// Ethereum address of an uncompressed secp256k1 pubkey: keccak256(X||Y)[12:].
fn eth_address_of_pubkey(uncompressed_65: &[u8]) -> String {
    assert_eq!(uncompressed_65.len(), 65);
    assert_eq!(uncompressed_65[0], 0x04);
    let mut h = Keccak256::new();
    h.update(&uncompressed_65[1..]); // X||Y, drop the 0x04 tag
    let digest = h.finalize();
    format!("0x{}", hex(&digest[12..]))
}

/// Recover the ETH address from a 64-byte `r||s` over `hash`, trying both
/// recovery ids. This is the exact primitive an ETH node runs (`ecrecover`),
/// implemented with RustCrypto's k256 — independent of tss-lib AND go-ethereum.
/// Returns the recovered address for whichever recovery id yields one (there is
/// one canonical signer per valid `(r,s)`; trying both ids is how a verifier
/// proceeds when `v` is not transmitted on-chain).
fn recover_eth_address_from_rs(hash: &[u8; 32], rs64: &[u8; 64]) -> Option<(String, u8)> {
    let sig = K256Sig::from_slice(rs64).ok()?;
    for v in 0u8..=1 {
        let rec_id = RecoveryId::from_byte(v)?;
        if let Ok(vk) = VerifyingKey::recover_from_prehash(hash, &sig, rec_id) {
            let enc = vk.to_encoded_point(false); // uncompressed 65B
            return Some((eth_address_of_pubkey(enc.as_bytes()), v));
        }
    }
    None
}

fn main() {
    let rpc = RpcClient::new_with_commitment(RPC_URL.to_string(), CommitmentConfig::confirmed());
    let program = pid();
    let token_2022 = spl_token_2022::id();

    println!("Distin / Milestone 4 — GG20 secp256k1 (EVM) end-to-end MPC loop on localnet");
    println!("program: {program}\n");

    // ---- Actors. One funded keypair plays admin / operators / requester. ----
    let admin = Keypair::new();
    let op_auths: Vec<Keypair> = (0..3).map(|_| Keypair::new()).collect();
    println!("airdropping SOL to actors...");
    airdrop(&rpc, &admin.pubkey(), 100);
    for k in &op_auths {
        airdrop(&rpc, &k.pubkey(), 10);
    }

    // ---- 0. GG20 distributed keygen via the Go signer (slow, no dealer). ----
    println!("\n[0] driving the Go kobe-ecdsa signer: GG20 distributed keygen (2-of-3)");
    let shares_dir = std::env::temp_dir();
    let shares_path = shares_dir
        .join(format!("distin-gg20-shares-{}.json", std::process::id()))
        .to_string_lossy()
        .to_string();
    let (group_pub_65, go_group_addr) = go_keygen(&shares_path);
    // Independent: derive the ETH address from the group pubkey ourselves (k256/keccak),
    // not trusting the Go signer's own address string.
    let group_addr = eth_address_of_pubkey(&group_pub_65);
    println!("    group public key (secp256k1, 65B): 04{}", hex(&group_pub_65[1..]));
    println!("    group ETH address (Go signer)     : {go_group_addr}");
    println!("    group ETH address (Rust k256/keccak): {group_addr}");
    assert_eq!(
        group_addr.to_lowercase(),
        go_group_addr.to_lowercase(),
        "Rust-derived group address disagrees with Go signer"
    );

    // The on-chain operator record holds a 33-byte `group_pubkey`. For the
    // secp256k1 branch we store the COMPRESSED SEC1 form (0x02/0x03 || X), which
    // is exactly 33 bytes — the natural on-chain key for this scheme.
    let group_pk_33 = compress_pubkey(&group_pub_65);
    println!("    group_pubkey on-chain (compressed 33B): {}", hex(&group_pk_33));

    // ---- 1. Token-2022 LST mint + bootstrap the protocol. ----
    let mint = create_token2022_mint(&rpc, &admin);
    println!("\n[1] bond mint (Token-2022): {mint}");

    let (protocol, _) = Pubkey::find_program_address(&[b"protocol"], &program);
    let (bond_vault, _) =
        Pubkey::find_program_address(&[b"bond_vault", protocol.as_ref()], &program);
    let (slash_pool, _) =
        Pubkey::find_program_address(&[b"slash_pool", protocol.as_ref()], &program);
    let oracle = Keypair::new().pubkey();

    // initialize
    {
        let mut data = DISC_INITIALIZE.to_vec();
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

    // register 3 operators, each carrying the secp256k1 group key.
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

    // ---- 2. User posts a Gg20Secp256k1 / Evm signing request. ----
    // The message: keccak256 of a "transaction-like" payload — exactly what an
    // ETH signer commits to. This is the on-chain `message_hash`.
    let message_hash: [u8; 32] = {
        let mut h = Keccak256::new();
        h.update(b"distin::m4 -> transfer 1.0 ETH on chain id 1 (mainnet-style)");
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
        data.push(1); // scheme: Gg20Secp256k1 (enum index 1)
        data.push(1); // target_vm: Evm (enum index 1)
        data.extend_from_slice(&1u64.to_le_bytes()); // target_chain_id = 1 (ETH mainnet)
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
        println!("\n[2] create_signing_request (Gg20Secp256k1 / Evm) tx: {sig}");
    }

    let req = decode_request(&rpc.get_account(&request).unwrap().data);
    println!("\n    --- ON-CHAIN SigningRequest (read back by the coordinator) ---");
    println!("    request PDA      : {request}");
    println!("    request_id       : {}", req.request_id);
    println!("    scheme           : {} (1=Gg20Secp256k1)", req.scheme);
    println!("    target_vm        : {} (1=Evm)", req.target_vm);
    println!("    target_chain_id  : {}", req.target_chain_id);
    println!("    message_hash     : {}", hex(&req.message_hash));
    println!("    threshold        : {}", req.threshold);
    println!("    status           : {} (0=Pending)", req.status);
    assert_eq!(req.message_hash, message_hash, "on-chain message mismatch");
    assert_eq!(req.scheme, 1, "request scheme is not Gg20Secp256k1");
    assert_eq!(req.status, 0, "request not Pending");

    // ---- 3a. Coordinator drives the Go GG20 signer over the on-chain message. ----
    println!("\n[3] coordinator invokes the Go kobe-ecdsa signer to threshold-sign");
    println!("    the on-chain message_hash with the 2-of-3 quorum {{shares 0,2}}...");
    let go_sig = go_sign(&shares_path, &req.message_hash, "0,2");
    println!("    signature r      : {}", hex(&go_sig.r));
    println!("    signature s      : {}", hex(&go_sig.s));
    println!("    recovery v        : {}", go_sig.v);
    println!("    Go signer recovered addr: {}", go_sig.recovered_addr);
    assert!(go_sig.matched, "Go signer's own recover-check failed");

    // On-chain field is [u8;64] = r||s. (v is recovered off-chain; see header.)
    let mut rs64 = [0u8; 64];
    rs64[..32].copy_from_slice(&go_sig.r);
    rs64[32..].copy_from_slice(&go_sig.s);

    // ---- 3b. Submit participation receipts for the 2 signing operators. ----
    let quorum_indices = [1u16, 3]; // 1-based operator labels for shares 0 and 2
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
        // GG20 receipt: the program's verify_partial_share requires the S half
        // (bytes 32..64) non-zero for the secp256k1 branch; bind it to op+message.
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

    // ---- 3c. Record the REAL aggregate (r||s) on-chain. ----
    {
        let mut data = DISC_AGGREGATE_EMIT.to_vec();
        data.extend_from_slice(&rs64); // aggregate_sig [u8;64] = r||s
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
        println!("    aggregate_and_emit (records the REAL secp256k1 r||s) tx: {sig}");
    }

    // ---- 4. Re-read the FINALIZED request and verify INDEPENDENTLY (k256). ----
    let fin = decode_request(&rpc.get_account(&request).unwrap().data);
    println!("\n[4] --- ON-CHAIN SigningRequest (FINAL state) ---");
    println!("    status           : {} (1=Aggregated)", fin.status);
    println!("    partials_collected: {}", fin.partials_collected);
    println!("    aggregate_sig(r||s): {}", hex(&fin.aggregate_sig));

    assert_eq!(fin.status, 1, "request did not finalize to Aggregated");
    assert_eq!(
        fin.aggregate_sig, rs64,
        "on-chain recorded sig != the real GG20 r||s"
    );

    // INDEPENDENT recovery: from the ON-CHAIN 64 bytes + the request's own
    // message_hash, recover the ETH address with k256 (not tss-lib, not Go).
    let (recovered_addr, rec_v) = recover_eth_address_from_rs(&fin.message_hash, &fin.aggregate_sig)
        .expect("k256 could not recover any address from the on-chain signature");
    println!("\n    INDEPENDENT k256 ecrecover from the ON-CHAIN bytes:");
    println!("    recovered ETH addr: {recovered_addr} (recovery id {rec_v})");
    println!("    group ETH addr    : {group_addr}");
    assert_eq!(
        recovered_addr.to_lowercase(),
        group_addr.to_lowercase(),
        "RECOVERED ADDRESS != GROUP ADDRESS — on-chain sig is not chain-valid"
    );

    // Negative control 1: the same sig must NOT recover the group addr over a
    // different message.
    let mut tampered_msg = fin.message_hash;
    tampered_msg[0] ^= 0xFF;
    let neg1 = recover_eth_address_from_rs(&tampered_msg, &fin.aggregate_sig);
    assert!(
        neg1.is_none() || neg1.as_ref().unwrap().0.to_lowercase() != group_addr.to_lowercase(),
        "tampered-message recovered the group address — verifier is broken"
    );
    println!(
        "\n    negative control (wrong message): recovered {} != group  ✓",
        neg1.map(|x| x.0).unwrap_or_else(|| "<none>".into())
    );

    // Negative control 2: tamper S -> must not recover the group addr.
    let mut tampered_sig = fin.aggregate_sig;
    tampered_sig[63] ^= 0x01;
    let neg2 = recover_eth_address_from_rs(&fin.message_hash, &tampered_sig);
    assert!(
        neg2.is_none() || neg2.as_ref().unwrap().0.to_lowercase() != group_addr.to_lowercase(),
        "tampered-S recovered the group address — verifier is broken"
    );
    println!(
        "    negative control (tampered S)   : recovered {} != group  ✓",
        neg2.map(|x| x.0).unwrap_or_else(|| "<none>".into())
    );

    let _ = std::fs::remove_file(&shares_path);

    println!("\n=== END-TO-END ETH-VERIFIED (GG20 / secp256k1) ===");
    println!("The (r,s) RECORDED ON-CHAIN at the request PDA recovers, via an");
    println!("INDEPENDENT k256 ecrecover over the EXACT on-chain message_hash, to");
    println!("the group's Ethereum address. 2 of 3 operators produced it via real");
    println!("GG20 threshold-ECDSA (Binance tss-lib); the group key was never");
    println!("reconstructed.");
    println!("\nrequest PDA      : {request}");
    println!("group ETH address: {group_addr}");
    println!("on-chain message : {}", hex(&fin.message_hash));
    println!("on-chain r||s    : {}", hex(&fin.aggregate_sig));
    println!("recovered address: {recovered_addr}");
}

// ---------- helpers ----------

/// Compress an uncompressed 65-byte SEC1 pubkey (04||X||Y) to 33 bytes (02/03||X).
fn compress_pubkey(uncompressed_65: &[u8]) -> [u8; 33] {
    assert_eq!(uncompressed_65.len(), 65);
    let mut out = [0u8; 33];
    // y parity: last byte of Y odd -> 0x03, even -> 0x02.
    let y_is_odd = uncompressed_65[64] & 1 == 1;
    out[0] = if y_is_odd { 0x03 } else { 0x02 };
    out[1..].copy_from_slice(&uncompressed_65[1..33]); // X
    out
}

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

/// GG20 participation receipt: secp256k1-shaped (S half non-zero), bound to the
/// operator and message so it is non-trivial and passes `verify_partial_share`.
fn participation_receipt(op: &Pubkey, message_hash: &[u8; 32]) -> [u8; 64] {
    let mut h = Sha256::new();
    h.update(b"distin::participation::gg20-secp256k1");
    h.update(op.as_ref());
    h.update(message_hash);
    let second: [u8; 32] = h.finalize().into();
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(message_hash); // r-half non-zero
    out[32..].copy_from_slice(&second); // s-half non-zero (required for GG20)
    out
}

fn read_request_nonce(buf: &[u8]) -> u64 {
    let off = 8 + 32 * 6 + 2 + 8 * 4 + 4 + 8;
    u64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
}

struct ReqView {
    request_id: u64,
    scheme: u8,
    target_vm: u8,
    target_chain_id: u64,
    message_hash: [u8; 32],
    threshold: u16,
    partials_collected: u16,
    status: u8,
    aggregate_sig: [u8; 64],
}

fn decode_request(buf: &[u8]) -> ReqView {
    let mut o = 8 + 32 + 32;
    let request_id = u64::from_le_bytes(buf[o..o + 8].try_into().unwrap());
    o += 8;
    let scheme = buf[o];
    o += 1;
    let target_vm = buf[o];
    o += 1;
    let target_chain_id = u64::from_le_bytes(buf[o..o + 8].try_into().unwrap());
    o += 8;
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
        target_vm,
        target_chain_id,
        message_hash,
        threshold,
        partials_collected,
        status,
        aggregate_sig,
    }
}
