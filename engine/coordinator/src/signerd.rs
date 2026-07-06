//! distin-signerd — the persistent off-chain signer daemon.
//!
//! Unlike `demo` (a one-shot localnet ceremony that keygens fresh every run and
//! signs its own request), this binary holds ONE long-lived FROST key set on
//! disk, registers it on-chain once, then runs a poll loop that watches devnet
//! for `Pending` `FrostEd25519` `SigningRequest`s — including the ones the
//! product web posts — and completes each with real FROST partials + the
//! aggregate signature. That is what makes the product actually usable: a
//! request posted from the browser gets signed on-chain by this daemon.
//!
//!   signerd bootstrap   # init protocol (if needed) + register operators
//!   signerd run         # poll + sign forever
//!   signerd request <64-hex-message>   # post a test request like the web does
//!
//! Config is env-overridable so the same binary serves devnet or mainnet.

use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::time::Duration;

use k256::ecdsa::{RecoveryId, Signature as K256Sig, VerifyingKey};
use kobe::KeySet;
use sha2::{Digest, Sha256};
use sha3::{Digest as _, Keccak256};
use solana_client::rpc_client::RpcClient;
use solana_client::rpc_config::RpcProgramAccountsConfig;
use solana_client::rpc_filter::{Memcmp, MemcmpEncodedBytes, RpcFilterType};
use solana_sdk::program_pack::Pack;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_instruction, system_program, sysvar,
    transaction::Transaction,
};
use spl_associated_token_account::get_associated_token_address_with_program_id;

// ---- config (env-overridable) ----
fn rpc_url() -> String {
    std::env::var("DISTIN_RPC_URL").unwrap_or_else(|_| "https://api.devnet.solana.com".into())
}
fn program_id() -> Pubkey {
    let s = std::env::var("DISTIN_PROGRAM_ID")
        .unwrap_or_else(|_| "4xy9dYHfAzi7cAcX5JHxNR6EoMJ9PGfeQDMHx6YUQQM6".into());
    Pubkey::from_str(&s).unwrap()
}
fn keys_dir() -> String {
    std::env::var("DISTIN_KEYS_DIR").unwrap_or_else(|_| "keys".into())
}

// operator set: 2-of-3, 60% economic threshold (2 ops carry 66.7% > 60%).
const N: u16 = 3;
const T: u16 = 2;
const THRESHOLD_BPS: u16 = 6000;
const BOND_AMOUNT: u64 = 10_000_000;

// instruction discriminators (Anchor "global:<name>", first 8 bytes).
const DISC_INITIALIZE: [u8; 8] = [175, 175, 109, 31, 13, 152, 155, 237];
const DISC_REGISTER_OPERATOR: [u8; 8] = [49, 242, 151, 125, 212, 136, 31, 89];
const DISC_CREATE_REQUEST: [u8; 8] = [81, 124, 188, 129, 112, 241, 32, 39];
const DISC_SUBMIT_PARTIAL: [u8; 8] = [226, 18, 202, 183, 167, 26, 196, 50];
const DISC_AGGREGATE_EMIT: [u8; 8] = [66, 189, 125, 18, 115, 114, 117, 74];

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_else(|| "run".into());
    let rpc = RpcClient::new_with_commitment(rpc_url(), CommitmentConfig::confirmed());
    let program = program_id();
    println!("distin-signerd | rpc={} | program={}", rpc_url(), program);

    match cmd.as_str() {
        "bootstrap" => bootstrap(&rpc, &program),
        "bootstrap-gg20" => bootstrap_gg20(&rpc, &program),
        "bootstrap-frostnet" => bootstrap_frostnet(&rpc, &program),
        "seal-keys" => seal_keys(),
        "run" => run(&rpc, &program),
        "request" => {
            let hexmsg = std::env::args().nth(2).expect("usage: request <64-hex>");
            let msg = decode_hex32(&hexmsg);
            post_request(&rpc, &program, &msg, 0);
        }
        "request-gg20" => {
            let hexmsg = std::env::args().nth(2).expect("usage: request-gg20 <64-hex>");
            let msg = decode_hex32(&hexmsg);
            post_request(&rpc, &program, &msg, 1);
        }
        other => panic!("unknown command: {other} (bootstrap | bootstrap-gg20 | seal-keys | run | request | request-gg20 <hex>)"),
    }
}

// ---- key management ----

/// Load the admin keypair (protocol authority + fee payer). Defaults to the
/// engine's deploy key, which is the on-chain admin / upgrade / mint authority.
fn load_admin() -> Keypair {
    let path = std::env::var("DISTIN_ADMIN_KEYPAIR").unwrap_or_else(|_| {
        format!(
            "{}/Downloads/concept-machine/passed/DISTIN/engine/deploy.json",
            std::env::var("HOME").unwrap()
        )
    });
    read_keypair(&path)
}

fn read_keypair(path: &str) -> Keypair {
    let bytes: Vec<u8> = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    Keypair::from_bytes(&bytes).unwrap()
}

// Key material must not be world-readable: dir 0700, files 0600.
fn make_keys_dir() -> String {
    let dir = keys_dir();
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir).unwrap();
    dir
}

// ---- encryption-at-rest (opt-in via DISTIN_KEY_PASSPHRASE) ----
// File layout when sealed: MAGIC(6) | salt(16) | nonce(12) | ciphertext+tag.
// Argon2id(passphrase, salt) -> 32-byte key; ChaCha20-Poly1305 seals. Files
// WITHOUT the magic are read as plaintext, so pre-existing keys keep working —
// sealing is a one-shot `seal-keys` migration, never an implicit break.
const KEY_MAGIC: &[u8; 6] = b"DSTNK1";

fn key_passphrase() -> Option<String> {
    std::env::var("DISTIN_KEY_PASSPHRASE").ok().filter(|s| !s.is_empty())
}

fn derive_key(pass: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    argon2::Argon2::default()
        .hash_password_into(pass.as_bytes(), salt, &mut key)
        .expect("argon2 kdf failed");
    key
}

fn seal(plain: &[u8], pass: &str) -> Vec<u8> {
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Key, Nonce};
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut salt).unwrap();
    getrandom::getrandom(&mut nonce).unwrap();
    let key = derive_key(pass, &salt);
    let ct = ChaCha20Poly1305::new(Key::from_slice(&key))
        .encrypt(Nonce::from_slice(&nonce), plain)
        .expect("seal failed");
    let mut out = Vec::with_capacity(6 + 16 + 12 + ct.len());
    out.extend_from_slice(KEY_MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

fn unseal(buf: &[u8], pass: &str) -> Vec<u8> {
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Key, Nonce};
    let key = derive_key(pass, &buf[6..22]);
    ChaCha20Poly1305::new(Key::from_slice(&key))
        .decrypt(Nonce::from_slice(&buf[22..34]), &buf[34..])
        .expect("decrypt failed — wrong DISTIN_KEY_PASSPHRASE?")
}

/// Read secret bytes, transparently decrypting a sealed file.
fn read_secret(path: &str) -> std::io::Result<Vec<u8>> {
    let buf = std::fs::read(path)?;
    if buf.len() >= 6 && &buf[..6] == KEY_MAGIC {
        let pass = key_passphrase()
            .expect("key file is sealed but DISTIN_KEY_PASSPHRASE is not set");
        Ok(unseal(&buf, &pass))
    } else {
        Ok(buf)
    }
}

fn write_secret(path: &str, bytes: &[u8]) {
    // Seal at rest when a passphrase is configured; otherwise write as-is.
    let payload = match key_passphrase() {
        Some(pass) => seal(bytes, &pass),
        None => bytes.to_vec(),
    };
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    f.write_all(&payload).unwrap();
}

/// One-shot migration: re-write on-disk key material sealed under
/// DISTIN_KEY_PASSPHRASE. Reads each file (plaintext or already-sealed) and
/// writes it back sealed. Idempotent; does not regenerate any key.
fn seal_keys() {
    assert!(key_passphrase().is_some(), "set DISTIN_KEY_PASSPHRASE before seal-keys");
    let dir = keys_dir();
    let ks_path = format!("{dir}/keyset.bin");
    if let Ok(buf) = read_secret(&ks_path) {
        KeySet::from_bytes(&buf).expect("keyset.bin corrupt — refusing to re-seal");
        write_secret(&ks_path, &buf);
        println!("sealed {ks_path}");
    }
    for i in 1..=N {
        let p = format!("{dir}/op{i}.json");
        if let Ok(buf) = read_secret(&p) {
            write_secret(&p, &buf);
            println!("sealed {p}");
        }
    }
    println!("done — FROST keyset + operator keypairs encrypted at rest.");
    println!("keep DISTIN_KEY_PASSPHRASE set in the daemon env (launchd/Docker secret).");
}

#[cfg(test)]
mod kms_tests {
    use super::{read_secret, seal, unseal, KEY_MAGIC};

    // A sealed blob decrypts back to the exact plaintext under the same passphrase.
    #[test]
    fn seal_roundtrip() {
        let plain = b"a FROST key share \x00\x01\xff and some bytes";
        let sealed = seal(plain, "correct horse battery staple");
        assert_eq!(&sealed[..6], KEY_MAGIC, "sealed blob must carry the magic header");
        assert_ne!(&sealed[6..], &plain[..], "plaintext must not appear in the blob");
        assert_eq!(unseal(&sealed, "correct horse battery staple"), plain);
    }

    // Two seals of the same input differ (fresh salt+nonce), so the blob leaks
    // nothing about repeated key material.
    #[test]
    fn seal_is_randomized() {
        let plain = b"same input twice";
        assert_ne!(seal(plain, "p"), seal(plain, "p"));
    }

    // AEAD authentication: the wrong passphrase must fail closed, never return
    // garbage plaintext.
    #[test]
    #[should_panic(expected = "decrypt failed")]
    fn wrong_passphrase_fails() {
        let sealed = seal(b"secret", "right");
        let _ = unseal(&sealed, "wrong");
    }

    // Backward compatibility — THE property that keeps the live daemon safe: a
    // pre-existing plaintext key file (no magic header) is read verbatim, with no
    // passphrase set. Enabling encryption never bricks a restart on old keys.
    #[test]
    fn plaintext_passthrough() {
        let plain = b"\x03\x00\x02\x00 legacy keyset.bin bytes, unencrypted";
        assert_ne!(&plain[..6], KEY_MAGIC, "fixture must not collide with the magic");
        let path = std::env::temp_dir()
            .join(format!("distin-kms-{}-{}.bin", std::process::id(), line!()));
        std::fs::write(&path, plain).unwrap();
        let got = read_secret(path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(got, plain);
    }
}

fn load_or_make_operator(i: u16) -> Keypair {
    let dir = make_keys_dir();
    let path = format!("{dir}/op{i}.json");
    if let Ok(buf) = read_secret(&path) {
        let bytes: Vec<u8> = serde_json::from_slice(&buf).unwrap();
        Keypair::from_bytes(&bytes).unwrap()
    } else {
        let kp = Keypair::new();
        write_secret(&path, serde_json::to_string(&kp.to_bytes().to_vec()).unwrap().as_bytes());
        kp
    }
}

fn load_or_make_keyset() -> KeySet {
    let path = format!("{}/keyset.bin", keys_dir());
    if let Ok(buf) = read_secret(&path) {
        KeySet::from_bytes(&buf).expect("keyset.bin corrupt")
    } else {
        let ks = KeySet::generate(N, T).expect("FROST keygen failed");
        make_keys_dir();
        write_secret(&path, &ks.to_bytes().unwrap());
        println!("generated new FROST {T}-of-{N} keyset -> {path}");
        ks
    }
}

// ---- bootstrap: init protocol (if needed) + register the operator set ----

fn bootstrap(rpc: &RpcClient, program: &Pubkey) {
    let admin = load_admin();
    let ops: Vec<Keypair> = (1..=N).map(load_or_make_operator).collect();
    let keyset = load_or_make_keyset();
    let group_pk = keyset.group_public_key().unwrap();
    let mut group_pk_33 = [0u8; 33];
    group_pk_33[1..].copy_from_slice(&group_pk);
    println!("admin: {}", admin.pubkey());
    println!("group public key: {}", hex(&group_pk));

    let (protocol, _) = Pubkey::find_program_address(&[b"protocol"], program);
    let (bond_vault, _) = Pubkey::find_program_address(&[b"bond_vault", protocol.as_ref()], program);
    let (slash_pool, _) = Pubkey::find_program_address(&[b"slash_pool", protocol.as_ref()], program);
    let token_2022 = spl_token_2022::id();

    // fund operator authorities from admin so they can sign register txs.
    for op in &ops {
        if rpc.get_balance(&op.pubkey()).unwrap() < 30_000_000 {
            let ix = system_instruction::transfer(&admin.pubkey(), &op.pubkey(), 50_000_000);
            send(rpc, ix, &admin, &[]);
        }
    }

    // If the protocol already exists we reuse its bond mint; else init fresh.
    let bond_mint = match rpc.get_account(&protocol) {
        Ok(acc) => {
            let mint = Pubkey::new_from_array(acc.data[72..104].try_into().unwrap());
            println!("protocol already initialized; bond mint {mint}");
            mint
        }
        Err(_) => {
            let mint = create_token2022_mint(rpc, &admin);
            println!("created bond mint (Token-2022): {mint}");
            let oracle = Pubkey::new_unique(); // non-default placeholder feed
            let mut data = DISC_INITIALIZE.to_vec();
            data.extend_from_slice(&THRESHOLD_BPS.to_le_bytes());
            data.extend_from_slice(&1_000_000u64.to_le_bytes()); // min_bond
            data.extend_from_slice(&10u64.to_le_bytes()); // unbonding_slots
            data.extend_from_slice(&0u64.to_le_bytes()); // request_fee
            data.extend_from_slice(&216_000u64.to_le_bytes()); // max_validity_slots
            data.extend_from_slice(oracle.as_ref());
            let ix = Instruction {
                program_id: *program,
                accounts: vec![
                    AccountMeta::new(admin.pubkey(), true),
                    AccountMeta::new(protocol, false),
                    AccountMeta::new_readonly(mint, false),
                    AccountMeta::new(bond_vault, false),
                    AccountMeta::new(slash_pool, false),
                    AccountMeta::new_readonly(token_2022, false),
                    AccountMeta::new_readonly(system_program::id(), false),
                    AccountMeta::new_readonly(sysvar::rent::id(), false),
                ],
                data,
            };
            println!("initialize tx: {}", send(rpc, ix, &admin, &[]));
            mint
        }
    };

    let proto = rpc.get_account(&protocol).unwrap();
    let oracle = Pubkey::new_from_array(proto.data[8 + 32 * 5..8 + 32 * 6].try_into().unwrap());

    for (i, op) in ops.iter().enumerate() {
        let (operator, _) = Pubkey::find_program_address(
            &[b"operator", protocol.as_ref(), op.pubkey().as_ref()],
            program,
        );
        if rpc.get_account(&operator).is_ok() {
            println!("operator {} already registered", i + 1);
            continue;
        }
        let op_ata = create_and_fund_ata(rpc, &admin, &bond_mint, &op.pubkey(), BOND_AMOUNT);
        let mut data = DISC_REGISTER_OPERATOR.to_vec();
        data.extend_from_slice(&group_pk_33);
        data.extend_from_slice(&BOND_AMOUNT.to_le_bytes());
        let ix = Instruction {
            program_id: *program,
            accounts: vec![
                AccountMeta::new(op.pubkey(), true),
                AccountMeta::new(protocol, false),
                AccountMeta::new(operator, false),
                AccountMeta::new_readonly(bond_mint, false),
                AccountMeta::new(op_ata, false),
                AccountMeta::new(bond_vault, false),
                AccountMeta::new_readonly(oracle, false),
                AccountMeta::new_readonly(token_2022, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data,
        };
        println!("register_operator[{}] tx: {}", i + 1, send(rpc, ix, op, &[]));
    }
    println!("\nbootstrap done. protocol {protocol} ready with {N} operators.");
}

// ---- run: poll devnet, sign every pending FROST request ----

fn run(rpc: &RpcClient, program: &Pubkey) {
    let admin = load_admin();
    let ops: Vec<Keypair> = (1..=N).map(load_or_make_operator).collect();
    let keyset = load_or_make_keyset();
    // GG20 operator authorities are loaded lazily (only if a gg20 set exists on disk).
    let gg20 = Gg20Set::load_if_present();
    // Networked FROST set: when present, scheme-0 requests sign via 3 separate
    // operator processes over mTLS instead of the in-process keyset.
    let frostnet = FrostNetSet::load_if_present();
    let (protocol, _) = Pubkey::find_program_address(&[b"protocol"], program);
    let req_disc = anchor_disc("account:SigningRequest");
    println!(
        "watching for pending requests ({}{}) ... (Ctrl-C to stop)\n",
        if frostnet.is_some() { "networked FROST" } else { "in-process FROST" },
        if gg20.is_some() { " + GG20" } else { "" }
    );

    loop {
        let cfg = RpcProgramAccountsConfig {
            filters: Some(vec![RpcFilterType::Memcmp(Memcmp::new(
                0,
                MemcmpEncodedBytes::Bytes(req_disc.to_vec()),
            ))]),
            account_config: solana_client::rpc_config::RpcAccountInfoConfig {
                encoding: Some(solana_account_decoder::UiAccountEncoding::Base64),
                commitment: Some(CommitmentConfig::confirmed()),
                ..Default::default()
            },
            ..Default::default()
        };
        let accts = rpc
            .get_program_accounts_with_config(program, cfg)
            .unwrap_or_default();
        let slot = rpc.get_slot().unwrap_or(0);

        for (pda, acc) in accts {
            let r = decode_request(&acc.data);
            if r.status != 0 || slot > r.expiry_slot {
                continue; // only Pending, not expired
            }
            if require_wallet() && !wallet_registered(rpc, program, &protocol, &r.requester) {
                eprintln!(
                    "  request {pda}: requester {} has no registered wallet, skipping",
                    r.requester
                );
                continue;
            }
            // Isolate each request: a panic inside fulfill (e.g. an RPC send that
            // unwraps on a transient error) must skip this one request, never take
            // the whole daemon down. catch_unwind turns it into a logged skip.
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match r.scheme {
                0 => match &frostnet {
                    Some(f) => fulfill_frostnet(rpc, program, &protocol, &admin, f, &pda, &r),
                    None => fulfill(rpc, program, &protocol, &admin, &ops, &keyset, &pda, &r),
                },
                1 => match &gg20 {
                    Some(g) => fulfill_gg20(rpc, program, &protocol, &admin, g, &pda, &r),
                    None => Ok(()), // no GG20 set bootstrapped yet
                },
                _ => Ok(()),
            }));
            match outcome {
                Ok(Ok(())) => {}
                Ok(Err(e)) => eprintln!("  request {pda}: {e}"),
                Err(_) => eprintln!("  request {pda}: signing panicked, skipping (daemon stays up)"),
            }
        }
        std::thread::sleep(Duration::from_secs(3));
    }
}

fn fulfill(
    rpc: &RpcClient,
    program: &Pubkey,
    protocol: &Pubkey,
    admin: &Keypair,
    ops: &[Keypair],
    keyset: &KeySet,
    request: &Pubkey,
    r: &ReqView,
) -> Result<(), String> {
    let quorum = [1u16, 2];
    let ts = keyset
        .threshold_sign(&quorum, &r.message_hash)
        .map_err(|e| format!("frost sign: {e}"))?;

    println!("request {} (id {}) -> signing", request, r.request_id);
    for &idx in &quorum {
        let op = &ops[(idx - 1) as usize];
        let (operator, _) = Pubkey::find_program_address(
            &[b"operator", protocol.as_ref(), op.pubkey().as_ref()],
            program,
        );
        let (partial, _) =
            Pubkey::find_program_address(&[b"partial", request.as_ref(), operator.as_ref()], program);
        if rpc.get_account(&partial).is_ok() {
            continue; // this operator already submitted
        }
        let receipt = participation_receipt(&op.pubkey(), &r.message_hash);
        let mut data = DISC_SUBMIT_PARTIAL.to_vec();
        data.extend_from_slice(&receipt);
        let ix = Instruction {
            program_id: *program,
            accounts: vec![
                AccountMeta::new(op.pubkey(), true),
                AccountMeta::new_readonly(*protocol, false),
                AccountMeta::new(*request, false),
                AccountMeta::new(operator, false),
                AccountMeta::new(partial, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data,
        };
        println!("  submit_partial[op {idx}] tx: {}", send(rpc, ix, op, &[]));
    }

    let mut data = DISC_AGGREGATE_EMIT.to_vec();
    data.extend_from_slice(&ts.signature);
    let ix = Instruction {
        program_id: *program,
        accounts: vec![
            AccountMeta::new_readonly(admin.pubkey(), true),
            AccountMeta::new_readonly(*protocol, false),
            AccountMeta::new(*request, false),
        ],
        data,
    };
    println!("  aggregate_and_emit tx: {}", send(rpc, ix, admin, &[]));
    println!("  signed. group sig {}", hex(&ts.signature));
    Ok(())
}

// ---- post a test request (mimics the product web's create_signing_request) ----

fn post_request(rpc: &RpcClient, program: &Pubkey, message_hash: &[u8; 32], scheme: u8) {
    let admin = load_admin();
    let (protocol, _) = Pubkey::find_program_address(&[b"protocol"], program);
    // Client-chosen nonce (requester + nonce seed the request PDA); use the slot
    // for a fresh value each call.
    let client_nonce = rpc.get_slot().unwrap_or(0);
    let (request, _) = Pubkey::find_program_address(
        &[b"request", admin.pubkey().as_ref(), &client_nonce.to_le_bytes()],
        program,
    );
    let mut data = DISC_CREATE_REQUEST.to_vec();
    data.extend_from_slice(&client_nonce.to_le_bytes()); // client_nonce (first arg)
    data.push(scheme); // 0=FrostEd25519, 1=Gg20Secp256k1
    data.push(if scheme == 1 { 1 } else { 0 }); // target_vm: Evm for gg20, Svm for frost
    data.extend_from_slice(&0u64.to_le_bytes()); // target_chain_id
    data.extend_from_slice(message_hash);
    data.extend_from_slice(&T.to_le_bytes()); // threshold
    data.extend_from_slice(&1000u64.to_le_bytes()); // validity_slots
    let ix = Instruction {
        program_id: *program,
        accounts: vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(protocol, false),
            AccountMeta::new(request, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data,
    };
    println!("create_signing_request tx: {}", send(rpc, ix, &admin, &[]));
    println!("request PDA: {request}");
}

// ---- helpers (shared shape with demo main.rs) ----

fn anchor_disc(preimage: &str) -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(preimage.as_bytes());
    let full: [u8; 32] = h.finalize().into();
    full[..8].try_into().unwrap()
}

fn send(rpc: &RpcClient, ix: Instruction, payer: &Keypair, extra: &[&Keypair]) -> String {
    let mut signers: Vec<&Keypair> = vec![payer];
    signers.extend_from_slice(extra);
    let bh = rpc.get_latest_blockhash().unwrap();
    let tx =
        Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &signers, bh);
    rpc.send_and_confirm_transaction(&tx).unwrap().to_string()
}

fn create_token2022_mint(rpc: &RpcClient, admin: &Keypair) -> Pubkey {
    let mint = Keypair::new();
    let mint_len = spl_token_2022::state::Mint::LEN;
    let rent = rpc.get_minimum_balance_for_rent_exemption(mint_len).unwrap();
    let create = system_instruction::create_account(
        &admin.pubkey(),
        &mint.pubkey(),
        rent,
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
    let tx =
        Transaction::new_signed_with_payer(&[create, init], Some(&admin.pubkey()), &[admin, &mint], bh);
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
    let tx = Transaction::new_signed_with_payer(&[create, mint_to], Some(&admin.pubkey()), &[admin], bh);
    rpc.send_and_confirm_transaction(&tx).unwrap();
    ata
}

fn participation_receipt(op: &Pubkey, message_hash: &[u8; 32]) -> [u8; 64] {
    let mut h = Sha256::new();
    h.update(b"distin::participation::frost-ed25519");
    h.update(op.as_ref());
    h.update(message_hash);
    let first: [u8; 32] = h.finalize().into();
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&first);
    out[32..].copy_from_slice(message_hash);
    out
}

fn read_request_nonce(buf: &[u8]) -> u64 {
    let off = 8 + 32 * 6 + 2 + 8 * 4 + 4 + 8;
    u64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
}

struct ReqView {
    request_id: u64,
    requester: Pubkey,
    scheme: u8,
    message_hash: [u8; 32],
    status: u8,
    expiry_slot: u64,
}

fn decode_request(buf: &[u8]) -> ReqView {
    let requester = Pubkey::new_from_array(buf[8 + 32..8 + 64].try_into().unwrap());
    let mut o = 8 + 32 + 32;
    let request_id = u64::from_le_bytes(buf[o..o + 8].try_into().unwrap());
    o += 8;
    let scheme = buf[o];
    o += 1 + 1 + 8; // scheme + target_vm + target_chain_id
    let mut message_hash = [0u8; 32];
    message_hash.copy_from_slice(&buf[o..o + 32]);
    o += 32;
    o += 2 + 2 + 8 + 8 + 8; // threshold + partials + stake_collected + required + created_slot
    let expiry_slot = u64::from_le_bytes(buf[o..o + 8].try_into().unwrap());
    o += 8;
    let status = buf[o];
    ReqView {
        request_id,
        requester,
        scheme,
        message_hash,
        status,
        expiry_slot,
    }
}

/// Wallet-gate policy (second line of defense behind the on-chain constraint).
///
/// With `DISTIN_REQUIRE_WALLET=1` the daemon only fulfills requests whose
/// requester has a registered `Wallet` PDA (`[b"wallet", protocol, requester]`
/// holding that same authority). Requests from unregistered requesters are
/// skipped, whichever instruction created them. Default off: the live devnet
/// flow (legacy permissionless requests) keeps working until clients migrate.
fn require_wallet() -> bool {
    std::env::var("DISTIN_REQUIRE_WALLET").map(|v| v == "1") == Ok(true)
}

fn wallet_registered(
    rpc: &RpcClient,
    program: &Pubkey,
    protocol: &Pubkey,
    requester: &Pubkey,
) -> bool {
    let (wallet, _) = Pubkey::find_program_address(
        &[b"wallet", protocol.as_ref(), requester.as_ref()],
        program,
    );
    let Ok(acc) = rpc.get_account(&wallet) else {
        return false; // account absent (or RPC error): fail closed
    };
    // Wallet layout: disc 8 + protocol 32 + authority 32 + registered_slot 8 + bump 1.
    acc.owner == *program && acc.data.len() >= 81 && acc.data[40..72] == requester.to_bytes()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn decode_hex32(s: &str) -> [u8; 32] {
    let s = s.trim_start_matches("0x");
    assert_eq!(s.len(), 64, "message must be 32 bytes (64 hex chars)");
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

#[allow(dead_code)]
fn _use(_: BTreeMap<u8, u8>) {}

// ================= GG20 secp256k1 (Bitcoin / Ethereum / Tron / Cosmos) =================
// Drives the Go tss-lib GG20 operators for secp256k1 requests. The on-chain
// group_pubkey is a non-default identity bound to the group ETH address; the
// cryptographic proof is the on-chain r||s recovering (ecrecover) to that address.

struct Gg20Set {
    ops: Vec<Keypair>, // on-chain operator authorities
    bin_dir: String,
    ops_dir: String,
    log_dir: String,
    group_addr: String,
}

impl Gg20Set {
    fn dir() -> String {
        format!("{}/gg20", keys_dir())
    }
    fn load_if_present() -> Option<Gg20Set> {
        let base = Self::dir();
        if !std::path::Path::new(&format!("{base}/op1.json")).exists() {
            return None;
        }
        let group_addr = std::fs::read_to_string(format!("{base}/group_addr.txt"))
            .ok()?
            .trim()
            .to_string();
        let ops = (1..=N)
            .map(|i| read_keypair(&format!("{base}/op{i}.json")))
            .collect();
        Some(Gg20Set {
            ops,
            // Overridable so a container ships its own linux operator binaries
            // (the on-disk keys are cross-platform; the Go binaries are not).
            bin_dir: std::env::var("DISTIN_GG20_BIN_DIR").unwrap_or_else(|_| format!("{base}/bin")),
            ops_dir: format!("{base}/operators"),
            log_dir: format!("{base}/logs"),
            group_addr,
        })
    }
}

fn gg20_group_pk_33(group_addr: &str) -> [u8; 33] {
    let mut h = Keccak256::new();
    h.update(b"distin::group_pubkey::");
    h.update(group_addr.as_bytes());
    let d = h.finalize();
    let mut out = [0u8; 33];
    out[0] = 0x02;
    out[1..].copy_from_slice(&d[..32]);
    out
}

fn read_or_make_keypair(path: &str) -> Keypair {
    if let Ok(s) = std::fs::read_to_string(path) {
        let b: Vec<u8> = serde_json::from_str(&s).unwrap();
        Keypair::from_bytes(&b).unwrap()
    } else {
        let kp = Keypair::new();
        std::fs::write(path, serde_json::to_string(&kp.to_bytes().to_vec()).unwrap()).unwrap();
        kp
    }
}

fn update_threshold(rpc: &RpcClient, program: &Pubkey, admin: &Keypair, protocol: &Pubkey, bps: u16) {
    let mut data = anchor_disc("global:update_config").to_vec();
    data.push(1); // threshold_bps = Some
    data.extend_from_slice(&bps.to_le_bytes());
    data.extend_from_slice(&[0, 0, 0, 0]); // min_bond/unbonding/request_fee/max_validity = None
    let ix = Instruction {
        program_id: *program,
        accounts: vec![
            AccountMeta::new_readonly(admin.pubkey(), true),
            AccountMeta::new(*protocol, false),
        ],
        data,
    };
    println!("update_config threshold_bps={bps} tx: {}", send(rpc, ix, admin, &[]));
}

fn bootstrap_gg20(rpc: &RpcClient, program: &Pubkey) {
    let admin = load_admin();
    let base = Gg20Set::dir();
    let bin_dir = format!("{base}/bin");
    let ops_dir = format!("{base}/operators");
    let log_dir = format!("{base}/logs");
    for d in [&bin_dir, &ops_dir, &log_dir] {
        std::fs::create_dir_all(d).unwrap();
    }
    let (protocol, _) = Pubkey::find_program_address(&[b"protocol"], program);

    // Lower the economic threshold so a 2-of-3 quorum still passes with both the
    // FROST + GG20 sets bonded (6 ops): attesters = ceil(6*3000/1e4) = 2.
    update_threshold(rpc, program, &admin, &protocol, 3000);

    println!("building GG20 (tss-lib) operator binaries...");
    build_operator_binaries(&bin_dir);
    if !std::path::Path::new(&format!("{ops_dir}/op0.json")).exists() {
        println!("minting 3 GG20 operator identities...");
        gen_operators(&bin_dir, &ops_dir, 9300);
    }

    let addr_path = format!("{base}/group_addr.txt");
    let group_addr = if let Ok(a) = std::fs::read_to_string(&addr_path) {
        a.trim().to_string()
    } else {
        println!("running GG20 distributed keygen (3 separate processes over TCP)...");
        let procs = launch_operators(
            &bin_dir,
            &ops_dir,
            &log_dir,
            &["-phase", "keygen", "-threshold", "1", "-timeout", "300s"],
            "kg",
        );
        let results = join_operators(procs);
        let mut ga = None;
        for (idx, ok, json) in &results {
            assert!(*ok, "gg20 keygen op {idx} failed (see {log_dir}/kg-op{idx}.log)");
            ga = Some(json["group_eth_address"].as_str().unwrap().to_string());
        }
        let a = ga.unwrap();
        std::fs::write(&addr_path, &a).unwrap();
        a
    };
    println!("GG20 group ETH address: {group_addr}");
    let group_pk_33 = gg20_group_pk_33(&group_addr);

    let proto = rpc.get_account(&protocol).unwrap();
    let bond_mint = Pubkey::new_from_array(proto.data[72..104].try_into().unwrap());
    let oracle = Pubkey::new_from_array(proto.data[8 + 32 * 5..8 + 32 * 6].try_into().unwrap());
    let (bond_vault, _) = Pubkey::find_program_address(&[b"bond_vault", protocol.as_ref()], program);
    let token_2022 = spl_token_2022::id();

    for i in 1..=N {
        let op = read_or_make_keypair(&format!("{base}/op{i}.json"));
        if rpc.get_balance(&op.pubkey()).unwrap() < 30_000_000 {
            send(
                rpc,
                system_instruction::transfer(&admin.pubkey(), &op.pubkey(), 50_000_000),
                &admin,
                &[],
            );
        }
        let (operator, _) = Pubkey::find_program_address(
            &[b"operator", protocol.as_ref(), op.pubkey().as_ref()],
            program,
        );
        if rpc.get_account(&operator).is_ok() {
            println!("gg20 operator {i} already registered");
            continue;
        }
        let op_ata = create_and_fund_ata(rpc, &admin, &bond_mint, &op.pubkey(), BOND_AMOUNT);
        let mut data = DISC_REGISTER_OPERATOR.to_vec();
        data.extend_from_slice(&group_pk_33);
        data.extend_from_slice(&BOND_AMOUNT.to_le_bytes());
        let ix = Instruction {
            program_id: *program,
            accounts: vec![
                AccountMeta::new(op.pubkey(), true),
                AccountMeta::new(protocol, false),
                AccountMeta::new(operator, false),
                AccountMeta::new_readonly(bond_mint, false),
                AccountMeta::new(op_ata, false),
                AccountMeta::new(bond_vault, false),
                AccountMeta::new_readonly(oracle, false),
                AccountMeta::new_readonly(token_2022, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data,
        };
        println!("register gg20 operator[{i}] tx: {}", send(rpc, ix, &op, &[]));
    }
    println!("\nGG20 bootstrap done. Bitcoin/ETH/Tron/Cosmos requests will now sign.");
}

fn fulfill_gg20(
    rpc: &RpcClient,
    program: &Pubkey,
    protocol: &Pubkey,
    admin: &Keypair,
    g: &Gg20Set,
    request: &Pubkey,
    r: &ReqView,
) -> Result<(), String> {
    let hash_hex = hex(&r.message_hash);
    let procs = launch_operators(
        &g.bin_dir,
        &g.ops_dir,
        &g.log_dir,
        &["-phase", "sign", "-quorum", "0,2", "-hash", &hash_hex, "-timeout", "120s"],
        "sg",
    );
    let results = join_operators(procs);
    let mut rs64: Option<[u8; 64]> = None;
    for (idx, ok, json) in &results {
        if !ok {
            return Err(format!("gg20 operator {idx} sign failed"));
        }
        if json["participated"].as_bool().unwrap_or(false) {
            let rb = decode_hex32(json["r"].as_str().ok_or("missing r")?);
            let sb = decode_hex32(json["s"].as_str().ok_or("missing s")?);
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&rb);
            buf[32..].copy_from_slice(&sb);
            rs64 = Some(buf);
        }
    }
    let rs64 = rs64.ok_or("no gg20 signature produced")?;

    println!("request {} (id {}) -> GG20 signing", request, r.request_id);
    for &oi in &[0usize, 2usize] {
        let op = &g.ops[oi];
        let (operator, _) = Pubkey::find_program_address(
            &[b"operator", protocol.as_ref(), op.pubkey().as_ref()],
            program,
        );
        let (partial, _) =
            Pubkey::find_program_address(&[b"partial", request.as_ref(), operator.as_ref()], program);
        if rpc.get_account(&partial).is_ok() {
            continue;
        }
        let receipt = participation_receipt(&op.pubkey(), &r.message_hash);
        let mut data = DISC_SUBMIT_PARTIAL.to_vec();
        data.extend_from_slice(&receipt);
        let ix = Instruction {
            program_id: *program,
            accounts: vec![
                AccountMeta::new(op.pubkey(), true),
                AccountMeta::new_readonly(*protocol, false),
                AccountMeta::new(*request, false),
                AccountMeta::new(operator, false),
                AccountMeta::new(partial, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data,
        };
        println!("  submit_partial[gg20 op{oi}] tx: {}", send(rpc, ix, op, &[]));
    }
    let mut data = DISC_AGGREGATE_EMIT.to_vec();
    data.extend_from_slice(&rs64);
    let ix = Instruction {
        program_id: *program,
        accounts: vec![
            AccountMeta::new_readonly(admin.pubkey(), true),
            AccountMeta::new_readonly(*protocol, false),
            AccountMeta::new(*request, false),
        ],
        data,
    };
    println!("  aggregate_and_emit tx: {}", send(rpc, ix, admin, &[]));
    match recover_candidates_from_rs(&r.message_hash, &rs64)
        .into_iter()
        .find(|(a, _)| a.to_lowercase() == g.group_addr.to_lowercase())
    {
        Some((addr, _)) => println!("  GG20 signed. r||s ecrecovers to {addr} ✓"),
        None => println!("  GG20 signed (r||s recorded); recover check inconclusive"),
    }
    Ok(())
}

// ---- Go (tss-lib) operator process seam ----

fn kobe_ecdsa_dir() -> PathBuf {
    if let Ok(d) = std::env::var("KOBE_ECDSA_DIR") {
        return PathBuf::from(d);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("kobe-ecdsa")
}

fn kobe_frost_dir() -> PathBuf {
    if let Ok(d) = std::env::var("KOBE_FROST_DIR") {
        return PathBuf::from(d);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("kobe")
}

fn build_operator_binaries(bin_dir: &str) {
    // The Go operator reaches the AUDITED FROST crypto (engine/kobe) over cgo, so
    // build kobe as a cdylib first and point CGO_LDFLAGS at it.
    let kobe = kobe_frost_dir();
    let dylib_dir = kobe.join("target/release");
    if !dylib_dir.join("libkobe.dylib").exists() && !dylib_dir.join("libkobe.so").exists() {
        println!("building the audited FROST cdylib (engine/kobe)...");
        let out = Command::new("cargo")
            .current_dir(&kobe)
            .args(["build", "--release"])
            .output()
            .expect("failed to spawn cargo build kobe");
        assert!(
            out.status.success(),
            "kobe cdylib build failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let ldflags = format!(
        "-L{d} -lkobe -Wl,-rpath,{d}",
        d = dylib_dir.display()
    );
    for (name, src) in [("operator", "./cmd/operator"), ("gen-operators", "./cmd/gen-operators")] {
        let out = Command::new("go")
            .current_dir(kobe_ecdsa_dir())
            .env("CGO_LDFLAGS", &ldflags)
            .args(["build", "-o", &format!("{bin_dir}/{name}"), src])
            .output()
            .expect("failed to spawn go build");
        assert!(
            out.status.success(),
            "go build {name} failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

fn gen_operators(bin_dir: &str, ops_dir: &str, base_port: u16) {
    let out = Command::new(format!("{bin_dir}/gen-operators"))
        .current_dir(kobe_ecdsa_dir())
        .args(["-n", "3", "-base-port", &base_port.to_string(), "-dir", ops_dir])
        .output()
        .expect("failed to spawn gen-operators");
    assert!(
        out.status.success(),
        "gen-operators failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

struct OpProc {
    index: usize,
    child: Child,
}

fn launch_operators(bin_dir: &str, ops_dir: &str, log_dir: &str, extra: &[&str], tag: &str) -> Vec<OpProc> {
    launch_named_operators("operator", bin_dir, ops_dir, log_dir, extra, tag)
}

fn launch_named_operators(
    bin: &str,
    bin_dir: &str,
    ops_dir: &str,
    log_dir: &str,
    extra: &[&str],
    tag: &str,
) -> Vec<OpProc> {
    let mut procs = Vec::new();
    std::fs::create_dir_all(log_dir).ok(); // may be pruned on a fresh host
    for idx in 0..3 {
        let cfg = format!("{ops_dir}/op{idx}.json");
        let log = std::fs::File::create(format!("{log_dir}/{tag}-op{idx}.log")).unwrap();
        let mut args: Vec<String> = vec!["-config".into(), cfg];
        for a in extra {
            args.push((*a).to_string());
        }
        let child = Command::new(format!("{bin_dir}/{bin}"))
            .current_dir(kobe_ecdsa_dir())
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::from(log))
            .spawn()
            .expect("failed to spawn operator process");
        procs.push(OpProc { index: idx, child });
    }
    procs
}

fn join_operators(procs: Vec<OpProc>) -> Vec<(usize, bool, serde_json::Value)> {
    let mut out = Vec::new();
    for p in procs {
        let res = p.child.wait_with_output().expect("wait operator");
        let stdout = String::from_utf8_lossy(&res.stdout);
        let json = serde_json::from_str(stdout.trim()).unwrap_or(serde_json::Value::Null);
        out.push((p.index, res.status.success(), json));
    }
    out
}

fn eth_address_of_pubkey(uncompressed_65: &[u8]) -> String {
    let mut h = Keccak256::new();
    h.update(&uncompressed_65[1..]);
    let d = h.finalize();
    format!("0x{}", hex(&d[12..]))
}

fn recover_candidates_from_rs(hash: &[u8; 32], rs64: &[u8; 64]) -> Vec<(String, u8)> {
    let mut out = Vec::new();
    let Ok(sig) = K256Sig::from_slice(rs64) else {
        return out;
    };
    for v in 0u8..=1 {
        let Some(rid) = RecoveryId::from_byte(v) else {
            continue;
        };
        if let Ok(vk) = VerifyingKey::recover_from_prehash(hash, &sig, rid) {
            let enc = vk.to_encoded_point(false);
            out.push((eth_address_of_pubkey(enc.as_bytes()), v));
        }
    }
    out
}

// ================= Networked FROST (independent operator processes) =================
// Drives cmd/frost-operator — 3 separate OS processes over mutual TLS running the
// AUDITED ZF frost-ed25519 DKG + threshold sign (the frost_demo.sh stack). When a
// frostnet set exists on disk, scheme-0 requests are signed by THESE processes
// instead of the in-process KeySet, making FROST as distributed as GG20. The
// coordinator re-verifies the aggregate under ed25519-dalek before submitting —
// it never trusts the Go processes.

struct FrostNetSet {
    ops: Vec<Keypair>, // on-chain operator authorities (sealed at rest)
    bin_dir: String,
    ops_dir: String,
    log_dir: String,
    group_pk: [u8; 32],
}

impl FrostNetSet {
    fn dir() -> String {
        format!("{}/frostnet", keys_dir())
    }
    fn load_if_present() -> Option<FrostNetSet> {
        let base = Self::dir();
        if !std::path::Path::new(&format!("{base}/op1.json")).exists() {
            return None;
        }
        let pk_hex = std::fs::read_to_string(format!("{base}/group_pubkey.txt")).ok()?;
        let group_pk = decode_hex32(pk_hex.trim());
        let ops = (1..=N)
            .map(|i| read_or_make_sealed_keypair(&format!("{base}/op{i}.json")))
            .collect();
        let ops_dir = format!("{base}/operators");
        // The per-operator mTLS configs (operators/op{idx}.json) store share/cert
        // paths as ABSOLUTE paths, frozen at `bootstrap-frostnet` time on whatever
        // host generated them. When the sealed key material is shipped to a
        // different host (e.g. baked into the Fly image from a mac), those paths
        // no longer resolve and every frost-operator aborts at config load. Re-root
        // each path field at the live ops_dir so the set is host-portable and this
        // self-heals on every daemon start.
        normalize_operator_configs(&ops_dir);
        Some(FrostNetSet {
            ops,
            bin_dir: std::env::var("DISTIN_FROSTNET_BIN_DIR")
                .unwrap_or_else(|_| format!("{base}/bin")),
            ops_dir,
            log_dir: format!("{base}/logs"),
            group_pk,
        })
    }
}

/// Rewrite the absolute path fields in each `operators/op{idx}.json` so they
/// point at `ops_dir` on THIS host. Only the filename of each stored path is
/// kept (every field points into the operators dir); `cert_dir` becomes
/// `ops_dir` itself. Idempotent: files already correct are left untouched.
fn normalize_operator_configs(ops_dir: &str) {
    let rebase = |stored: &str| -> String {
        let name = std::path::Path::new(stored)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        format!("{ops_dir}/{name}")
    };
    for idx in 0..3 {
        let path = format!("{ops_dir}/op{idx}.json");
        let Ok(raw) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(mut cfg) = serde_json::from_str::<serde_json::Value>(&raw) else {
            continue;
        };
        let mut changed = false;
        for field in ["share_path", "ca_cert", "leaf_cert"] {
            if let Some(v) = cfg.get(field).and_then(|v| v.as_str()) {
                let fixed = rebase(v);
                if fixed != v {
                    cfg[field] = serde_json::Value::String(fixed);
                    changed = true;
                }
            }
        }
        if cfg.get("cert_dir").and_then(|v| v.as_str()) != Some(ops_dir) {
            cfg["cert_dir"] = serde_json::Value::String(ops_dir.to_string());
            changed = true;
        }
        if changed {
            if let Ok(s) = serde_json::to_string_pretty(&cfg) {
                let _ = std::fs::write(&path, s);
            }
        }
    }
}

/// Like read_or_make_keypair but sealed at rest under DISTIN_KEY_PASSPHRASE.
fn read_or_make_sealed_keypair(path: &str) -> Keypair {
    if let Ok(buf) = read_secret(path) {
        let b: Vec<u8> = serde_json::from_slice(&buf).unwrap();
        Keypair::from_bytes(&b).unwrap()
    } else {
        let kp = Keypair::new();
        write_secret(path, serde_json::to_string(&kp.to_bytes().to_vec()).unwrap().as_bytes());
        kp
    }
}

fn decode_hex64(s: &str) -> [u8; 64] {
    assert_eq!(s.len(), 128, "signature must be 64 bytes (128 hex chars)");
    let mut out = [0u8; 64];
    for i in 0..64 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

fn bootstrap_frostnet(rpc: &RpcClient, program: &Pubkey) {
    let admin = load_admin();
    let base = FrostNetSet::dir();
    let bin_dir = format!("{base}/bin");
    let ops_dir = format!("{base}/operators");
    let log_dir = format!("{base}/logs");
    for d in [&bin_dir, &ops_dir, &log_dir] {
        std::fs::create_dir_all(d).unwrap();
    }
    let (protocol, _) = Pubkey::find_program_address(&[b"protocol"], program);

    // 9 equal-bond operators after this set joins: a 2-op quorum carries 22.2%,
    // so the economic threshold must sit at 2000 bps BEFORE registration (drop it
    // first — lowering never invalidates existing quorums, so nothing breaks).
    update_threshold(rpc, program, &admin, &protocol, 2000);

    println!("building frost-operator (networked FROST) binaries...");
    build_frostnet_binaries(&bin_dir);
    if !std::path::Path::new(&format!("{ops_dir}/op0.json")).exists() {
        println!("minting 3 frostnet operator identities (mTLS PKI)...");
        let out = Command::new(format!("{bin_dir}/gen-operators"))
            .current_dir(kobe_ecdsa_dir())
            .args(["-n", "3", "-base-port", "9400", "-dir", &ops_dir, "-tls"])
            .output()
            .expect("failed to spawn gen-operators");
        assert!(
            out.status.success(),
            "gen-operators failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let pk_path = format!("{base}/group_pubkey.txt");
    let group_pk_hex = if let Ok(s) = std::fs::read_to_string(&pk_path) {
        s.trim().to_string()
    } else {
        println!("running FROST distributed keygen (3 separate processes over mTLS)...");
        let procs = launch_named_operators(
            "frost-operator",
            &bin_dir,
            &ops_dir,
            &log_dir,
            &["-phase", "keygen", "-timeout", "300s"],
            "kg",
        );
        let results = join_operators(procs);
        let mut pk = None;
        for (idx, ok, json) in &results {
            assert!(*ok, "frostnet keygen op {idx} failed (see {log_dir}/kg-op{idx}.log)");
            let g = json["group_pubkey"].as_str().expect("keygen output missing group_pubkey");
            match &pk {
                None => pk = Some(g.to_string()),
                Some(prev) => assert_eq!(prev, g, "operators disagree on the group pubkey"),
            }
        }
        let pk = pk.unwrap();
        std::fs::write(&pk_path, &pk).unwrap();
        println!("frostnet group pubkey: {pk}");
        pk
    };
    let group_pk = decode_hex32(&group_pk_hex);
    let mut group_pk_33 = [0u8; 33];
    group_pk_33[1..].copy_from_slice(&group_pk);

    // fund + register the 3 on-chain authorities bonded to THIS group key.
    let ops: Vec<Keypair> =
        (1..=N).map(|i| read_or_make_sealed_keypair(&format!("{base}/op{i}.json"))).collect();
    let proto = rpc.get_account(&protocol).expect("protocol not initialized");
    let bond_mint = Pubkey::new_from_array(proto.data[72..104].try_into().unwrap());
    let oracle = Pubkey::new_from_array(proto.data[8 + 32 * 5..8 + 32 * 6].try_into().unwrap());
    let (bond_vault, _) =
        Pubkey::find_program_address(&[b"bond_vault", protocol.as_ref()], program);
    let token_2022 = spl_token_2022::id();

    for (i, op) in ops.iter().enumerate() {
        let (operator, _) = Pubkey::find_program_address(
            &[b"operator", protocol.as_ref(), op.pubkey().as_ref()],
            program,
        );
        if rpc.get_account(&operator).is_ok() {
            println!("frostnet operator {} already registered", i + 1);
            continue;
        }
        if rpc.get_balance(&op.pubkey()).unwrap() < 30_000_000 {
            let ix = system_instruction::transfer(&admin.pubkey(), &op.pubkey(), 50_000_000);
            send(rpc, ix, &admin, &[]);
        }
        let op_ata = create_and_fund_ata(rpc, &admin, &bond_mint, &op.pubkey(), BOND_AMOUNT);
        let mut data = DISC_REGISTER_OPERATOR.to_vec();
        data.extend_from_slice(&group_pk_33);
        data.extend_from_slice(&BOND_AMOUNT.to_le_bytes());
        let ix = Instruction {
            program_id: *program,
            accounts: vec![
                AccountMeta::new(op.pubkey(), true),
                AccountMeta::new(protocol, false),
                AccountMeta::new(operator, false),
                AccountMeta::new_readonly(bond_mint, false),
                AccountMeta::new(op_ata, false),
                AccountMeta::new(bond_vault, false),
                AccountMeta::new_readonly(oracle, false),
                AccountMeta::new_readonly(token_2022, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data,
        };
        println!("register_operator[frostnet {}] tx: {}", i + 1, send(rpc, ix, op, &[]));
    }
    println!("\nfrostnet bootstrap done. scheme-0 requests now sign via 3 networked processes.");
}

fn build_frostnet_binaries(bin_dir: &str) {
    let kobe = kobe_frost_dir();
    let dylib_dir = kobe.join("target/release");
    assert!(
        dylib_dir.join("libkobe.dylib").exists() || dylib_dir.join("libkobe.so").exists(),
        "build engine/kobe (cargo build --release) first"
    );
    let ldflags = format!("-L{d} -lkobe -Wl,-rpath,{d}", d = dylib_dir.display());
    for (name, src) in [("frost-operator", "./cmd/frost-operator"), ("gen-operators", "./cmd/gen-operators")] {
        let out = Command::new("go")
            .current_dir(kobe_ecdsa_dir())
            .env("CGO_LDFLAGS", &ldflags)
            .args(["build", "-o", &format!("{bin_dir}/{name}"), src])
            .output()
            .expect("failed to spawn go build");
        assert!(
            out.status.success(),
            "go build {name} failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

fn fulfill_frostnet(
    rpc: &RpcClient,
    program: &Pubkey,
    protocol: &Pubkey,
    admin: &Keypair,
    f: &FrostNetSet,
    request: &Pubkey,
    r: &ReqView,
) -> Result<(), String> {
    let hash_hex = hex(&r.message_hash);
    let procs = launch_named_operators(
        "frost-operator",
        &f.bin_dir,
        &f.ops_dir,
        &f.log_dir,
        &["-phase", "sign", "-quorum", "0,2", "-msg", &hash_hex, "-aggregator", "0", "-timeout", "120s"],
        "sg",
    );
    let results = join_operators(procs);
    let mut sig: Option<[u8; 64]> = None;
    for (idx, ok, json) in &results {
        if !ok {
            return Err(format!("frostnet operator {idx} sign failed"));
        }
        if let Some(s) = json["signature"].as_str() {
            let g = json["group_pubkey"].as_str().ok_or("missing group_pubkey")?;
            if decode_hex32(g) != f.group_pk {
                return Err("aggregator group pubkey does not match the registered group".into());
            }
            sig = Some(decode_hex64(s));
        }
    }
    let sig = sig.ok_or("no frostnet signature produced")?;

    // Independent verification: ed25519-dalek against the ON-CHAIN-registered
    // group key, before anything is submitted. RFC 8032 — what Solana checks.
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&f.group_pk)
        .map_err(|e| format!("bad group key: {e}"))?;
    vk.verify_strict(&r.message_hash, &ed25519_dalek::Signature::from_bytes(&sig))
        .map_err(|e| format!("networked aggregate failed independent verify: {e}"))?;

    println!("request {} (id {}) -> networked FROST signing (3 processes, mTLS)", request, r.request_id);
    for &oi in &[0usize, 2usize] {
        let op = &f.ops[oi];
        let (operator, _) = Pubkey::find_program_address(
            &[b"operator", protocol.as_ref(), op.pubkey().as_ref()],
            program,
        );
        let (partial, _) =
            Pubkey::find_program_address(&[b"partial", request.as_ref(), operator.as_ref()], program);
        if rpc.get_account(&partial).is_ok() {
            continue;
        }
        let receipt = participation_receipt(&op.pubkey(), &r.message_hash);
        let mut data = DISC_SUBMIT_PARTIAL.to_vec();
        data.extend_from_slice(&receipt);
        let ix = Instruction {
            program_id: *program,
            accounts: vec![
                AccountMeta::new(op.pubkey(), true),
                AccountMeta::new_readonly(*protocol, false),
                AccountMeta::new(*request, false),
                AccountMeta::new(operator, false),
                AccountMeta::new(partial, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data,
        };
        println!("  submit_partial[frostnet op{oi}] tx: {}", send(rpc, ix, op, &[]));
    }
    let mut data = DISC_AGGREGATE_EMIT.to_vec();
    data.extend_from_slice(&sig);
    let ix = Instruction {
        program_id: *program,
        accounts: vec![
            AccountMeta::new_readonly(admin.pubkey(), true),
            AccountMeta::new_readonly(*protocol, false),
            AccountMeta::new(*request, false),
        ],
        data,
    };
    println!("  aggregate_and_emit tx: {}", send(rpc, ix, admin, &[]));
    println!("  networked FROST signed. group sig {} (dalek-verified)", hex(&sig));
    Ok(())
}
