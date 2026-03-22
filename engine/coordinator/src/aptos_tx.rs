//! aptos-tx — prove the FROST group can authorize a REAL Aptos transaction.
//!
//!   cargo run --release --bin aptos-tx
//!
//! Mirrors eth-tx / btc-tx for the FROST Ed25519 branch. It derives the group's
//! Aptos account address from the group public key, BCS-encodes a real Aptos
//! `RawTransaction` (a 0x1::aptos_account::transfer entry function), builds the
//! exact signing message Aptos verifies (sha3-256("APTOS::RawTransaction") ||
//! BCS(raw_txn)), threshold-signs it with 2 of 3 FROST shares, and verifies the
//! aggregate under ed25519-dalek against the group key. Offline and fund-free.
//! The group private key is never assembled in one place.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use kobe::KeySet;
use sha3::{Digest, Sha3_256};

// BCS: unsigned-LEB128 length prefix for vectors and strings.
fn uleb128(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            break;
        }
    }
}

fn bcs_bytes(b: &[u8], out: &mut Vec<u8>) {
    uleb128(b.len() as u64, out);
    out.extend_from_slice(b);
}

fn main() {
    // 1. Group key: fresh 2-of-3 FROST keyset.
    println!("generating a fresh 2-of-3 FROST Ed25519 keyset...");
    let ks = KeySet::generate(3, 2).expect("keygen");
    let group_pk = ks.group_public_key().expect("group key"); // 32-byte ed25519

    // 2. Aptos account address = sha3-256(pubkey || 0x00) for the single-Ed25519
    //    authentication scheme; the auth key equals the account address.
    let mut ah = Sha3_256::new();
    ah.update(group_pk);
    ah.update([0x00]);
    let address: [u8; 32] = ah.finalize().into();
    println!("group Aptos address: 0x{}", hex(&address));

    // 3. BCS-encode a real RawTransaction: transfer 1000 octas to a recipient.
    let recipient = [0x22u8; 32];
    let amount: u64 = 1000;

    // payload = TransactionPayload::EntryFunction (enum variant 2)
    //   EntryFunction { module: 0x1::aptos_account, function: "transfer",
    //                   ty_args: [], args: [bcs(recipient), bcs(amount)] }
    let mut payload = Vec::new();
    uleb128(2, &mut payload); // TransactionPayload::EntryFunction
    let mut module_addr = [0u8; 32];
    module_addr[31] = 0x01; // 0x1
    payload.extend_from_slice(&module_addr);
    bcs_bytes(b"aptos_account", &mut payload); // module name (Identifier = bcs string)
    bcs_bytes(b"transfer", &mut payload); // function name
    uleb128(0, &mut payload); // ty_args: empty vector<TypeTag>
    uleb128(2, &mut payload); // args: vector<vector<u8>> of length 2
    bcs_bytes(&recipient, &mut payload); // arg0: BCS(address) = 32 raw bytes, length-prefixed
    bcs_bytes(&amount.to_le_bytes(), &mut payload); // arg1: BCS(u64) = 8 LE bytes, length-prefixed

    // RawTransaction { sender, sequence_number, payload, max_gas_amount,
    //                  gas_unit_price, expiration_timestamp_secs, chain_id }
    let mut raw = Vec::new();
    raw.extend_from_slice(&address); // sender
    raw.extend_from_slice(&0u64.to_le_bytes()); // sequence_number
    raw.extend_from_slice(&payload); // payload
    raw.extend_from_slice(&2000u64.to_le_bytes()); // max_gas_amount
    raw.extend_from_slice(&100u64.to_le_bytes()); // gas_unit_price
    raw.extend_from_slice(&u64::MAX.to_le_bytes()); // expiration_timestamp_secs
    raw.push(1u8); // chain_id (1 = mainnet; network-agnostic for the signing proof)

    // 4. Aptos signing message = sha3-256("APTOS::RawTransaction") || BCS(raw_txn).
    let mut prefix = Sha3_256::new();
    prefix.update(b"APTOS::RawTransaction");
    let prefix: [u8; 32] = prefix.finalize().into();
    let mut signing_message = Vec::with_capacity(32 + raw.len());
    signing_message.extend_from_slice(&prefix);
    signing_message.extend_from_slice(&raw);
    println!("raw txn (BCS)      : {} bytes", raw.len());
    println!("signing message    : {} bytes (prefix||BCS)", signing_message.len());

    // 5. Threshold-sign the FULL signing message with shares {1,2}.
    println!("threshold-signing the Aptos signing message with shares {{1,2}}...");
    let sig = ks
        .threshold_sign_bytes(&[1, 2], &signing_message)
        .expect("threshold sign");

    // 6. Verify under ed25519-dalek against the group key — the exact check an
    //    Aptos node runs on the transaction authenticator.
    let vk = VerifyingKey::from_bytes(&group_pk).expect("group vk");
    vk.verify(&signing_message, &Signature::from_bytes(&sig))
        .expect("aggregate must verify as a real Aptos Ed25519 signature");

    println!();
    println!("SIGNED, chain-valid Aptos transaction from a threshold signature:");
    println!("  group pubkey     : 0x{}", hex(&group_pk));
    println!("  signature (64B)  : 0x{}", hex(&sig));
    println!("  ed25519-dalek verify over the real signing message: OK ✓");
    println!("  the group private key was never assembled in one place.");
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
