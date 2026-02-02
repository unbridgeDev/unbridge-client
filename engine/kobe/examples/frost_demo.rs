//! Runnable demo of Distin's 2-of-3 FROST Ed25519 threshold signer.
//!
//!   cargo run --example frost_demo
//!
//! Prints the group public key, the aggregate signature, and a VERIFIED line
//! confirmed by an independent standard Ed25519 verifier (ed25519-dalek).

use ed25519_dalek::{Signature as DalekSig, Verifier, VerifyingKey as DalekKey};
use kobe::frost_threshold_sign;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let message: [u8; 32] = *b"distin: one account, every chain";

    println!("Distin / kobe — 2-of-3 FROST Ed25519 threshold signer\n");
    println!("scheme       : FrostEd25519 (SVM / Cosmos branch)");
    println!("parties      : 3, threshold : 2");
    println!("signing quorum: participants {{1, 2}}  (party 3 stays offline)");
    println!("message (32B): {}", hex(&message));

    let r = frost_threshold_sign(3, 2, &[1, 2], &message).expect("threshold signing failed");

    println!("\ngroup pubkey : {}", hex(&r.group_public_key));
    println!("signature(64): {}", hex(&r.signature));

    // Independent standard Ed25519 verification — what an SVM/Cosmos chain runs.
    let dalek_key = DalekKey::from_bytes(&r.group_public_key).expect("invalid Ed25519 group key");
    dalek_key
        .verify(&r.message, &DalekSig::from_bytes(&r.signature))
        .expect("independent ed25519-dalek verification failed");

    println!("\nindependent ed25519-dalek verify against the group key:");
    println!("VERIFIED — 2 of 3 shares produced a valid standard Ed25519 signature,");
    println!("           and the group secret was never reconstructed.");
}
