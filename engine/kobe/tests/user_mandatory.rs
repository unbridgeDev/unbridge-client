//! User-mandatory custody: a 2-of-2 split (user + operator network) where the
//! operator side, even fully colluding, cannot sign without the user's share.
//!
//! This is the cryptographic core of the non-custodial per-user wallet model:
//! the guarantee is not economic (slashing) or procedural (allowlist) but a
//! property of the threshold scheme. The tests assert both the positive case
//! (user + network verifies as a standard Ed25519 signature) and the two
//! negative cases (either party alone is structurally unable to sign).

use ed25519_dalek::{Signature as DalekSig, Verifier, VerifyingKey as DalekKey};
use kobe::KeySet;

const USER: u16 = 1;
const NETWORK: u16 = 2;

/// User + network together produce a real Ed25519 signature under the group key.
#[test]
fn user_plus_network_signs_and_verifies() {
    let message: [u8; 32] = *b"unbridge::custody::user-required";
    let ks = KeySet::generate(2, 2).expect("keygen");
    let group_pk = ks.group_public_key().expect("group pk");

    let sig = ks
        .threshold_sign(&[USER, NETWORK], &message)
        .expect("joint sign");

    // Independent RFC 8032 verification, the same primitive the target chain runs.
    let key = DalekKey::from_bytes(&group_pk).expect("group key is a valid point");
    key.verify(&message, &DalekSig::from_bytes(&sig.signature))
        .expect("independent ed25519-dalek verify");
    assert_eq!(sig.signers, vec![USER, NETWORK]);
}

/// THE guarantee: the operator network alone (party 2), no matter how compromised,
/// is below threshold and cannot produce a signature.
#[test]
#[should_panic(expected = "threshold is 2")]
fn operator_network_alone_cannot_sign() {
    let message = [9u8; 32];
    let ks = KeySet::generate(2, 2).expect("keygen");
    let _ = ks.threshold_sign(&[NETWORK], &message);
}

/// Symmetric safety: a stolen user device alone is also below threshold, so
/// device compromise does not move funds.
#[test]
#[should_panic(expected = "threshold is 2")]
fn user_device_alone_cannot_sign() {
    let message = [9u8; 32];
    let ks = KeySet::generate(2, 2).expect("keygen");
    let _ = ks.threshold_sign(&[USER], &message);
}
