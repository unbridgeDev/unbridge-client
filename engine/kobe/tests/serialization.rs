//! KeySet disk-serialization round-trip. The signer daemon persists its FROST
//! key set with `to_bytes` and reloads it on every restart with `from_bytes`;
//! a silent corruption here would change the group key and orphan the on-chain
//! operator registration. So the property tested is not just byte equality but
//! that a RESTORED set still signs for the ORIGINAL group key.

use ed25519_dalek::{Signature, VerifyingKey};
use kobe::KeySet;

#[test]
fn roundtrip_preserves_group_and_signing() {
    let ks = KeySet::generate(3, 2).expect("keygen");
    let restored = KeySet::from_bytes(&ks.to_bytes().expect("serialize")).expect("deserialize");

    let group = ks.group_public_key().expect("group key");
    assert_eq!(group, restored.group_public_key().unwrap());

    // Sign with the restored shares, verify against the original group key
    // under ed25519-dalek (RFC 8032 — the same check Solana applies).
    let msg = [0x42u8; 32];
    let ts = restored.threshold_sign(&[1, 2], &msg).expect("threshold sign");
    VerifyingKey::from_bytes(&group)
        .unwrap()
        .verify_strict(&msg, &Signature::from_bytes(&ts.signature))
        .expect("restored keyset must sign for the original group key");
}

#[test]
fn from_bytes_rejects_truncation() {
    let ks = KeySet::generate(3, 2).unwrap();
    let bytes = ks.to_bytes().unwrap();
    // Every strict prefix must fail to parse — never yield a partial key set.
    for cut in [0usize, 1, 4, bytes.len() / 2, bytes.len() - 1] {
        assert!(
            KeySet::from_bytes(&bytes[..cut]).is_err(),
            "truncated buffer (len {cut}) must not deserialize"
        );
    }
}
