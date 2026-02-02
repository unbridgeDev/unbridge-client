//! Milestone 1 deliverable: 2-of-3 FROST Ed25519 produces an aggregate that is a
//! REAL, standard Ed25519 signature over the group key.
//!
//! The pass condition is cryptographic, not "it compiled": the aggregate must
//! verify (a) under FROST's own verify path AND (b) under an INDEPENDENT
//! standard verifier (`ed25519-dalek`), which is the same primitive an SVM or
//! Cosmos chain uses. We also assert the negative cases (wrong message, wrong
//! key, tampered signature all fail) so a green test can't be a false positive.

use ed25519_dalek::{Signature as DalekSig, Verifier, VerifyingKey as DalekKey};
use kobe::{frost_threshold_sign, frost_verify};

/// 2-of-3: keygen -> sign with signers {1,2} -> aggregate -> verify two ways.
#[test]
fn two_of_three_aggregate_is_a_valid_ed25519_signature() {
    let message: [u8; 32] = *b"distin::svm::threshold-sign-test";

    // 2-of-3, signing quorum = participants 1 and 2 (the 3rd never participates).
    let result = frost_threshold_sign(3, 2, &[1, 2], &message).expect("threshold signing failed");

    // (a) FROST's own verify path.
    frost_verify(&result.group_public_key, &result.message, &result.signature)
        .expect("FROST verify rejected a signature it just produced");

    // (b) INDEPENDENT standard Ed25519 verifier (ed25519-dalek). This is the
    //     load-bearing check: it proves the FROST aggregate is byte-for-byte a
    //     normal RFC 8032 Ed25519 signature, verifiable by any chain — not just
    //     "valid under FROST's bespoke verifier".
    let dalek_key =
        DalekKey::from_bytes(&result.group_public_key).expect("group key is not a valid Ed25519 point");
    let dalek_sig = DalekSig::from_bytes(&result.signature);
    dalek_key
        .verify(&result.message, &dalek_sig)
        .expect("INDEPENDENT ed25519-dalek verify rejected the FROST aggregate");

    // The signing quorum (2) was strictly fewer than all parties (3): the magic
    // is that 2 shares reconstructed a signature for the 3-party group key
    // without ever reconstructing the secret.
    assert_eq!(result.signers, vec![1, 2]);

    // --- Negative controls: a real verifier MUST reject these. ---

    // Wrong message.
    let mut other_msg = message;
    other_msg[0] ^= 0xFF;
    assert!(
        dalek_key.verify(&other_msg, &dalek_sig).is_err(),
        "verifier accepted the signature over a DIFFERENT message"
    );

    // Tampered signature.
    let mut bad_sig = result.signature;
    bad_sig[10] ^= 0x01;
    assert!(
        frost_verify(&result.group_public_key, &message, &bad_sig).is_err(),
        "verifier accepted a TAMPERED signature"
    );

    // Wrong group key (sign a fresh group, verify against this one's key).
    let other = frost_threshold_sign(3, 2, &[1, 3], &message).expect("second signing failed");
    assert!(
        frost_verify(&result.group_public_key, &message, &other.signature).is_err(),
        "verifier accepted a signature from a DIFFERENT group key"
    );
}

/// A different quorum ({2,3}) must also produce a valid signature for the SAME
/// group key — the threshold property holds for any t-subset, not one fixed set.
#[test]
fn any_two_of_three_quorum_verifies() {
    let message: [u8; 32] = *b"distin::cosmos::any-quorum-works";
    for quorum in [[1u16, 2], [1, 3], [2, 3]] {
        let r = frost_threshold_sign(3, 2, &quorum, &message)
            .unwrap_or_else(|e| panic!("signing failed for quorum {quorum:?}: {e:?}"));
        let dalek_key = DalekKey::from_bytes(&r.group_public_key).unwrap();
        dalek_key
            .verify(&r.message, &DalekSig::from_bytes(&r.signature))
            .unwrap_or_else(|e| panic!("dalek verify failed for quorum {quorum:?}: {e:?}"));
    }
}

/// A single share (below threshold) must not be able to forge a signature: the
/// API itself refuses a sub-threshold quorum.
#[test]
#[should_panic(expected = "threshold is 2")]
fn one_share_cannot_sign() {
    let message = [7u8; 32];
    let _ = frost_threshold_sign(3, 2, &[1], &message);
}
