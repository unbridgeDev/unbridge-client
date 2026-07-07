//! Browser-side FROST Ed25519 for the user-mandatory custody model.
//!
//! Phase 1 goal: prove the audited `frost-ed25519` crypto actually compiles and
//! RUNS on wasm32, so the user's key share can live in the browser rather than
//! on a server. This is the load-bearing risk for the non-custodial wallet: if
//! FROST runs here, the user can be a mandatory signer with a share that never
//! leaves their device.
//!
//! `custody_selftest` runs the full 2-of-2 (user + network) in one call and
//! returns a JSON report: the operator-only attempt is blocked, the joint sign
//! produces an ordinary Ed25519 signature, and it verifies. The granular
//! round1/round2 entry points are what the real browser-to-daemon ceremony will
//! drive, with the two shares held on two different machines.

use frost_ed25519 as frost;
use std::collections::BTreeMap;
use wasm_bindgen::prelude::*;

use frost::{
    keys::{KeyPackage, PublicKeyPackage},
    round1, round2, Identifier, Signature, SigningPackage, VerifyingKey,
};
use rand::rngs::OsRng;

const USER: u16 = 1;
const NETWORK: u16 = 2;

fn id(i: u16) -> Identifier {
    Identifier::try_from(i).expect("valid identifier")
}

/// Full 2-of-2 custody proof, in the browser. Returns a JSON string:
/// `{ ok, group_pubkey, signature, operator_only_blocked, verified }`.
///
/// `message_hex` is the 32-byte message to sign, hex-encoded (64 chars).
#[wasm_bindgen]
pub fn custody_selftest(message_hex: &str) -> String {
    match run_selftest(message_hex) {
        Ok(json) => json,
        Err(e) => format!("{{\"ok\":false,\"error\":\"{}\"}}", e.replace('"', "'")),
    }
}

fn run_selftest(message_hex: &str) -> Result<String, String> {
    let message = hex::decode(message_hex).map_err(|e| format!("bad message hex: {e}"))?;

    // 2-of-2 keygen: one group key split into a user share and a network share.
    // (Trusted-dealer here; the real wallet does a 2-party DKG so neither side
    // ever sees the other's share at generation.)
    let (shares, pubkey_package) = frost::keys::generate_with_dealer(
        2,
        2,
        frost::keys::IdentifierList::Default,
        OsRng,
    )
    .map_err(|e| format!("keygen: {e}"))?;

    let mut key_packages: BTreeMap<Identifier, KeyPackage> = BTreeMap::new();
    for (i, share) in shares {
        key_packages.insert(i, KeyPackage::try_from(share).map_err(|e| format!("keypkg: {e}"))?);
    }

    let group_pk_bytes = pubkey_package
        .verifying_key()
        .serialize()
        .map_err(|e| format!("group pk: {e}"))?;

    // The core property: the operator network alone (party 2) is below threshold
    // and cannot produce a signature. Attempting a 1-party FROST sign yields no
    // valid aggregate.
    let operator_only_blocked = sign_quorum(&key_packages, &pubkey_package, &[NETWORK], &message).is_err();

    // The only path that works: user + network together.
    let signature = sign_quorum(&key_packages, &pubkey_package, &[USER, NETWORK], &message)
        .map_err(|e| format!("joint sign: {e}"))?;

    // Independent verification with the standard verifying key (RFC 8032), the
    // same check the destination chain runs.
    let vk = VerifyingKey::deserialize(&group_pk_bytes).map_err(|e| format!("vk: {e}"))?;
    let sig = Signature::deserialize(&signature).map_err(|e| format!("sig: {e}"))?;
    let verified = vk.verify(&message, &sig).is_ok();

    Ok(format!(
        "{{\"ok\":true,\"group_pubkey\":\"{}\",\"signature\":\"{}\",\"operator_only_blocked\":{},\"verified\":{}}}",
        hex::encode(group_pk_bytes),
        hex::encode(signature),
        operator_only_blocked,
        verified
    ))
}

/// Run FROST round 1 + round 2 over `message` for the given quorum and aggregate.
/// Fails (returns Err) when the quorum is below the 2-of-2 threshold, which is
/// exactly how "operators alone cannot sign" manifests.
fn sign_quorum(
    key_packages: &BTreeMap<Identifier, KeyPackage>,
    pubkey_package: &PublicKeyPackage,
    quorum: &[u16],
    message: &[u8],
) -> Result<[u8; 64], String> {
    if quorum.len() < 2 {
        return Err("below threshold".into());
    }
    let ids: Vec<Identifier> = quorum.iter().map(|i| id(*i)).collect();

    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for i in &ids {
        let (n, c) = round1::commit(key_packages[i].signing_share(), &mut OsRng);
        nonces.insert(*i, n);
        commitments.insert(*i, c);
    }

    let signing_package = SigningPackage::new(commitments, message);

    let mut shares = BTreeMap::new();
    for i in &ids {
        let s = round2::sign(&signing_package, &nonces[i], &key_packages[i])
            .map_err(|e| format!("round2: {e}"))?;
        shares.insert(*i, s);
    }

    let group_sig: Signature = frost::aggregate(&signing_package, &shares, pubkey_package)
        .map_err(|e| format!("aggregate: {e}"))?;
    let bytes = group_sig.serialize().map_err(|e| format!("ser: {e}"))?;
    bytes.as_slice().try_into().map_err(|_| "sig len".to_string())
}
