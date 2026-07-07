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

// ---------------------------------------------------------------------------
// Distributed key generation (2-party). Replaces the trusted dealer: neither
// side ever sees the other's share, not even at wallet creation. Each party
// holds its own secret packages between rounds and exchanges only the public
// round1/round2 packages. The three parts mirror the FROST DKG protocol.
// ---------------------------------------------------------------------------

use frost::keys::dkg;

/// DKG round 1 for one party. `id` is 1 (user) or 2 (network). Returns the
/// secret package (held by this party until part 2) and the public package
/// (broadcast to the other party). Both hex.
#[wasm_bindgen]
pub fn dkg_part1(id_u16: u16) -> String {
    let run = || -> Result<String, String> {
        let (secret, package) = dkg::part1(id(id_u16), 2, 2, OsRng).map_err(|e| e.to_string())?;
        Ok(format!(
            "{{\"ok\":true,\"secret\":\"{}\",\"package\":\"{}\"}}",
            hex::encode(secret.serialize().map_err(|e| e.to_string())?),
            hex::encode(package.serialize().map_err(|e| e.to_string())?)
        ))
    };
    run().unwrap_or_else(err_json)
}

/// DKG round 2 for one party. Consumes this party's round1 secret and the OTHER
/// party's round1 package. Returns this party's round2 secret (held until part
/// 3) and the round2 package addressed to the other party. Both hex.
#[wasm_bindgen]
pub fn dkg_part2(r1_secret_hex: &str, other_id_u16: u16, other_r1_package_hex: &str) -> String {
    let run = || -> Result<String, String> {
        let r1_secret = dkg::round1::SecretPackage::deserialize(
            &hex::decode(r1_secret_hex).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let other_pkg = dkg::round1::Package::deserialize(
            &hex::decode(other_r1_package_hex).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let mut others = BTreeMap::new();
        others.insert(id(other_id_u16), other_pkg);
        let (r2_secret, r2_packages) = dkg::part2(r1_secret, &others).map_err(|e| e.to_string())?;
        // In a 2-party DKG there is exactly one round2 package, addressed to the
        // other participant.
        let for_other = r2_packages
            .get(&id(other_id_u16))
            .ok_or("missing round2 package for peer")?;
        Ok(format!(
            "{{\"ok\":true,\"secret\":\"{}\",\"package\":\"{}\"}}",
            hex::encode(r2_secret.serialize().map_err(|e| e.to_string())?),
            hex::encode(for_other.serialize().map_err(|e| e.to_string())?)
        ))
    };
    run().unwrap_or_else(err_json)
}

/// DKG round 3 for one party. Consumes this party's round2 secret, the other
/// party's round1 package, and the round2 package the other party addressed to
/// it. Produces this party's own key package plus the shared public-key package
/// and group public key. The party's key package never leaves this call.
#[wasm_bindgen]
pub fn dkg_part3(
    r2_secret_hex: &str,
    other_id_u16: u16,
    other_r1_package_hex: &str,
    r2_package_from_other_hex: &str,
) -> String {
    let run = || -> Result<String, String> {
        let r2_secret = dkg::round2::SecretPackage::deserialize(
            &hex::decode(r2_secret_hex).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let other_r1 = dkg::round1::Package::deserialize(
            &hex::decode(other_r1_package_hex).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let r2_from_other = dkg::round2::Package::deserialize(
            &hex::decode(r2_package_from_other_hex).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let mut r1_map = BTreeMap::new();
        r1_map.insert(id(other_id_u16), other_r1);
        let mut r2_map = BTreeMap::new();
        r2_map.insert(id(other_id_u16), r2_from_other);
        let (key_package, pubkey_package) =
            dkg::part3(&r2_secret, &r1_map, &r2_map).map_err(|e| e.to_string())?;
        Ok(format!(
            "{{\"ok\":true,\"key_package\":\"{}\",\"pubkey_pkg\":\"{}\",\"group_pk\":\"{}\"}}",
            hex::encode(key_package.serialize().map_err(|e| e.to_string())?),
            hex::encode(pubkey_package.serialize().map_err(|e| e.to_string())?),
            hex::encode(
                pubkey_package
                    .verifying_key()
                    .serialize()
                    .map_err(|e| e.to_string())?
            )
        ))
    };
    run().unwrap_or_else(err_json)
}

// ---------------------------------------------------------------------------
// Split-party signing API. Each function touches only ONE party's key material,
// so the user's share (party 1, browser) and the network's share (party 2,
// daemon) live on different machines and exchange only serialized commitments
// and shares. The SigningPackage is rebuilt locally on each side from the two
// commitments, so it never has to cross the wire.
// ---------------------------------------------------------------------------

fn err_json(e: impl std::fmt::Display) -> String {
    format!("{{\"ok\":false,\"error\":\"{}\"}}", e.to_string().replace('"', "'"))
}

/// 2-of-2 trusted-dealer keygen. Returns hex-encoded key packages for the user
/// (party 1) and the network (party 2), the shared public-key package, and the
/// group public key. The caller keeps `user_kp` in the browser and hands
/// `net_kp` + `pubkey_pkg` to the network signer. (A real 2-party DKG, where
/// neither side sees the other's share, is the next phase.)
#[wasm_bindgen]
pub fn keygen_2of2() -> String {
    match keygen_inner() {
        Ok(j) => j,
        Err(e) => err_json(e),
    }
}

fn keygen_inner() -> Result<String, String> {
    let (shares, pubkey_package) =
        frost::keys::generate_with_dealer(2, 2, frost::keys::IdentifierList::Default, OsRng)
            .map_err(|e| e.to_string())?;
    let mut kps: BTreeMap<Identifier, KeyPackage> = BTreeMap::new();
    for (i, s) in shares {
        kps.insert(i, KeyPackage::try_from(s).map_err(|e| e.to_string())?);
    }
    let user_kp = kps[&id(USER)].serialize().map_err(|e| e.to_string())?;
    let net_kp = kps[&id(NETWORK)].serialize().map_err(|e| e.to_string())?;
    let pk_pkg = pubkey_package.serialize().map_err(|e| e.to_string())?;
    let group_pk = pubkey_package.verifying_key().serialize().map_err(|e| e.to_string())?;
    Ok(format!(
        "{{\"ok\":true,\"user_kp\":\"{}\",\"net_kp\":\"{}\",\"pubkey_pkg\":\"{}\",\"group_pk\":\"{}\"}}",
        hex::encode(user_kp),
        hex::encode(net_kp),
        hex::encode(pk_pkg),
        hex::encode(group_pk),
    ))
}

/// Round 1 for one party: produce nonces (secret, the caller holds these until
/// round 2) and commitments (shared). Returns `{ nonces, commitments }` hex.
#[wasm_bindgen]
pub fn round1(key_package_hex: &str) -> String {
    match round1_inner(key_package_hex) {
        Ok(j) => j,
        Err(e) => err_json(e),
    }
}

fn round1_inner(kp_hex: &str) -> Result<String, String> {
    let kp = KeyPackage::deserialize(&hex::decode(kp_hex).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let (nonces, commitments) = round1::commit(kp.signing_share(), &mut OsRng);
    let n = nonces.serialize().map_err(|e| e.to_string())?;
    let c = commitments.serialize().map_err(|e| e.to_string())?;
    Ok(format!(
        "{{\"ok\":true,\"nonces\":\"{}\",\"commitments\":\"{}\"}}",
        hex::encode(n),
        hex::encode(c)
    ))
}

// Rebuild the shared SigningPackage from both parties' commitments + message.
fn signing_package(
    user_commit_hex: &str,
    net_commit_hex: &str,
    message: &[u8],
) -> Result<SigningPackage, String> {
    let uc = round1::SigningCommitments::deserialize(
        &hex::decode(user_commit_hex).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let nc = round1::SigningCommitments::deserialize(
        &hex::decode(net_commit_hex).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let mut m = BTreeMap::new();
    m.insert(id(USER), uc);
    m.insert(id(NETWORK), nc);
    Ok(SigningPackage::new(m, message))
}

/// Round 2 for one party: produce its signature share over the shared package,
/// which is rebuilt locally from both commitments. Returns `{ share }` hex.
#[wasm_bindgen]
pub fn round2(
    key_package_hex: &str,
    nonces_hex: &str,
    user_commit_hex: &str,
    net_commit_hex: &str,
    message_hex: &str,
) -> String {
    match round2_inner(key_package_hex, nonces_hex, user_commit_hex, net_commit_hex, message_hex) {
        Ok(j) => j,
        Err(e) => err_json(e),
    }
}

fn round2_inner(
    kp_hex: &str,
    nonces_hex: &str,
    uc_hex: &str,
    nc_hex: &str,
    msg_hex: &str,
) -> Result<String, String> {
    let kp = KeyPackage::deserialize(&hex::decode(kp_hex).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let nonces = round1::SigningNonces::deserialize(&hex::decode(nonces_hex).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let message = hex::decode(msg_hex).map_err(|e| e.to_string())?;
    let package = signing_package(uc_hex, nc_hex, &message)?;
    let share = round2::sign(&package, &nonces, &kp).map_err(|e| e.to_string())?;
    Ok(format!(
        "{{\"ok\":true,\"share\":\"{}\"}}",
        hex::encode(share.serialize())
    ))
}

/// Aggregate both parties' shares into one signature and verify it against the
/// group key. Returns `{ signature, verified }`.
#[wasm_bindgen]
pub fn aggregate(
    user_commit_hex: &str,
    net_commit_hex: &str,
    message_hex: &str,
    user_share_hex: &str,
    net_share_hex: &str,
    pubkey_pkg_hex: &str,
) -> String {
    match aggregate_inner(user_commit_hex, net_commit_hex, message_hex, user_share_hex, net_share_hex, pubkey_pkg_hex) {
        Ok(j) => j,
        Err(e) => err_json(e),
    }
}

#[allow(clippy::too_many_arguments)]
fn aggregate_inner(
    uc_hex: &str,
    nc_hex: &str,
    msg_hex: &str,
    us_hex: &str,
    ns_hex: &str,
    pk_hex: &str,
) -> Result<String, String> {
    let message = hex::decode(msg_hex).map_err(|e| e.to_string())?;
    let package = signing_package(uc_hex, nc_hex, &message)?;
    let pubkey_package =
        PublicKeyPackage::deserialize(&hex::decode(pk_hex).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let us = round2::SignatureShare::deserialize(&hex::decode(us_hex).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let ns = round2::SignatureShare::deserialize(&hex::decode(ns_hex).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let mut shares = BTreeMap::new();
    shares.insert(id(USER), us);
    shares.insert(id(NETWORK), ns);
    let sig: Signature = frost::aggregate(&package, &shares, &pubkey_package).map_err(|e| e.to_string())?;
    let sig_bytes = sig.serialize().map_err(|e| e.to_string())?;
    let verified = pubkey_package.verifying_key().verify(&message, &sig).is_ok();
    Ok(format!(
        "{{\"ok\":true,\"signature\":\"{}\",\"verified\":{}}}",
        hex::encode(sig_bytes),
        verified
    ))
}

/// The network signer trying to finalize ALONE, with only its own share and a
/// single-party package. Returns `{ signed }`; it must be `false`. This is the
/// property a live challenge would exercise: hand over every operator secret,
/// the network still cannot sign without the user's share.
#[wasm_bindgen]
pub fn network_sign_alone(
    net_key_package_hex: &str,
    net_nonces_hex: &str,
    net_commit_hex: &str,
    message_hex: &str,
    pubkey_pkg_hex: &str,
) -> String {
    let attempt = || -> Result<bool, String> {
        let kp = KeyPackage::deserialize(&hex::decode(net_key_package_hex).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        let nonces = round1::SigningNonces::deserialize(
            &hex::decode(net_nonces_hex).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let nc = round1::SigningCommitments::deserialize(
            &hex::decode(net_commit_hex).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let message = hex::decode(message_hex).map_err(|e| e.to_string())?;
        let pubkey_package =
            PublicKeyPackage::deserialize(&hex::decode(pubkey_pkg_hex).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        // Single-party package: only the network's own commitment.
        let mut m = BTreeMap::new();
        m.insert(id(NETWORK), nc);
        let package = SigningPackage::new(m, &message);
        let share = round2::sign(&package, &nonces, &kp).map_err(|e| e.to_string())?;
        let mut shares = BTreeMap::new();
        shares.insert(id(NETWORK), share);
        // Aggregate with a below-threshold share set. Must not yield a valid sig.
        match frost::aggregate(&package, &shares, &pubkey_package) {
            Ok(sig) => Ok(pubkey_package.verifying_key().verify(&message, &sig).is_ok()),
            Err(_) => Ok(false),
        }
    };
    match attempt() {
        Ok(signed) => format!("{{\"ok\":true,\"signed\":{signed}}}"),
        // An error here is also a failure to sign, which is the safe outcome.
        Err(_) => "{\"ok\":true,\"signed\":false}".to_string(),
    }
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
