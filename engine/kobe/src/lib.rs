//! kobe — Distin's off-chain MPC threshold signer.
//!
//! This crate is the real cryptographic engine behind the `=== ... point ===`
//! stubs in the on-chain program (`engine/programs/distin/src/lib.rs`):
//!
//! - `verify_partial_share` (lib.rs:454/599): on-chain checks only the
//!   *structural* invariants of a share; the cryptographic validity of each
//!   signer's partial lives here.
//! - `aggregate_and_emit` (lib.rs:524): the on-chain accumulator is a
//!   deterministic byte-fold placeholder; the *canonical* FROST group-combine
//!   that yields a broadcastable signature is [`frost_threshold_sign`] below.
//!
//! ## Milestone 1 (this file)
//! 2-of-3 **FROST Ed25519** for the SVM / Cosmos branch
//! ([`SignatureScheme::FrostEd25519`] in the on-chain `state.rs`). We do NOT
//! roll our own crypto: keygen, per-signer round 1/2, and the group aggregate
//! all run through the **audited ZF `frost-ed25519` 3.0** crate. The output is
//! a standard RFC 8032 / RFC 9591 Ed25519 signature over the group public key —
//! exactly what an SVM or Cosmos chain verifies natively.
//!
//! Not in this milestone (later, see crate README / report): secp256k1
//! threshold-ECDSA (GG20) for the EVM/BTC/Tron branch, a real operator network
//! (this simulates the N parties in-process), per-chain address derivation, and
//! wiring the partials to the on-chain `submit_partial_signature` accounts.

use std::collections::BTreeMap;

/// C ABI over the audited FROST crate for the networked operator path
/// (M11-Part-2 / F1). The hardened Go transport (mTLS/PKI/encrypted shares,
/// `engine/kobe-ecdsa/net`) drives these from separate operator processes.
pub mod ffi;

use frost_ed25519 as frost;
use frost::{
    keys::{KeyPackage, PublicKeyPackage},
    round1, round2, Identifier, Signature, SigningPackage,
};
use rand::rngs::OsRng;

/// Outcome of one threshold-signing run: the group public key, the message that
/// was signed, the aggregate signature, and the bookkeeping a caller needs.
pub struct ThresholdSignature {
    /// 32-byte compressed Ed25519 group public key (what the target chain holds).
    pub group_public_key: [u8; 32],
    /// The 32-byte message that was signed.
    pub message: [u8; 32],
    /// 64-byte aggregate signature: `R || s`. A standard Ed25519 signature.
    pub signature: [u8; 64],
    /// Which signer identifiers actually contributed (the active quorum).
    pub signers: Vec<u16>,
}

/// A persistent FROST key set: the per-operator key packages and the shared
/// public-key package, produced once by trusted-dealer keygen and reused across
/// many signing ceremonies (mirrors operators holding long-term shares behind a
/// single registered group public key).
pub struct KeySet {
    key_packages: BTreeMap<Identifier, KeyPackage>,
    pubkey_package: PublicKeyPackage,
    max_signers: u16,
    min_signers: u16,
}

impl KeySet {
    /// Trusted-dealer keygen: split a fresh group key into `max_signers` shares
    /// with a `min_signers` threshold. Returns the long-term key material the
    /// simulated operators hold; the group public key is what gets registered
    /// on-chain and what the destination chain verifies against.
    pub fn generate(max_signers: u16, min_signers: u16) -> Result<Self, frost::Error> {
        let mut rng = OsRng;
        let (secret_shares, pubkey_package) = frost::keys::generate_with_dealer(
            max_signers,
            min_signers,
            frost::keys::IdentifierList::Default,
            rng,
        )?;
        let mut key_packages = BTreeMap::new();
        for (id, secret_share) in secret_shares {
            key_packages.insert(id, KeyPackage::try_from(secret_share)?);
        }
        Ok(Self {
            key_packages,
            pubkey_package,
            max_signers,
            min_signers,
        })
    }

    /// 32-byte compressed Ed25519 group public key (registered on-chain).
    pub fn group_public_key(&self) -> Result<[u8; 32], frost::Error> {
        let bytes = self.pubkey_package.verifying_key().serialize()?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    /// Run FROST round 1 (nonce commitments) and round 2 (signature shares) over
    /// `message` with the given quorum, then aggregate into ONE Ed25519
    /// signature. The group key is fixed (the registered one) across calls.
    pub fn threshold_sign(
        &self,
        signing_indices: &[u16],
        message: &[u8; 32],
    ) -> Result<ThresholdSignature, frost::Error> {
        assert!(
            signing_indices.len() >= self.min_signers as usize,
            "quorum of {} given, threshold is {}",
            signing_indices.len(),
            self.min_signers
        );
        let mut rng = OsRng;

        let quorum: Vec<Identifier> = signing_indices
            .iter()
            .map(|i| Identifier::try_from(*i))
            .collect::<Result<_, _>>()?;

        // Round 1: each signer in the quorum produces nonces + commitments.
        let mut nonces_map: BTreeMap<Identifier, round1::SigningNonces> = BTreeMap::new();
        let mut commitments_map: BTreeMap<Identifier, round1::SigningCommitments> = BTreeMap::new();
        for id in &quorum {
            let key_package = &self.key_packages[id];
            let (nonces, commitments) = round1::commit(key_package.signing_share(), &mut rng);
            nonces_map.insert(*id, nonces);
            commitments_map.insert(*id, commitments);
        }

        let signing_package = SigningPackage::new(commitments_map, message);

        // Round 2: each signer produces its signature share over the package.
        let mut signature_shares: BTreeMap<Identifier, round2::SignatureShare> = BTreeMap::new();
        for id in &quorum {
            let key_package = &self.key_packages[id];
            let nonces = &nonces_map[id];
            let share = round2::sign(&signing_package, nonces, key_package)?;
            signature_shares.insert(*id, share);
        }

        // Aggregate: combine the shares into ONE signature (also verifies).
        let group_signature: Signature =
            frost::aggregate(&signing_package, &signature_shares, &self.pubkey_package)?;

        let group_public_key = self.group_public_key()?;
        let sig_bytes = group_signature.serialize()?;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&sig_bytes);

        Ok(ThresholdSignature {
            group_public_key,
            message: *message,
            signature,
            signers: signing_indices.to_vec(),
        })
    }

    /// Threshold-sign an arbitrary-length message. FROST Ed25519 signs the raw
    /// bytes (as Aptos/Solana ed25519 verification expects) rather than a
    /// pre-hashed 32-byte digest, so this is what a real chain signing message
    /// needs. Returns the 64-byte group signature; the group key is never
    /// assembled in one place.
    pub fn threshold_sign_bytes(
        &self,
        signing_indices: &[u16],
        message: &[u8],
    ) -> Result<[u8; 64], frost::Error> {
        assert!(
            signing_indices.len() >= self.min_signers as usize,
            "quorum of {} given, threshold is {}",
            signing_indices.len(),
            self.min_signers
        );
        let mut rng = OsRng;
        let quorum: Vec<Identifier> = signing_indices
            .iter()
            .map(|i| Identifier::try_from(*i))
            .collect::<Result<_, _>>()?;

        let mut nonces_map: BTreeMap<Identifier, round1::SigningNonces> = BTreeMap::new();
        let mut commitments_map: BTreeMap<Identifier, round1::SigningCommitments> = BTreeMap::new();
        for id in &quorum {
            let (nonces, commitments) = round1::commit(self.key_packages[id].signing_share(), &mut rng);
            nonces_map.insert(*id, nonces);
            commitments_map.insert(*id, commitments);
        }

        let signing_package = SigningPackage::new(commitments_map, message);
        let mut signature_shares: BTreeMap<Identifier, round2::SignatureShare> = BTreeMap::new();
        for id in &quorum {
            let share = round2::sign(&signing_package, &nonces_map[id], &self.key_packages[id])?;
            signature_shares.insert(*id, share);
        }

        let group_signature: Signature =
            frost::aggregate(&signing_package, &signature_shares, &self.pubkey_package)?;
        let sig_bytes = group_signature.serialize()?;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&sig_bytes);
        Ok(signature)
    }

    pub fn max_signers(&self) -> u16 {
        self.max_signers
    }
    pub fn min_signers(&self) -> u16 {
        self.min_signers
    }

    /// Serialize the whole key set (every operator's `KeyPackage` + the shared
    /// `PublicKeyPackage`) to bytes so a long-running signer can persist the ONE
    /// group key it registered on-chain and reuse it across restarts. Without
    /// this the daemon would keygen afresh every boot and its aggregate would not
    /// verify against the registered group public key.
    pub fn to_bytes(&self) -> Result<Vec<u8>, frost::Error> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.max_signers.to_le_bytes());
        out.extend_from_slice(&self.min_signers.to_le_bytes());
        let pk = self.pubkey_package.serialize()?;
        out.extend_from_slice(&(pk.len() as u32).to_le_bytes());
        out.extend_from_slice(&pk);
        // KeyPackages are stored in identifier order 1..=max_signers, so the
        // identifier itself never needs to be persisted (Default IdentifierList).
        for i in 1..=self.max_signers {
            let id = Identifier::try_from(i)?;
            let kp = self.key_packages[&id].serialize()?;
            out.extend_from_slice(&(kp.len() as u32).to_le_bytes());
            out.extend_from_slice(&kp);
        }
        Ok(out)
    }

    /// Reconstruct a key set previously produced by [`KeySet::to_bytes`].
    /// Fails closed: a truncated or malformed buffer returns `Err` — key
    /// material parsing must never panic or accept a partial set.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, frost::Error> {
        fn rd<'a>(b: &'a [u8], o: &mut usize, n: usize) -> Result<&'a [u8], frost::Error> {
            let end = o.checked_add(n).ok_or(frost::Error::DeserializationError)?;
            let s = b.get(*o..end).ok_or(frost::Error::DeserializationError)?;
            *o = end;
            Ok(s)
        }
        let mut o = 0usize;
        let max_signers = u16::from_le_bytes(rd(buf, &mut o, 2)?.try_into().unwrap());
        let min_signers = u16::from_le_bytes(rd(buf, &mut o, 2)?.try_into().unwrap());
        let pk_len = u32::from_le_bytes(rd(buf, &mut o, 4)?.try_into().unwrap()) as usize;
        let pubkey_package = PublicKeyPackage::deserialize(rd(buf, &mut o, pk_len)?)?;
        let mut key_packages = BTreeMap::new();
        for i in 1..=max_signers {
            let id = Identifier::try_from(i)?;
            let kp_len = u32::from_le_bytes(rd(buf, &mut o, 4)?.try_into().unwrap()) as usize;
            let kp = KeyPackage::deserialize(rd(buf, &mut o, kp_len)?)?;
            key_packages.insert(id, kp);
        }
        Ok(Self {
            key_packages,
            pubkey_package,
            max_signers,
            min_signers,
        })
    }
}

/// Run a full t-of-n FROST Ed25519 threshold-signing ceremony over `message`.
///
/// Trusted-dealer keygen splits a fresh group key into `max_signers` shares with
/// a `min_signers` threshold, then `signing_indices` (a quorum of at least
/// `min_signers`, 1-based) run FROST round 1 (nonce commitments) and round 2
/// (signature shares); the coordinator aggregates them into one Ed25519
/// signature. The signature verifies against the group key under both the FROST
/// verify path and any standard Ed25519 verifier — the threshold key is
/// indistinguishable from an ordinary Ed25519 key to the target chain.
///
/// All crypto is delegated to the audited `frost-ed25519` crate; this function
/// only wires the rounds and moves messages between the simulated parties.
pub fn frost_threshold_sign(
    max_signers: u16,
    min_signers: u16,
    signing_indices: &[u16],
    message: &[u8; 32],
) -> Result<ThresholdSignature, frost::Error> {
    assert!(
        signing_indices.len() >= min_signers as usize,
        "quorum of {} given, threshold is {}",
        signing_indices.len(),
        min_signers
    );
    let mut rng = OsRng;

    // --- Keygen: trusted dealer splits the group key into n shares (t-of-n). ---
    let (secret_shares, pubkey_package): (
        BTreeMap<Identifier, frost::keys::SecretShare>,
        PublicKeyPackage,
    ) = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Default,
        rng,
    )?;

    // Each participant validates its dealt share into a long-term KeyPackage.
    let mut key_packages: BTreeMap<Identifier, KeyPackage> = BTreeMap::new();
    for (id, secret_share) in secret_shares {
        key_packages.insert(id, KeyPackage::try_from(secret_share)?);
    }

    // The signing quorum (a subset of size >= min_signers).
    let quorum: Vec<Identifier> = signing_indices
        .iter()
        .map(|i| Identifier::try_from(*i))
        .collect::<Result<_, _>>()?;

    // --- Round 1: each signer in the quorum produces nonces + commitments. ---
    // Nonces stay secret on the signer; commitments go to the coordinator.
    let mut nonces_map: BTreeMap<Identifier, round1::SigningNonces> = BTreeMap::new();
    let mut commitments_map: BTreeMap<Identifier, round1::SigningCommitments> = BTreeMap::new();
    for id in &quorum {
        let key_package = &key_packages[id];
        let (nonces, commitments) = round1::commit(key_package.signing_share(), &mut rng);
        nonces_map.insert(*id, nonces);
        commitments_map.insert(*id, commitments);
    }

    // The coordinator binds all commitments + the message into a SigningPackage.
    let signing_package = SigningPackage::new(commitments_map, message);

    // --- Round 2: each signer produces its signature share over the package. ---
    let mut signature_shares: BTreeMap<Identifier, round2::SignatureShare> = BTreeMap::new();
    for id in &quorum {
        let key_package = &key_packages[id];
        let nonces = &nonces_map[id];
        let share = round2::sign(&signing_package, nonces, key_package)?;
        signature_shares.insert(*id, share);
    }

    // --- Aggregate: the coordinator combines the shares into ONE signature. ---
    // frost::aggregate already verifies the result against the group key (and,
    // on failure, would surface the misbehaving signer); a clean return here is
    // itself a cryptographic check that the threshold combine is valid.
    let group_signature: Signature =
        frost::aggregate(&signing_package, &signature_shares, &pubkey_package)?;

    // Serialize the group key (32 B) and signature (64 B) into fixed arrays.
    let gpk_bytes = pubkey_package.verifying_key().serialize()?;
    let mut group_public_key = [0u8; 32];
    group_public_key.copy_from_slice(&gpk_bytes);

    let sig_bytes = group_signature.serialize()?;
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&sig_bytes);

    Ok(ThresholdSignature {
        group_public_key,
        message: *message,
        signature,
        signers: signing_indices.to_vec(),
    })
}

/// Verify an aggregate signature against the group key using the **FROST**
/// verify path (the library's own `VerifyingKey::verify`).
///
/// Mirrors the on-chain `aggregate_and_emit` group-combine point: this is the
/// canonical check a relayer would run before publishing the signature.
pub fn frost_verify(
    group_public_key: &[u8; 32],
    message: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), frost::Error> {
    let verifying_key = frost::VerifyingKey::deserialize(group_public_key)?;
    let signature = Signature::deserialize(signature)?;
    verifying_key.verify(message, &signature)
}
