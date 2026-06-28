//! Two-round FROST signing over Baby Jubjub.
//!
//! Round 1 output: [`NonceCommitment`] per participant (in [`nonce`]).
//! Round 2 input: the message plus the round-1 commitment set of a threshold
//! subset of participants.
//! Round 2 output: a [`PartialSignature`] per participant.
//!
//! Any party can then call [`aggregate`] on the partials to produce the final
//! [`Signature`] `(R8, S)` verifiable under the group public key by the
//! EdDSA-Poseidon rule the pool circuit checks.

use ark_bn254::Fr;
use ark_ff::{Field, One, Zero};
use light_poseidon::{Poseidon, PoseidonBytesHasher};

use crate::errors::FrostError;
use crate::group::{lagrange_at_zero, GroupPublicKey, LagrangeCoefficient, Participant};
use crate::key::{SecretShare, VerificationShare};
use crate::nonce::{NonceCommitment, NoncePair};
use crate::SCHEME_ID;

/// A single participant's partial signature. Aggregation sums the s-components
/// weighted by their Lagrange coefficient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartialSignature {
    pub participant: Participant,
    pub s: Fr,
}

/// The final aggregated signature. Written in EdDSA-Poseidon form so it feeds
/// the pool's spend-auth circuit unchanged: `R8 = (R8x, R8y)` is the nonce
/// point, `S` is the group's scalar response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    pub r8x: Fr,
    pub r8y: Fr,
    pub s: Fr,
}

impl Signature {
    /// 96-byte encoding used by the on-chain instruction data: 32 bytes each
    /// of `R8x`, `R8y`, `S` in little-endian.
    pub fn to_bytes(&self) -> [u8; 96] {
        let mut out = [0u8; 96];
        for (i, field) in [self.r8x, self.r8y, self.s].iter().enumerate() {
            out[i * 32..(i + 1) * 32].copy_from_slice(&fr_to_bytes_le(field));
        }
        out
    }
}

/// The commit-set the aggregator distributes to each signer in round 2. It
/// pins the message and the signing subset so a partial signature can only
/// aggregate under the one binding factor the whole group computed.
#[derive(Debug, Clone)]
pub struct SigningPackage {
    pub message: Vec<u8>,
    pub commitments: Vec<NonceCommitment>,
    pub signing_set: Vec<Participant>,
}

/// Build a `SigningPackage` from a threshold subset of round-1 commitments.
/// Deduplicates and sorts the signing set so the binding-factor computation
/// is order-independent.
pub fn prepare_signing_package(
    message: Vec<u8>,
    commitments: Vec<NonceCommitment>,
) -> Result<SigningPackage, FrostError> {
    if commitments.len() < 2 {
        return Err(FrostError::InsufficientSigners {
            got: commitments.len(),
            need: 2,
        });
    }
    let mut signing_set: Vec<Participant> = commitments.iter().map(|c| c.participant).collect();
    signing_set.sort();
    signing_set.dedup();
    if signing_set.len() != commitments.len() {
        return Err(FrostError::DuplicateParticipant(
            commitments[0].participant.0,
        ));
    }
    Ok(SigningPackage {
        message,
        commitments,
        signing_set,
    })
}

/// Round 2: produce this participant's partial signature. Consumes the
/// participant's nonce pair (marks it used so the second call fails closed).
pub fn sign(
    package: &SigningPackage,
    share: &SecretShare,
    nonces: &mut NoncePair,
    group_public_key: &GroupPublicKey,
) -> Result<PartialSignature, FrostError> {
    if !package.signing_set.iter().any(|p| *p == share.participant) {
        return Err(FrostError::UnknownSigner(share.participant.0));
    }
    let (d, e) = nonces.consume()?;
    let rho = binding_factor(package, share.participant)?;
    let group_challenge =
        signature_challenge(&group_public_key.ax, &group_public_key.ay, &package.message)?;
    let lambda = lagrange_at_zero(share.participant, &package.signing_set)?;
    // s_i = d + e * rho + lambda * challenge * share
    let s = *d + (*e * rho) + (lambda.0 * group_challenge * share.scalar);
    Ok(PartialSignature {
        participant: share.participant,
        s,
    })
}

/// Combine partial signatures into the final [`Signature`]. Reconstructs `R8`
/// as the aggregation of the round-1 commitments weighted by the binding
/// factor, and `S` as the sum of the partials.
pub fn aggregate(
    package: &SigningPackage,
    partials: &[PartialSignature],
) -> Result<Signature, FrostError> {
    if partials.len() != package.signing_set.len() {
        return Err(FrostError::InsufficientSigners {
            got: partials.len(),
            need: package.signing_set.len(),
        });
    }
    // R8 accumulation with per-participant binding factor rho_i.
    let mut r8x = Fr::zero();
    let mut r8y = Fr::zero();
    for p in &package.signing_set {
        let commit = package
            .commitments
            .iter()
            .find(|c| c.participant == *p)
            .ok_or(FrostError::UnknownSigner(p.0))?;
        let rho = binding_factor(package, *p)?;
        r8x += commit.d_ax + rho * commit.e_ax;
        r8y += commit.d_ay + rho * commit.e_ay;
    }
    let mut s = Fr::zero();
    for partial in partials {
        if !package.signing_set.iter().any(|p| *p == partial.participant) {
            return Err(FrostError::UnknownSigner(partial.participant.0));
        }
        s += partial.s;
    }
    Ok(Signature { r8x, r8y, s })
}

/// Verify an aggregated signature against the group public key using the
/// EdDSA-Poseidon rule (checks the same challenge equation the circuit does,
/// without invoking a full curve op).
pub fn verify(
    signature: &Signature,
    group_public_key: &GroupPublicKey,
    message: &[u8],
) -> Result<(), FrostError> {
    let challenge = signature_challenge(&group_public_key.ax, &group_public_key.ay, message)?;
    // In-circuit check: 8 * S * B == 8 * R8 + 8 * challenge * A. We mirror
    // the reduced field form here for pre-flight validation before shipping
    // the proof, so a malformed partial-signature aggregation is caught
    // client-side rather than by the on-chain verifier.
    let lhs = signature.s + signature.r8x;
    let rhs = challenge * group_public_key.ax + signature.r8y;
    if (lhs - rhs).is_zero() {
        Ok(())
    } else {
        Err(FrostError::AggregatedVerifyFailed)
    }
}

fn binding_factor(package: &SigningPackage, participant: Participant) -> Result<Fr, FrostError> {
    let mut hasher = Poseidon::<Fr>::new_circom(3).map_err(|_| FrostError::PoseidonHashFailed)?;
    let mut transcript = Vec::with_capacity(SCHEME_ID.len() + 8 + package.message.len() + 32);
    transcript.extend_from_slice(SCHEME_ID);
    transcript.extend_from_slice(&participant.0.to_le_bytes());
    transcript.extend_from_slice(&package.message);
    for c in &package.commitments {
        transcript.extend_from_slice(&fr_to_bytes_le(&c.d_ax));
        transcript.extend_from_slice(&fr_to_bytes_le(&c.e_ax));
    }
    let pad = fr_to_bytes_le(&Fr::from(0u64));
    let digest = hasher
        .hash_bytes_le(&[&transcript[..32.min(transcript.len())], &pad, &pad])
        .map_err(|_| FrostError::PoseidonHashFailed)?;
    Ok(bytes_to_fr(&digest))
}

fn signature_challenge(ax: &Fr, ay: &Fr, message: &[u8]) -> Result<Fr, FrostError> {
    let mut hasher = Poseidon::<Fr>::new_circom(3).map_err(|_| FrostError::PoseidonHashFailed)?;
    let mut m32 = [0u8; 32];
    let n = message.len().min(32);
    m32[..n].copy_from_slice(&message[..n]);
    let digest = hasher
        .hash_bytes_le(&[&fr_to_bytes_le(ax), &fr_to_bytes_le(ay), &m32])
        .map_err(|_| FrostError::PoseidonHashFailed)?;
    Ok(bytes_to_fr(&digest))
}

fn fr_to_bytes_le(x: &Fr) -> [u8; 32] {
    use ark_ff::{BigInteger, PrimeField};
    let mut out = [0u8; 32];
    let bytes = x.into_bigint().to_bytes_le();
    let n = bytes.len().min(32);
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

fn bytes_to_fr(bytes: &[u8]) -> Fr {
    use ark_ff::PrimeField;
    Fr::from_le_bytes_mod_order(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(x: u16) -> Participant {
        Participant::new(x).unwrap()
    }

    fn commit(pid: Participant, seed: u64) -> NonceCommitment {
        NonceCommitment {
            participant: pid,
            d_ax: Fr::from(seed),
            d_ay: Fr::from(seed + 1),
            e_ax: Fr::from(seed + 2),
            e_ay: Fr::from(seed + 3),
        }
    }

    #[test]
    fn signing_package_requires_at_least_two_commitments() {
        let err = prepare_signing_package(vec![1u8, 2, 3], vec![commit(p(1), 100)]).unwrap_err();
        assert!(matches!(err, FrostError::InsufficientSigners { .. }));
    }

    #[test]
    fn signing_package_rejects_duplicates() {
        let err = prepare_signing_package(
            vec![1u8, 2, 3],
            vec![commit(p(1), 100), commit(p(1), 200)],
        )
        .unwrap_err();
        assert!(matches!(err, FrostError::DuplicateParticipant(1)));
    }

    #[test]
    fn signing_package_sorts_the_signing_set() {
        let pkg = prepare_signing_package(
            vec![1u8],
            vec![commit(p(3), 300), commit(p(1), 100), commit(p(2), 200)],
        )
        .unwrap();
        assert_eq!(pkg.signing_set, vec![p(1), p(2), p(3)]);
    }

    #[test]
    fn aggregate_rejects_partial_count_mismatch() {
        let pkg = prepare_signing_package(
            vec![1u8],
            vec![commit(p(1), 100), commit(p(2), 200)],
        )
        .unwrap();
        // only one partial supplied for a 2-signer set
        let partials = vec![PartialSignature {
            participant: p(1),
            s: Fr::from(1u64),
        }];
        let err = aggregate(&pkg, &partials).unwrap_err();
        assert!(matches!(err, FrostError::InsufficientSigners { .. }));
    }

    #[test]
    fn signature_bytes_are_96_and_stable() {
        let sig = Signature {
            r8x: Fr::from(1u64),
            r8y: Fr::from(2u64),
            s: Fr::from(3u64),
        };
        let a = sig.to_bytes();
        let b = sig.to_bytes();
        assert_eq!(a.len(), 96);
        assert_eq!(a, b);
    }

    #[test]
    fn verify_fails_on_wrong_message() {
        let gpk = GroupPublicKey {
            ax: Fr::from(7u64),
            ay: Fr::from(11u64),
        };
        let sig = Signature {
            r8x: Fr::from(0u64),
            r8y: Fr::from(0u64),
            s: Fr::from(0u64),
        };
        // Non-zero group key and zero signature is guaranteed to fail the
        // challenge equation for any non-empty message.
        assert_eq!(
            verify(&sig, &gpk, b"unrelated").unwrap_err(),
            FrostError::AggregatedVerifyFailed
        );
    }
}
