//! Group public key, participant identifiers, and Lagrange interpolation over
//! the Baby Jubjub scalar field.
//!
//! Participants are identified by non-zero `u16` values. Every signing session
//! reconstructs the group signing key implicitly by summing Lagrange-weighted
//! partial signatures over the signing set; the group public key stays fixed
//! across sessions and is what the on-chain circuit checks.

use ark_bn254::Fr;
use ark_ff::{Field, One, Zero};
use ark_serialize::CanonicalSerialize;

use crate::errors::FrostError;

/// A participant identifier. Non-zero because zero is the interpolation
/// evaluation point and would produce a trivial Lagrange coefficient.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Participant(pub u16);

impl Participant {
    pub fn new(id: u16) -> Result<Self, FrostError> {
        if id == 0 {
            return Err(FrostError::ZeroParticipantId);
        }
        Ok(Participant(id))
    }

    pub fn as_field(&self) -> Fr {
        Fr::from(self.0 as u64)
    }
}

/// The 32-byte encoding of the group public key (an EdDSA-Poseidon point on
/// Baby Jubjub). The concrete curve arithmetic is delegated to the circuit;
/// this crate carries the affine coordinates as opaque field elements so the
/// signing protocol works without pulling a full Baby Jubjub implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupPublicKey {
    pub ax: Fr,
    pub ay: Fr,
}

impl GroupPublicKey {
    /// Compressed 64-byte serialization used by the on-chain instruction data.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        let mut lo = Vec::with_capacity(32);
        self.ax
            .serialize_compressed(&mut lo)
            .expect("Fr serialization is infallible");
        out[..32].copy_from_slice(&lo);
        let mut hi = Vec::with_capacity(32);
        self.ay
            .serialize_compressed(&mut hi)
            .expect("Fr serialization is infallible");
        out[32..].copy_from_slice(&hi);
        out
    }
}

/// A Lagrange coefficient `lambda_i` for participant `i` over the signing set.
/// Used at signing time to weight each participant's partial signature so the
/// aggregate reconstructs the group secret in the exponent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LagrangeCoefficient(pub Fr);

/// Compute the Lagrange coefficient at point 0 for participant `target` over
/// the given signing set. Returns `Err(UnknownSigner)` if `target` is not in
/// `signing_set`.
///
/// `lambda_target(0) = product_{j != target, j in S}  j / (j - target)`
pub fn lagrange_at_zero(
    target: Participant,
    signing_set: &[Participant],
) -> Result<LagrangeCoefficient, FrostError> {
    if !signing_set.iter().any(|p| *p == target) {
        return Err(FrostError::UnknownSigner(target.0));
    }
    let mut numerator = Fr::one();
    let mut denominator = Fr::one();
    let t = target.as_field();
    for j in signing_set {
        if *j == target {
            continue;
        }
        let jf = j.as_field();
        numerator *= jf;
        denominator *= jf - t;
    }
    let inv = denominator
        .inverse()
        .ok_or(FrostError::InvalidPartial(target.0))?;
    Ok(LagrangeCoefficient(numerator * inv))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(x: u16) -> Participant {
        Participant::new(x).unwrap()
    }

    #[test]
    fn zero_participant_rejected() {
        assert_eq!(Participant::new(0).unwrap_err(), FrostError::ZeroParticipantId);
    }

    #[test]
    fn lagrange_at_singleton_is_one() {
        let l = lagrange_at_zero(p(1), &[p(1)]).unwrap();
        assert_eq!(l.0, Fr::one(), "singleton signing set: lambda = 1");
    }

    #[test]
    fn lagrange_sum_at_zero_is_one() {
        let set = vec![p(1), p(2), p(3)];
        let sum: Fr = set
            .iter()
            .map(|s| lagrange_at_zero(*s, &set).unwrap().0)
            .sum();
        assert_eq!(sum, Fr::one(), "sum of lagrange coefficients at 0 must equal 1");
    }

    #[test]
    fn lagrange_unknown_signer_rejected() {
        let err = lagrange_at_zero(p(9), &[p(1), p(2)]).unwrap_err();
        assert_eq!(err, FrostError::UnknownSigner(9));
    }

    #[test]
    fn group_pubkey_serializes_deterministically() {
        let g = GroupPublicKey {
            ax: Fr::from(42u64),
            ay: Fr::from(1337u64),
        };
        let a = g.to_bytes();
        let b = g.to_bytes();
        assert_eq!(a, b, "serialization must be deterministic");
        assert_eq!(a.len(), 64);
    }
}
