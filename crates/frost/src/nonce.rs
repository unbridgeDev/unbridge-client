//! Nonce pairs for FROST round 1.
//!
//! Each session, every participant draws two fresh scalars `(d, e)` and
//! publishes their curve commitments `(D, E)`. The signing binding factor
//! `rho_i = H(SCHEME_ID | i | message | commitment_set)` is then computed
//! deterministically by every party so no interactive round is needed to
//! agree on it. Nonces must be used exactly once; reuse across sessions is a
//! fatal security bug that leaks the participant's share.

use ark_bn254::Fr;
use ark_ff::UniformRand;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::FrostError;
use crate::group::Participant;

/// A committed nonce pair `(D, E)` published in round 1. The corresponding
/// secret nonces `(d, e)` are held by the participant until round 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonceCommitment {
    pub participant: Participant,
    pub d_ax: Fr,
    pub d_ay: Fr,
    pub e_ax: Fr,
    pub e_ay: Fr,
}

/// A participant's secret nonces. Zeroed on drop and marked used after
/// round 2 so the participant panics if they try to sign again with the same
/// pair.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct NoncePair {
    pub d: Fr,
    pub e: Fr,
    #[zeroize(skip)]
    used: bool,
}

impl NoncePair {
    pub fn fresh<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self {
            d: Fr::rand(rng),
            e: Fr::rand(rng),
            used: false,
        }
    }

    /// Mark the pair used and return `Err(NonceReused)` if it was used before.
    pub fn consume(&mut self) -> Result<(&Fr, &Fr), FrostError> {
        if self.used {
            return Err(FrostError::NonceReused);
        }
        self.used = true;
        Ok((&self.d, &self.e))
    }
}

impl std::fmt::Debug for NoncePair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoncePair")
            .field("d", &"REDACTED")
            .field("e", &"REDACTED")
            .field("used", &self.used)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn fresh_pair_not_yet_used() {
        let n = NoncePair::fresh(&mut OsRng);
        assert!(!n.used);
    }

    #[test]
    fn consume_marks_used_and_second_call_fails() {
        let mut n = NoncePair::fresh(&mut OsRng);
        assert!(n.consume().is_ok());
        assert_eq!(n.consume().unwrap_err(), FrostError::NonceReused);
    }

    #[test]
    fn debug_redacts_scalars() {
        let n = NoncePair::fresh(&mut OsRng);
        let dbg = format!("{n:?}");
        assert!(dbg.contains("REDACTED"));
    }

    #[test]
    fn two_fresh_pairs_differ() {
        let a = NoncePair::fresh(&mut OsRng);
        let b = NoncePair::fresh(&mut OsRng);
        assert_ne!(a.d, b.d);
        assert_ne!(a.e, b.e);
    }
}
