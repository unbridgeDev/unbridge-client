//! Key-share types.
//!
//! A `SecretShare` is the participant's private evaluation of the group
//! signing polynomial at their identifier; it is never combined with other
//! shares. A `VerificationShare` is the public evaluation used by the
//! aggregator to check a partial signature came from the claimed participant
//! without seeing their share.

use ark_bn254::Fr;
use ark_ff::Zero;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::group::{Participant, GroupPublicKey};

/// A participant's private key share. Zeroed on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretShare {
    #[zeroize(skip)]
    pub participant: Participant,
    pub scalar: Fr,
}

impl SecretShare {
    pub fn new(participant: Participant, scalar: Fr) -> Self {
        Self { participant, scalar }
    }
}

impl std::fmt::Debug for SecretShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretShare")
            .field("participant", &self.participant)
            .field("scalar", &"REDACTED")
            .finish()
    }
}

/// A participant's public verification share, published at DKG completion
/// and used by the signature aggregator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationShare {
    pub participant: Participant,
    pub ax: Fr,
    pub ay: Fr,
}

/// A committed polynomial coefficient published during DKG. The verification
/// commitments carry `t` such coefficients per participant so peers can check
/// a share against the committed polynomial at their own evaluation point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolynomialCommitment {
    pub ax: Fr,
    pub ay: Fr,
}

/// Complete key material returned to a participant at the end of a DKG
/// session: their own share plus the public group key and verification shares
/// of every peer.
#[derive(Debug, Clone)]
pub struct KeyMaterial {
    pub secret_share: SecretShare,
    pub group_public_key: GroupPublicKey,
    pub verification_shares: Vec<VerificationShare>,
}

impl KeyMaterial {
    /// Look up the verification share for a participant by id.
    pub fn verification_share(&self, participant: Participant) -> Option<VerificationShare> {
        self.verification_shares
            .iter()
            .copied()
            .find(|v| v.participant == participant)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_share_debug_redacts_scalar() {
        let s = SecretShare::new(Participant::new(1).unwrap(), Fr::from(42u64));
        let dbg = format!("{s:?}");
        assert!(dbg.contains("REDACTED"), "scalar must be redacted in Debug");
        assert!(!dbg.contains("42"), "raw scalar value must not appear");
    }

    #[test]
    fn key_material_lookup() {
        let vs = vec![
            VerificationShare {
                participant: Participant::new(1).unwrap(),
                ax: Fr::from(1u64),
                ay: Fr::from(2u64),
            },
            VerificationShare {
                participant: Participant::new(2).unwrap(),
                ax: Fr::from(3u64),
                ay: Fr::from(4u64),
            },
        ];
        let km = KeyMaterial {
            secret_share: SecretShare::new(Participant::new(1).unwrap(), Fr::zero()),
            group_public_key: GroupPublicKey {
                ax: Fr::zero(),
                ay: Fr::zero(),
            },
            verification_shares: vs,
        };
        assert!(km
            .verification_share(Participant::new(1).unwrap())
            .is_some());
        assert!(km
            .verification_share(Participant::new(99).unwrap())
            .is_none());
    }
}
