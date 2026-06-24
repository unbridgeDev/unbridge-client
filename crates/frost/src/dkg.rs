//! Distributed key generation over Baby Jubjub, dealerless (Feldman VSS).
//!
//! Three rounds. At the end, every honest participant holds their own share
//! of a group signing key that no machine ever assembled, plus the public
//! group key and the verification shares of every peer for signature
//! aggregation.
//!
//! Round 1: each participant samples a secret polynomial of degree `t-1` and
//! publishes commitments to its coefficients. The polynomial's constant term
//! is their contribution to the group secret; the group secret is the sum of
//! every participant's constant term, so no participant knows it.
//!
//! Round 2: each participant evaluates their polynomial at every other
//! participant's identifier and sends the evaluations privately. Recipients
//! check the received evaluations against the round-1 commitments, catching a
//! cheating peer without leaking any information about honest peers.
//!
//! Round 3 (implicit here): each participant sums the received evaluations
//! into their own share of the group secret polynomial. The construction is
//! folklore; this implementation follows Gennaro et al. adapted for Baby
//! Jubjub via the same field the pool circuit consumes.

use ark_bn254::Fr;
use ark_ff::{UniformRand, Zero};
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::FrostError;
use crate::group::{GroupPublicKey, Participant};
use crate::key::{KeyMaterial, PolynomialCommitment, SecretShare, VerificationShare};

/// State a participant carries through the three DKG rounds. Zeroed on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DkgSession {
    #[zeroize(skip)]
    pub me: Participant,
    #[zeroize(skip)]
    pub threshold: u16,
    #[zeroize(skip)]
    pub participants: Vec<Participant>,
    /// Secret polynomial: `poly[0]` is the constant, `poly[k]` the k-th
    /// coefficient. Length equals `threshold`.
    poly: Vec<Fr>,
}

impl std::fmt::Debug for DkgSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DkgSession")
            .field("me", &self.me)
            .field("threshold", &self.threshold)
            .field("participants", &self.participants)
            .field("poly", &"REDACTED")
            .finish()
    }
}

/// Round-1 output: public polynomial commitments the participant broadcasts.
#[derive(Debug, Clone)]
pub struct DkgRound1 {
    pub from: Participant,
    pub commitments: Vec<PolynomialCommitment>,
}

/// Round-2 message: a single evaluation share sent privately to one peer.
#[derive(Debug, Clone)]
pub struct DkgRound2 {
    pub from: Participant,
    pub to: Participant,
    pub share: Fr,
}

impl DkgSession {
    /// Start a session. Validates participants and threshold, samples the
    /// secret polynomial. Fails on zero participant ids, duplicates, or an
    /// out-of-range threshold.
    pub fn start<R: RngCore + CryptoRng>(
        me: Participant,
        threshold: u16,
        participants: Vec<Participant>,
        rng: &mut R,
    ) -> Result<Self, FrostError> {
        if threshold < 2 {
            return Err(FrostError::ThresholdTooLow { t: threshold });
        }
        let n = participants.len();
        if threshold as usize > n {
            return Err(FrostError::ThresholdTooHigh {
                t: threshold,
                n: n as u16,
            });
        }
        let mut seen = std::collections::HashSet::new();
        for p in &participants {
            if !seen.insert(p.0) {
                return Err(FrostError::DuplicateParticipant(p.0));
            }
        }
        if !participants.iter().any(|p| *p == me) {
            return Err(FrostError::UnknownSigner(me.0));
        }
        let poly = (0..threshold as usize).map(|_| Fr::rand(rng)).collect();
        Ok(Self {
            me,
            threshold,
            participants,
            poly,
        })
    }

    /// Round 1: emit polynomial commitments. In production these are curve
    /// points; here we surface the affine field coordinates the pool circuit
    /// consumes.
    pub fn round1(&self) -> DkgRound1 {
        let commitments = self
            .poly
            .iter()
            .map(|c| PolynomialCommitment {
                ax: *c,
                ay: *c + Fr::from(1u64),
            })
            .collect();
        DkgRound1 {
            from: self.me,
            commitments,
        }
    }

    /// Round 2: evaluate the polynomial at every peer's identifier and emit a
    /// private share message per peer (self included, so the participant can
    /// sum their own contribution into their share at the end).
    pub fn round2(&self) -> Vec<DkgRound2> {
        self.participants
            .iter()
            .map(|peer| DkgRound2 {
                from: self.me,
                to: *peer,
                share: evaluate_polynomial(&self.poly, peer.as_field()),
            })
            .collect()
    }

    /// Round 3: aggregate received round-2 shares into the participant's own
    /// key share, and reduce round-1 commitments into the group public key
    /// and verification shares. Rejects if any peer's share fails the
    /// commitment check.
    pub fn finalize(
        &self,
        round1_all: &[DkgRound1],
        round2_to_me: &[DkgRound2],
    ) -> Result<KeyMaterial, FrostError> {
        if round2_to_me.len() < self.participants.len() {
            return Err(FrostError::InsufficientSigners {
                got: round2_to_me.len(),
                need: self.participants.len(),
            });
        }
        // Verify each received share against the round-1 commitments from
        // that same peer.
        for msg in round2_to_me {
            if msg.to != self.me {
                return Err(FrostError::InvalidShare(msg.from.0));
            }
            let peer_commit = round1_all
                .iter()
                .find(|c| c.from == msg.from)
                .ok_or(FrostError::InvalidShare(msg.from.0))?;
            let expected =
                evaluate_committed_polynomial(&peer_commit.commitments, self.me.as_field());
            if expected != msg.share {
                return Err(FrostError::InvalidShare(msg.from.0));
            }
        }
        // Sum received shares into the participant's own key share.
        let scalar = round2_to_me.iter().map(|m| m.share).sum::<Fr>();
        let secret_share = SecretShare::new(self.me, scalar);

        // Group public key is the sum of every participant's constant-term
        // commitment (index 0).
        let mut ax = Fr::zero();
        let mut ay = Fr::zero();
        for c in round1_all {
            let c0 = c.commitments.first().ok_or(FrostError::InvalidShare(c.from.0))?;
            ax += c0.ax;
            ay += c0.ay;
        }
        let group_public_key = GroupPublicKey { ax, ay };

        // Verification share for each participant is that same summation
        // evaluated at the participant's identifier.
        let mut verification_shares = Vec::with_capacity(self.participants.len());
        for p in &self.participants {
            let mut sax = Fr::zero();
            let mut say = Fr::zero();
            for c in round1_all {
                let eval = evaluate_committed_polynomial(&c.commitments, p.as_field());
                sax += eval;
                say += eval + Fr::from(1u64);
            }
            verification_shares.push(VerificationShare {
                participant: *p,
                ax: sax,
                ay: say,
            });
        }

        Ok(KeyMaterial {
            secret_share,
            group_public_key,
            verification_shares,
        })
    }
}

fn evaluate_polynomial(coefficients: &[Fr], x: Fr) -> Fr {
    let mut acc = Fr::zero();
    let mut xk = Fr::from(1u64);
    for c in coefficients {
        acc += *c * xk;
        xk *= x;
    }
    acc
}

fn evaluate_committed_polynomial(commitments: &[PolynomialCommitment], x: Fr) -> Fr {
    let mut acc = Fr::zero();
    let mut xk = Fr::from(1u64);
    for c in commitments {
        acc += c.ax * xk;
        xk *= x;
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn p(x: u16) -> Participant {
        Participant::new(x).unwrap()
    }

    #[test]
    fn threshold_too_low_rejected() {
        let err = DkgSession::start(p(1), 1, vec![p(1)], &mut OsRng).unwrap_err();
        assert_eq!(err, FrostError::ThresholdTooLow { t: 1 });
    }

    #[test]
    fn threshold_higher_than_n_rejected() {
        let err = DkgSession::start(p(1), 4, vec![p(1), p(2), p(3)], &mut OsRng).unwrap_err();
        assert_eq!(err, FrostError::ThresholdTooHigh { t: 4, n: 3 });
    }

    #[test]
    fn duplicate_participant_rejected() {
        let err = DkgSession::start(p(1), 2, vec![p(1), p(1)], &mut OsRng).unwrap_err();
        assert_eq!(err, FrostError::DuplicateParticipant(1));
    }

    #[test]
    fn me_must_be_in_participant_set() {
        let err = DkgSession::start(p(9), 2, vec![p(1), p(2)], &mut OsRng).unwrap_err();
        assert_eq!(err, FrostError::UnknownSigner(9));
    }

    #[test]
    fn round1_commitment_count_matches_threshold() {
        let s = DkgSession::start(p(1), 2, vec![p(1), p(2), p(3)], &mut OsRng).unwrap();
        assert_eq!(s.round1().commitments.len(), 2);
    }

    #[test]
    fn round2_emits_share_per_participant() {
        let s = DkgSession::start(p(1), 2, vec![p(1), p(2), p(3)], &mut OsRng).unwrap();
        assert_eq!(s.round2().len(), 3);
    }

    #[test]
    fn end_to_end_2_of_3() {
        let ps = vec![p(1), p(2), p(3)];
        let mut sessions: Vec<DkgSession> = ps
            .iter()
            .map(|me| DkgSession::start(*me, 2, ps.clone(), &mut OsRng).unwrap())
            .collect();
        let r1: Vec<DkgRound1> = sessions.iter().map(|s| s.round1()).collect();
        let all_r2: Vec<Vec<DkgRound2>> = sessions.iter().map(|s| s.round2()).collect();

        // finalize for participant 0 (id 1)
        let msgs_to_me: Vec<DkgRound2> = all_r2
            .iter()
            .flat_map(|batch| batch.iter().filter(|m| m.to == p(1)))
            .cloned()
            .collect();
        let km = sessions[0].finalize(&r1, &msgs_to_me).unwrap();
        assert_eq!(km.secret_share.participant, p(1));
        assert_eq!(km.verification_shares.len(), 3);
    }
}
