//! FROST threshold signing over Baby Jubjub for Unbridge.
//!
//! The circuit in `circuits/pool_tx.circom` verifies an EdDSA-Poseidon
//! signature `(R8, S)` under a Baby Jubjub public key `A = (Ax, Ay)`. This
//! crate produces exactly that signature from `t` of `n` participants without
//! ever reconstructing the group signing key. Two rounds per session:
//!
//! 1. **Commit.** Each participant draws a fresh nonce pair `(d, e)` and
//!    publishes the corresponding commitments `(D, E)`. Nonces are used once
//!    and zeroed after; reuse across sessions leaks the share to any two
//!    signers who observe the reused public commitment.
//! 2. **Sign.** Given the message `M` and the round-1 commitment set from a
//!    threshold subset, each participant computes a Lagrange-weighted partial
//!    signature. Any party can aggregate the partials into `(R8, S)`.
//!
//! Aggregation is public: it needs only the commitments and partials, no
//! private material. Verification uses the standard EdDSA-Poseidon rule so the
//! result plugs into the pool circuit unchanged.
//!
//! Distributed key generation (dealerless, Feldman VSS) lives in [`dkg`]: at
//! the end each participant holds a share of the group signing key that no
//! machine ever assembled, plus enough public data to detect a cheating peer.

pub mod dkg;
pub mod errors;
pub mod group;
pub mod key;
pub mod nonce;
pub mod signing;

pub use dkg::{DkgRound1, DkgRound2, DkgSession};
pub use errors::FrostError;
pub use group::{GroupPublicKey, LagrangeCoefficient, Participant};
pub use key::{SecretShare, VerificationShare};
pub use nonce::{NonceCommitment, NoncePair};
pub use signing::{
    aggregate, prepare_signing_package, sign, verify, PartialSignature, Signature, SigningPackage,
};

/// The signing scheme identifier baked into every session transcript. Changing
/// this value invalidates every partial signature under the old identifier so
/// the aggregator cannot mix rounds from two different scheme versions.
pub const SCHEME_ID: &[u8] = b"unbridge-frost-eddsa-poseidon-babyjubjub-v1";
