//! Note primitives for the Unbridge shielded pool.
//!
//! A note is a Poseidon commitment `C = H(amount, owner, blinding, mint)` and
//! carries the funds inside the pool. The shape here is the same arity-4 layout
//! Sapling and Tornado-Nova use, with two Unbridge-specific choices:
//!
//! - `owner = Poseidon(Ax, Ay, nk)` (Sapling-style ak/nk split): `Ax, Ay` is
//!   the group EdDSA public key that spends the note, `nk` is a separate
//!   nullifier key with no spend power. This is what lets FROST drive spends
//!   without touching the nullifier path.
//! - `nullifier = Poseidon(commitment, leaf_index, nk)`: derived from a
//!   deterministic per-note secret `nk`, not from the (randomised) FROST
//!   signature, so one note maps to exactly one nullifier no matter which
//!   session signs it.
//!
//! The crate also carries the boundary-denomination allow-list enforced by
//! the on-chain program and the ChaCha20-Poly1305 wrapper the client uses to
//! encrypt the plaintext note against the vault's view key.

pub mod denomination;
pub mod encryption;
pub mod errors;
pub mod field;
pub mod note;
pub mod nullifier;

pub use denomination::{is_valid_denomination, DENOMINATIONS, PREPAID_FEE_LAMPORTS};
pub use encryption::{decrypt_note, encrypt_note, ViewKey};
pub use errors::NoteError;
pub use field::{fr_from_bytes_le, fr_to_bytes_le};
pub use note::{Note, NoteCommitment};
pub use nullifier::{nullifier_for, Nullifier, NullifierKey};
