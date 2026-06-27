//! Nullifier derivation.
//!
//! `nullifier = Poseidon(commitment, leaf_index, nk)`. The nullifier key
//! `nk` is separate from the spend-authorisation key (Sapling ak/nk split),
//! so a FROST group can produce a fresh signature per session without
//! affecting nullifier determinism: one note maps to exactly one nullifier
//! regardless of which threshold signs it. The program records spent
//! nullifiers in dedicated accounts to prevent double-spend.

use ark_bn254::Fr;
use light_poseidon::{Poseidon, PoseidonBytesHasher};

use crate::errors::NoteError;
use crate::field::{fr_from_bytes_le, fr_to_bytes_le};
use crate::note::NoteCommitment;

/// A 32-byte nullifier key. Held by the note's owner; carries no spend power
/// (a valid group signature is required for that).
#[derive(Debug, Clone, Copy)]
pub struct NullifierKey(pub [u8; 32]);

/// A 32-byte nullifier, revealed on spend to prevent double-spend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nullifier(pub [u8; 32]);

/// Derive the nullifier for a note at a given Merkle leaf index. Rejects
/// inputs that don't reduce to a valid BN254 field element so an ambiguous
/// encoding can never produce two different nullifiers for the same note.
pub fn nullifier_for(
    commitment: &NoteCommitment,
    leaf_index: u64,
    nk: &NullifierKey,
) -> Result<Nullifier, NoteError> {
    let c = fr_from_bytes_le(&commitment.0).map(|f| fr_to_bytes_le(&f))?;
    let idx = fr_to_bytes_le(&Fr::from(leaf_index));
    let n = fr_from_bytes_le(&nk.0).map(|f| fr_to_bytes_le(&f))?;

    let mut hasher = Poseidon::<Fr>::new_circom(3).map_err(|_| NoteError::PoseidonHashFailed)?;
    let digest = hasher
        .hash_bytes_le(&[&c, &idx, &n])
        .map_err(|_| NoteError::PoseidonHashFailed)?;
    Ok(Nullifier(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cm(b: u8) -> NoteCommitment {
        NoteCommitment([b; 32])
    }

    #[test]
    fn same_inputs_same_nullifier() {
        let n = NullifierKey([9u8; 32]);
        let a = nullifier_for(&cm(1), 42, &n).unwrap();
        let b = nullifier_for(&cm(1), 42, &n).unwrap();
        assert_eq!(a, b, "nullifier must be deterministic");
    }

    #[test]
    fn different_commitment_different_nullifier() {
        let n = NullifierKey([9u8; 32]);
        let a = nullifier_for(&cm(1), 42, &n).unwrap();
        let b = nullifier_for(&cm(2), 42, &n).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_leaf_index_different_nullifier() {
        let n = NullifierKey([9u8; 32]);
        let a = nullifier_for(&cm(1), 42, &n).unwrap();
        let b = nullifier_for(&cm(1), 43, &n).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_nk_different_nullifier() {
        let a_nk = NullifierKey([1u8; 32]);
        let b_nk = NullifierKey([2u8; 32]);
        let a = nullifier_for(&cm(1), 42, &a_nk).unwrap();
        let b = nullifier_for(&cm(1), 42, &b_nk).unwrap();
        assert_ne!(a, b, "different nk must produce different nullifier");
    }

    #[test]
    fn rejects_out_of_range_nk() {
        let nk = NullifierKey([0xffu8; 32]);
        assert_eq!(
            nullifier_for(&cm(1), 42, &nk).unwrap_err(),
            NoteError::FieldOutOfRange
        );
    }
}
