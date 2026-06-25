//! Poseidon commitment for a note.
//!
//! `C = H(amount, owner, blinding, mint)`. The client keeps the plaintext
//! `(amount, owner, blinding, mint)` for its own notes; the pool only ever
//! sees `C`.

use ark_bn254::Fr;
use light_poseidon::{Poseidon, PoseidonBytesHasher};

use crate::errors::NoteError;
use crate::field::{fr_from_bytes_le, fr_to_bytes_le};

/// A note in plaintext, as the client holds it locally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    /// Amount in lamports (not a boundary denomination in general).
    pub amount: u64,
    /// The owner key `Poseidon(Ax, Ay, nk)` as a 32-byte field element.
    pub owner: [u8; 32],
    /// Per-note random blinding factor, 32-byte field element.
    pub blinding: [u8; 32],
    /// SPL mint pubkey (or the zero pubkey for native SOL).
    pub mint: [u8; 32],
}

/// The Poseidon commitment for a note, on-chain leaf value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoteCommitment(pub [u8; 32]);

impl Note {
    /// Compute this note's commitment. Byte layout of every input must match
    /// what the circuit hashes so an off-chain reconstruction agrees with the
    /// on-chain leaf.
    pub fn commitment(&self) -> Result<NoteCommitment, NoteError> {
        let amount = fr_to_bytes_le(&Fr::from(self.amount));
        let owner = fr_from_bytes_le(&self.owner).map(|f| fr_to_bytes_le(&f))?;
        let blinding = fr_from_bytes_le(&self.blinding).map(|f| fr_to_bytes_le(&f))?;
        let mint = fr_from_bytes_le(&self.mint).map(|f| fr_to_bytes_le(&f))?;

        let mut hasher = Poseidon::<Fr>::new_circom(4).map_err(|_| NoteError::PoseidonHashFailed)?;
        let digest = hasher
            .hash_bytes_le(&[&amount, &owner, &blinding, &mint])
            .map_err(|_| NoteError::PoseidonHashFailed)?;
        Ok(NoteCommitment(digest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_note(amount: u64) -> Note {
        Note {
            amount,
            owner: [1u8; 32],
            blinding: [2u8; 32],
            mint: [0u8; 32],
        }
    }

    #[test]
    fn commitment_is_deterministic() {
        let n = dummy_note(1_000_000_000);
        let c1 = n.commitment().unwrap();
        let c2 = n.commitment().unwrap();
        assert_eq!(c1, c2, "commitment must be deterministic");
    }

    #[test]
    fn commitment_changes_with_amount() {
        let a = dummy_note(1_000_000_000).commitment().unwrap();
        let b = dummy_note(2_000_000_000).commitment().unwrap();
        assert_ne!(a, b, "amount change must change the commitment");
    }

    #[test]
    fn commitment_changes_with_blinding() {
        let mut n1 = dummy_note(1_000_000_000);
        let mut n2 = n1.clone();
        n1.blinding = [7u8; 32];
        n2.blinding = [8u8; 32];
        assert_ne!(
            n1.commitment().unwrap(),
            n2.commitment().unwrap(),
            "different blinding must produce different commitments"
        );
    }

    #[test]
    fn commitment_rejects_out_of_range_owner() {
        let mut n = dummy_note(1_000_000_000);
        n.owner = [0xffu8; 32];
        assert_eq!(n.commitment().unwrap_err(), NoteError::FieldOutOfRange);
    }
}
