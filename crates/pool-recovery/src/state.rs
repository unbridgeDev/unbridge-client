//! In-memory view of what a vault owns and what it has spent.
//!
//! Everything the recovery scanner learns lands here: owned notes indexed
//! by their commitment, spent nullifiers, and a running balance. The state
//! is a pure function of chain data plus the view key, so two clients
//! recovering the same vault produce byte-identical `VaultView`s.

use std::collections::HashMap;

use pool_note::{Note, NoteCommitment};

/// A note the vault owns: the decrypted plaintext plus the on-chain
/// commitment it corresponds to, plus a placeholder leaf index we fill in
/// once the client resolves the tree position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedNote {
    pub note: Note,
    pub commitment: NoteCommitment,
    pub leaf_index: Option<u64>,
    pub spent: bool,
}

impl OwnedNote {
    pub fn new(note: Note, commitment: NoteCommitment) -> Self {
        Self {
            note,
            commitment,
            leaf_index: None,
            spent: false,
        }
    }
}

/// Aggregated view of a vault as reconstructed from chain.
#[derive(Debug, Default, Clone)]
pub struct VaultView {
    owned_by_commitment: HashMap<[u8; 32], OwnedNote>,
    spent_nullifiers: Vec<[u8; 32]>,
}

impl VaultView {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an owned note. Idempotent by commitment (a note that appears
    /// in two scans stays as one entry).
    pub fn add_owned_note(&mut self, owned: OwnedNote) {
        self.owned_by_commitment
            .entry(owned.commitment.0)
            .or_insert(owned);
    }

    /// Record a nullifier the chain revealed. If the vault owns the note that
    /// would produce this nullifier, mark it spent.
    pub fn record_nullifier(
        &mut self,
        nullifier: [u8; 32],
        matcher: impl Fn(&OwnedNote) -> bool,
    ) {
        for owned in self.owned_by_commitment.values_mut() {
            if !owned.spent && matcher(owned) {
                owned.spent = true;
            }
        }
        self.spent_nullifiers.push(nullifier);
    }

    /// Sum of amounts of owned notes that have not been spent.
    pub fn spendable_balance(&self) -> u64 {
        self.owned_by_commitment
            .values()
            .filter(|n| !n.spent)
            .map(|n| n.note.amount)
            .sum()
    }

    /// Every owned note the scanner has surfaced, spent or not.
    pub fn owned_notes(&self) -> impl Iterator<Item = &OwnedNote> {
        self.owned_by_commitment.values()
    }

    /// Every nullifier the chain revealed while scanning.
    pub fn spent_nullifiers(&self) -> &[[u8; 32]] {
        &self.spent_nullifiers
    }

    pub fn owned_count(&self) -> usize {
        self.owned_by_commitment.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pool_note::Note;

    fn owned(amount: u64, commit_seed: u8) -> OwnedNote {
        OwnedNote::new(
            Note {
                amount,
                owner: [1u8; 32],
                blinding: [2u8; 32],
                mint: [0u8; 32],
            },
            NoteCommitment([commit_seed; 32]),
        )
    }

    #[test]
    fn balance_sums_unspent() {
        let mut v = VaultView::new();
        v.add_owned_note(owned(100, 1));
        v.add_owned_note(owned(200, 2));
        v.add_owned_note(owned(300, 3));
        assert_eq!(v.spendable_balance(), 600);
    }

    #[test]
    fn duplicate_commitment_not_double_counted() {
        let mut v = VaultView::new();
        v.add_owned_note(owned(100, 1));
        v.add_owned_note(owned(100, 1));
        assert_eq!(v.owned_count(), 1);
        assert_eq!(v.spendable_balance(), 100);
    }

    #[test]
    fn matched_nullifier_marks_spent() {
        let mut v = VaultView::new();
        v.add_owned_note(owned(100, 1));
        v.add_owned_note(owned(200, 2));
        // matcher marks the note with commit_seed=1 as spent
        v.record_nullifier([9u8; 32], |o| o.commitment.0[0] == 1);
        assert_eq!(v.spendable_balance(), 200, "the 100-lamport note is now spent");
        assert_eq!(v.spent_nullifiers().len(), 1);
    }

    #[test]
    fn unmatched_nullifier_still_recorded() {
        let mut v = VaultView::new();
        v.add_owned_note(owned(100, 1));
        v.record_nullifier([9u8; 32], |_| false);
        assert_eq!(v.spendable_balance(), 100, "no owned note was spent");
        assert_eq!(v.spent_nullifiers().len(), 1);
    }
}
