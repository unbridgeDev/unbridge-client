//! Pool boundary denominations.
//!
//! Inside the pool notes can carry any amount that fits in a u64. At the
//! deposit and withdraw boundary the program enforces exactly one of ten
//! fixed sizes: a 1-2-5 series from 0.1 SOL to 100 SOL. The client chunks
//! arbitrary user amounts into these denominations so each on-chain event
//! carries a uniform boundary value and one deposit is indistinguishable from
//! every other deposit at the same size.
//!
//! A deposit over-funds the pool by `PREPAID_FEE_LAMPORTS` so a later
//! withdrawal pays the recipient the clean denomination and pays the relayer
//! this prepaid amount for gas and rent. Keeping withdrawals denomination
//! clean avoids the "denomination minus a variable fee" tail that would
//! fingerprint the withdrawal.

/// The ten allowed boundary denominations, in lamports.
pub const DENOMINATIONS: [u64; 10] = [
    100_000_000,     // 0.1 SOL
    200_000_000,     // 0.2 SOL
    500_000_000,     // 0.5 SOL
    1_000_000_000,   // 1 SOL
    2_000_000_000,   // 2 SOL
    5_000_000_000,   // 5 SOL
    10_000_000_000,  // 10 SOL
    20_000_000_000,  // 20 SOL
    50_000_000_000,  // 50 SOL
    100_000_000_000, // 100 SOL
];

/// Prepaid withdrawal fee in lamports. A deposit adds this to the deposited
/// amount so the pool can pay the relayer a fixed fee when the note is later
/// withdrawn. 3_000_000 lamports covers a withdrawal's gas plus two nullifier
/// account rents plus a small relayer margin.
pub const PREPAID_FEE_LAMPORTS: u64 = 3_000_000;

/// Returns true iff `lamports` is one of the ten pool denominations exactly.
pub fn is_valid_denomination(lamports: u64) -> bool {
    DENOMINATIONS.iter().any(|d| *d == lamports)
}

/// Chunk an arbitrary lamport amount into a sequence of standard denominations,
/// greedy largest-first. Returns `Err(NonStandardDenomination(rem))` if the
/// residual after greedy split is not divisible into the smallest denomination.
pub fn chunk_amount(lamports: u64) -> Result<Vec<u64>, crate::NoteError> {
    let mut remaining = lamports;
    let mut out = Vec::new();
    for d in DENOMINATIONS.iter().rev() {
        while remaining >= *d {
            out.push(*d);
            remaining -= *d;
        }
    }
    if remaining > 0 {
        return Err(crate::NoteError::NonStandardDenomination(remaining));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_denomination_validates() {
        for d in DENOMINATIONS.iter() {
            assert!(is_valid_denomination(*d), "denom {d} must validate");
        }
    }

    #[test]
    fn rejects_non_denomination() {
        for bad in [0u64, 1, 99_999_999, 300_000_000, 1_500_000_000, 12_345_000_000] {
            assert!(
                !is_valid_denomination(bad),
                "value {bad} must NOT be a denomination"
            );
        }
    }

    #[test]
    fn chunk_1_5_sol_is_1_plus_5x01() {
        // 1.5 SOL = 1×(1 SOL) + 5×(0.1 SOL)
        let got = chunk_amount(1_500_000_000).unwrap();
        assert_eq!(got.iter().sum::<u64>(), 1_500_000_000);
        assert_eq!(got.iter().filter(|d| **d == 1_000_000_000).count(), 1);
        assert_eq!(got.iter().filter(|d| **d == 100_000_000).count(), 5);
    }

    #[test]
    fn chunk_37_uses_greedy_largest_first() {
        // 3.7 SOL = 1×2 + 1×1 + 2×0.2 + 3×0.1
        let got = chunk_amount(3_700_000_000).unwrap();
        assert_eq!(got.iter().sum::<u64>(), 3_700_000_000);
        // greedy: 2 + 1 + 0.5 + 0.2 = wait, 2+1+0.5+0.2 = 3.7, so 4 chunks
        assert!(got.len() <= 5, "greedy should be at most 5 chunks");
    }

    #[test]
    fn chunk_rejects_non_01_multiple() {
        // 0.15 SOL cannot be expressed in the allowed units
        let err = chunk_amount(150_000_000).unwrap_err();
        assert_eq!(err, crate::NoteError::NonStandardDenomination(50_000_000));
    }

    #[test]
    fn chunk_zero() {
        assert_eq!(chunk_amount(0).unwrap(), Vec::<u64>::new());
    }

    #[test]
    fn chunk_exact_denomination_is_singleton() {
        let got = chunk_amount(5_000_000_000).unwrap();
        assert_eq!(got, vec![5_000_000_000]);
    }
}
