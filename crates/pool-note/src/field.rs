//! BN254 scalar field helpers.
//!
//! Every note field (amount, blinding, keys) lives in the BN254 scalar field
//! `Fr`. On the wire and on chain we pass 32-byte little-endian encodings; the
//! circuit consumes them as field elements. These helpers do the conversion
//! and reject byte strings that overflow the field modulus.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

use crate::errors::NoteError;

/// Encode a field element as its canonical 32-byte little-endian byte string.
pub fn fr_to_bytes_le(x: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = x.into_bigint().to_bytes_le();
    let n = bytes.len().min(32);
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

/// Decode a 32-byte little-endian string into a field element, rejecting
/// values outside the field range so we never accept an ambiguous encoding.
pub fn fr_from_bytes_le(bytes: &[u8; 32]) -> Result<Fr, NoteError> {
    let x = Fr::from_le_bytes_mod_order(bytes);
    if fr_to_bytes_le(&x) != *bytes {
        return Err(NoteError::FieldOutOfRange);
    }
    Ok(x)
}

/// Interpret a u64 lamport amount as a field element.
pub fn fr_from_u64(x: u64) -> Fr {
    Fr::from(x)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_u64() {
        for v in [0u64, 1, 100_000_000, u64::MAX] {
            let f = fr_from_u64(v);
            let bytes = fr_to_bytes_le(&f);
            let g = fr_from_bytes_le(&bytes).unwrap();
            assert_eq!(f, g, "roundtrip failed for {v}");
        }
    }

    #[test]
    fn rejects_out_of_range_bytes() {
        // All-ones 32-byte string > BN254 field modulus.
        let ones = [0xffu8; 32];
        assert_eq!(
            fr_from_bytes_le(&ones),
            Err(NoteError::FieldOutOfRange),
            "all-ones must be rejected"
        );
    }

    #[test]
    fn zero_is_stable() {
        let z = Fr::from(0u64);
        assert_eq!(fr_to_bytes_le(&z), [0u8; 32]);
    }
}
