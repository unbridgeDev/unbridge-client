//! Note encryption under a vault view key.
//!
//! Plaintext notes go into an on-chain `encrypted_output` field so a vault's
//! members can rebuild their balance from chain state alone. The wrapper is
//! ChaCha20-Poly1305 with a 12-byte nonce prepended to the ciphertext. The
//! view key is a 32-byte secret shared out of band across the team.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::NoteError;
use crate::note::Note;

const NONCE_BYTES: usize = 12;

/// Vault view key. 32 bytes of high-entropy secret. Held by members off chain.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ViewKey(pub [u8; 32]);

impl ViewKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        ViewKey(bytes)
    }
}

/// Encrypt a note against `view_key`. Nonce is prepended to the ciphertext.
pub fn encrypt_note<R: RngCore + CryptoRng>(
    view_key: &ViewKey,
    note: &Note,
    rng: &mut R,
) -> Result<Vec<u8>, NoteError> {
    let key = Key::from_slice(&view_key.0);
    let cipher = ChaCha20Poly1305::new(key);

    let mut nonce_bytes = [0u8; NONCE_BYTES];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut plaintext = Vec::with_capacity(8 + 32 + 32 + 32);
    plaintext.extend_from_slice(&note.amount.to_le_bytes());
    plaintext.extend_from_slice(&note.owner);
    plaintext.extend_from_slice(&note.blinding);
    plaintext.extend_from_slice(&note.mint);

    let ct = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|_| NoteError::DecryptAuthFailed)?;

    let mut out = Vec::with_capacity(NONCE_BYTES + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a ciphertext produced by [`encrypt_note`]. Fails closed on any
/// tampering, wrong key, or shortened ciphertext.
pub fn decrypt_note(view_key: &ViewKey, ct: &[u8]) -> Result<Note, NoteError> {
    if ct.len() < NONCE_BYTES + 16 {
        return Err(NoteError::CiphertextTooShort {
            got: ct.len(),
            need: NONCE_BYTES + 16,
        });
    }
    let key = Key::from_slice(&view_key.0);
    let cipher = ChaCha20Poly1305::new(key);

    let nonce = Nonce::from_slice(&ct[..NONCE_BYTES]);
    let plaintext = cipher
        .decrypt(nonce, &ct[NONCE_BYTES..])
        .map_err(|_| NoteError::DecryptAuthFailed)?;

    if plaintext.len() != 8 + 32 * 3 {
        return Err(NoteError::CiphertextTooShort {
            got: plaintext.len(),
            need: 8 + 32 * 3,
        });
    }
    let mut amt = [0u8; 8];
    amt.copy_from_slice(&plaintext[..8]);
    let mut owner = [0u8; 32];
    owner.copy_from_slice(&plaintext[8..40]);
    let mut blinding = [0u8; 32];
    blinding.copy_from_slice(&plaintext[40..72]);
    let mut mint = [0u8; 32];
    mint.copy_from_slice(&plaintext[72..104]);

    Ok(Note {
        amount: u64::from_le_bytes(amt),
        owner,
        blinding,
        mint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn note() -> Note {
        Note {
            amount: 1_234_567_890,
            owner: [0x11u8; 32],
            blinding: [0x22u8; 32],
            mint: [0x33u8; 32],
        }
    }

    #[test]
    fn roundtrip() {
        let vk = ViewKey::new([0x55u8; 32]);
        let ct = encrypt_note(&vk, &note(), &mut OsRng).unwrap();
        let back = decrypt_note(&vk, &ct).unwrap();
        assert_eq!(back, note());
    }

    #[test]
    fn wrong_key_fails_closed() {
        let good = ViewKey::new([0x55u8; 32]);
        let bad = ViewKey::new([0x66u8; 32]);
        let ct = encrypt_note(&good, &note(), &mut OsRng).unwrap();
        assert_eq!(decrypt_note(&bad, &ct).unwrap_err(), NoteError::DecryptAuthFailed);
    }

    #[test]
    fn tampered_ciphertext_fails_closed() {
        let vk = ViewKey::new([0x55u8; 32]);
        let mut ct = encrypt_note(&vk, &note(), &mut OsRng).unwrap();
        // flip a bit in the ciphertext body (skip the 12-byte nonce prefix)
        ct[NONCE_BYTES + 3] ^= 0x01;
        assert_eq!(decrypt_note(&vk, &ct).unwrap_err(), NoteError::DecryptAuthFailed);
    }

    #[test]
    fn short_ciphertext_rejected() {
        let vk = ViewKey::new([0x55u8; 32]);
        assert!(matches!(
            decrypt_note(&vk, &[0u8; 5]).unwrap_err(),
            NoteError::CiphertextTooShort { .. }
        ));
    }

    #[test]
    fn nonces_are_fresh_each_time() {
        let vk = ViewKey::new([0x55u8; 32]);
        let a = encrypt_note(&vk, &note(), &mut OsRng).unwrap();
        let b = encrypt_note(&vk, &note(), &mut OsRng).unwrap();
        assert_ne!(a, b, "each encryption must draw a fresh nonce");
    }
}
