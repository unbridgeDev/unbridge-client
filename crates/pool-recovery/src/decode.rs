//! Parse the program-log side of a pool transaction.
//!
//! Anchor programs surface their emitted events as `Program log: ...` lines.
//! The pool program emits two shapes recovery cares about:
//!
//! - `encrypted_output=<base64>` lines from `deposit` / `transact` /
//!   `transact_spl`. Each blob is one candidate note the vault might own.
//! - `nullifier=<base64>` lines from `transact` / `transact_spl`. Each entry
//!   marks a previously-owned note as spent.
//!
//! Anything else on the log stream is ignored. The parser is byte-oriented
//! and does no allocation on the log lines themselves; per-blob allocation
//! only happens once we know the line is a match.

use base64::Engine;

use crate::errors::RecoveryError;

const LOG_PREFIX: &str = "Program log: ";
const ENCRYPTED_KEY: &str = "encrypted_output=";
const NULLIFIER_KEY: &str = "nullifier=";

/// A pool event lifted out of the log stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgramLogEvent {
    /// Candidate note ciphertext. The vault view-key decides ownership.
    EncryptedOutput(EncryptedBlob),
    /// Nullifier revealed by a spend. Marks a previously-owned note spent.
    NullifierReveal([u8; 32]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedBlob {
    /// Raw ChaCha20-Poly1305 ciphertext (nonce prefix included).
    pub bytes: Vec<u8>,
}

/// Extract every event of interest from a single transaction's log stream.
pub fn parse_program_events(logs: &[String]) -> Result<Vec<ProgramLogEvent>, RecoveryError> {
    let mut out = Vec::new();
    for line in logs {
        let Some(body) = line.strip_prefix(LOG_PREFIX) else {
            continue;
        };
        let body = body.trim();
        if let Some(b64) = body.strip_prefix(ENCRYPTED_KEY) {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map_err(|e| RecoveryError::Base64(e.to_string()))?;
            out.push(ProgramLogEvent::EncryptedOutput(EncryptedBlob { bytes }));
        } else if let Some(b64) = body.strip_prefix(NULLIFIER_KEY) {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map_err(|e| RecoveryError::Base64(e.to_string()))?;
            if bytes.len() != 32 {
                return Err(RecoveryError::BadNullifierLength { got: bytes.len() });
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            out.push(ProgramLogEvent::NullifierReveal(arr));
        }
    }
    Ok(out)
}

/// Convenience: only the encrypted-output events, in order.
pub fn parse_encrypted_outputs(logs: &[String]) -> Result<Vec<EncryptedBlob>, RecoveryError> {
    Ok(parse_program_events(logs)?
        .into_iter()
        .filter_map(|e| match e {
            ProgramLogEvent::EncryptedOutput(b) => Some(b),
            ProgramLogEvent::NullifierReveal(_) => None,
        })
        .collect())
}

/// Convenience: only the revealed nullifiers, in order.
pub fn parse_nullifier_reveals(logs: &[String]) -> Result<Vec<[u8; 32]>, RecoveryError> {
    Ok(parse_program_events(logs)?
        .into_iter()
        .filter_map(|e| match e {
            ProgramLogEvent::NullifierReveal(n) => Some(n),
            ProgramLogEvent::EncryptedOutput(_) => None,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[test]
    fn ignores_unrelated_program_logs() {
        let logs = vec![
            "Program log: Instruction: Deposit".to_string(),
            "Program log: some other diagnostic".to_string(),
        ];
        assert!(parse_program_events(&logs).unwrap().is_empty());
    }

    #[test]
    fn extracts_encrypted_output() {
        let ciphertext = vec![0x11u8, 0x22, 0x33];
        let logs = vec![format!("Program log: encrypted_output={}", b64(&ciphertext))];
        let out = parse_encrypted_outputs(&logs).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].bytes, ciphertext);
    }

    #[test]
    fn extracts_nullifier() {
        let n = [0xabu8; 32];
        let logs = vec![format!("Program log: nullifier={}", b64(&n))];
        let out = parse_nullifier_reveals(&logs).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], n);
    }

    #[test]
    fn rejects_wrong_nullifier_length() {
        let short = vec![0u8; 16];
        let logs = vec![format!("Program log: nullifier={}", b64(&short))];
        let err = parse_nullifier_reveals(&logs).unwrap_err();
        assert!(matches!(err, RecoveryError::BadNullifierLength { got: 16 }));
    }

    #[test]
    fn preserves_event_order() {
        let logs = vec![
            format!("Program log: encrypted_output={}", b64(&[1u8])),
            format!("Program log: nullifier={}", b64(&[7u8; 32])),
            format!("Program log: encrypted_output={}", b64(&[2u8])),
        ];
        let events = parse_program_events(&logs).unwrap();
        assert!(matches!(events[0], ProgramLogEvent::EncryptedOutput(_)));
        assert!(matches!(events[1], ProgramLogEvent::NullifierReveal(_)));
        assert!(matches!(events[2], ProgramLogEvent::EncryptedOutput(_)));
    }

    #[test]
    fn tolerates_padding_whitespace() {
        let logs = vec![format!(
            "Program log:   encrypted_output={}   ",
            b64(&[9u8, 8, 7])
        )];
        let out = parse_encrypted_outputs(&logs).unwrap();
        assert_eq!(out[0].bytes, vec![9u8, 8, 7]);
    }
}
