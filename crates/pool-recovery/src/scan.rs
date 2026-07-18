//! Top-level recovery scan.
//!
//! Walks the pool program's signature history page by page, decodes each
//! transaction's program-log stream, tries the view key against every
//! encrypted-output blob, and records revealed nullifiers. Emits progress
//! events so a UI can show which slot the scanner is at without polling.

use pool_note::{decrypt_note, ViewKey};

use crate::decode::{parse_program_events, ProgramLogEvent};
use crate::errors::RecoveryError;
use crate::rpc::{RpcClient, TransactionRecord};
use crate::state::{OwnedNote, VaultView};
use crate::MAINNET_POOL_PROGRAM;

/// Progress notifications the scanner emits as it walks history.
#[derive(Debug, Clone)]
pub enum RecoveryProgress {
    /// Scanner started; total is None if the RPC does not report it up front.
    Started { total_estimate: Option<u64> },
    /// One transaction fully processed.
    ScannedTransaction {
        signature: String,
        slot: u64,
        owned_delta: usize,
        nullifier_delta: usize,
    },
    /// Reached the end of the signature history.
    Finished { owned: usize, spendable: u64 },
}

/// Configurable recovery run.
pub struct Recovery<'a> {
    view_key: &'a ViewKey,
    rpc: RpcClient,
    program_id: String,
    page_size: u32,
    max_pages: u32,
    progress: Option<Box<dyn FnMut(RecoveryProgress) + 'a>>,
}

impl<'a> Recovery<'a> {
    pub fn new(rpc: RpcClient, view_key: &'a ViewKey) -> Self {
        Self {
            view_key,
            rpc,
            program_id: MAINNET_POOL_PROGRAM.to_string(),
            page_size: 100,
            max_pages: 200,
            progress: None,
        }
    }

    /// Point the scan at a non-default program (devnet, localnet, or a fork).
    pub fn with_program(mut self, program_id: impl Into<String>) -> Self {
        self.program_id = program_id.into();
        self
    }

    pub fn with_page_size(mut self, page_size: u32) -> Self {
        self.page_size = page_size;
        self
    }

    /// Cap the number of signature pages the scanner will pull. Default 200
    /// pages of 100 signatures = 20 000 transactions.
    pub fn with_max_pages(mut self, max_pages: u32) -> Self {
        self.max_pages = max_pages;
        self
    }

    pub fn on_progress(mut self, cb: impl FnMut(RecoveryProgress) + 'a) -> Self {
        self.progress = Some(Box::new(cb));
        self
    }

    /// Run the scan. Returns the accumulated [`VaultView`].
    pub fn scan(mut self) -> Result<VaultView, RecoveryError> {
        self.emit(RecoveryProgress::Started { total_estimate: None });

        let mut vault = VaultView::new();
        let mut before: Option<String> = None;
        for _page in 0..self.max_pages {
            let sigs = self.rpc.get_signatures_for_address(
                &self.program_id,
                self.page_size,
                before.as_deref(),
            )?;
            if sigs.is_empty() {
                break;
            }
            let last_sig = sigs.last().map(|s| s.signature.clone());
            for sig in sigs {
                if !sig.is_success() {
                    continue;
                }
                let tx = match self.rpc.get_transaction(&sig.signature)? {
                    Some(tx) if tx.is_success() => tx,
                    _ => continue,
                };
                let deltas = self.scan_transaction(&tx, &mut vault)?;
                self.emit(RecoveryProgress::ScannedTransaction {
                    signature: sig.signature,
                    slot: sig.slot,
                    owned_delta: deltas.0,
                    nullifier_delta: deltas.1,
                });
            }
            before = last_sig;
        }

        let spendable = vault.spendable_balance();
        let owned = vault.owned_count();
        self.emit(RecoveryProgress::Finished { owned, spendable });
        Ok(vault)
    }

    fn scan_transaction(
        &self,
        tx: &TransactionRecord,
        vault: &mut VaultView,
    ) -> Result<(usize, usize), RecoveryError> {
        let events = parse_program_events(tx.logs())?;
        let mut owned_delta = 0usize;
        let mut nullifier_delta = 0usize;
        for event in events {
            match event {
                ProgramLogEvent::EncryptedOutput(blob) => {
                    // A miss here is expected on most blobs; only ours decrypt.
                    let Ok(note) = decrypt_note(self.view_key, &blob.bytes) else {
                        continue;
                    };
                    let commitment = note.commitment()?;
                    vault.add_owned_note(OwnedNote::new(note, commitment));
                    owned_delta += 1;
                }
                ProgramLogEvent::NullifierReveal(nullifier) => {
                    // Client resolves note-to-nullifier via its own nk. Here we
                    // just record the reveal; the top-level caller can bind an
                    // owned-note matcher via `VaultView::record_nullifier`
                    // when it has the nk on hand.
                    vault.record_nullifier(nullifier, |_| false);
                    nullifier_delta += 1;
                }
            }
        }
        Ok((owned_delta, nullifier_delta))
    }

    fn emit(&mut self, event: RecoveryProgress) {
        if let Some(cb) = self.progress.as_mut() {
            cb(event);
        }
    }
}

/// Convenience: run a default mainnet recovery against `view_key`.
pub fn recover_vault(view_key: &ViewKey) -> Result<VaultView, RecoveryError> {
    Recovery::new(RpcClient::mainnet(), view_key).scan()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pool_note::{encrypt_note, Note, ViewKey};
    use rand_core::OsRng;

    #[test]
    fn own_a_note_via_view_key_match() {
        // Construct a note we own, encrypt with a view key.
        let vk = ViewKey::new([0xaau8; 32]);
        let note = Note {
            amount: 1_000_000_000,
            owner: [1u8; 32],
            blinding: [2u8; 32],
            mint: [0u8; 32],
        };
        let ct = encrypt_note(&vk, &note, &mut OsRng).unwrap();

        // Simulate a tx log containing our encrypted output plus a decoy.
        let decoy_vk = ViewKey::new([0xbbu8; 32]);
        let decoy = encrypt_note(&decoy_vk, &note, &mut OsRng).unwrap();
        let logs = vec![
            format!(
                "Program log: encrypted_output={}",
                base64::engine::general_purpose::STANDARD.encode(&decoy)
            ),
            format!(
                "Program log: encrypted_output={}",
                base64::engine::general_purpose::STANDARD.encode(&ct)
            ),
        ];

        // Scan a fake transaction with these logs.
        let mut vault = VaultView::new();
        let tx = TransactionRecord {
            slot: 42,
            block_time: None,
            meta: Some(crate::rpc::TxMeta {
                log_messages: Some(logs),
                err: None,
            }),
        };
        // Reach into scan_transaction via the public Recovery builder.
        let rec = Recovery::new(RpcClient::mainnet(), &vk);
        let (owned, _) = rec.scan_transaction(&tx, &mut vault).unwrap();
        assert_eq!(owned, 1, "our view key must claim exactly one note");
        assert_eq!(vault.spendable_balance(), 1_000_000_000);
    }

    #[test]
    fn foreign_notes_stay_unclaimed() {
        // Two notes on chain, neither encrypted to our key.
        let ours = ViewKey::new([0xaau8; 32]);
        let their_vk = ViewKey::new([0xbbu8; 32]);
        let note = Note {
            amount: 100,
            owner: [1u8; 32],
            blinding: [2u8; 32],
            mint: [0u8; 32],
        };
        let a = encrypt_note(&their_vk, &note, &mut OsRng).unwrap();
        let b = encrypt_note(&their_vk, &note, &mut OsRng).unwrap();
        let logs = vec![
            format!(
                "Program log: encrypted_output={}",
                base64::engine::general_purpose::STANDARD.encode(&a)
            ),
            format!(
                "Program log: encrypted_output={}",
                base64::engine::general_purpose::STANDARD.encode(&b)
            ),
        ];
        let mut vault = VaultView::new();
        let tx = TransactionRecord {
            slot: 0,
            block_time: None,
            meta: Some(crate::rpc::TxMeta {
                log_messages: Some(logs),
                err: None,
            }),
        };
        let rec = Recovery::new(RpcClient::mainnet(), &ours);
        let (owned, _) = rec.scan_transaction(&tx, &mut vault).unwrap();
        assert_eq!(owned, 0);
        assert_eq!(vault.spendable_balance(), 0);
    }
}
