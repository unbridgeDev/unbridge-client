//! Reconstruct an Unbridge vault's note set and balance from Solana chain
//! state plus the view key, with no reliance on local cache.
//!
//! The recovery flow:
//!
//! 1. Enumerate every transaction that touched the pool program via
//!    `getSignaturesForAddress`. Pagination handled with the `before` cursor.
//! 2. For each signature, fetch the transaction via `getTransaction` and pull
//!    the `encryptedOutput` byte blobs the pool program's `deposit` /
//!    `transact` / `transact_spl` instructions emit as program logs.
//! 3. Try decrypting each blob against the vault's view key. A successful
//!    ChaCha20-Poly1305 authentication tag confirms the note belongs to this
//!    vault; a fail-closed miss is O(one AEAD verify).
//! 4. Read the nullifier accounts revealed by each `transact` to mark
//!    previously-owned notes as spent.
//! 5. Sum unspent owned-note amounts into the current balance.
//!
//! The client never trusts server-side state; the recovery output is a
//! function of chain data plus the view key held by team members. Restoring
//! from a fresh device with only the view key rebuilds the same view of the
//! vault a locally-cached client would show.

pub mod decode;
pub mod errors;
pub mod rpc;
pub mod scan;
pub mod state;

pub use decode::{parse_encrypted_outputs, parse_nullifier_reveals, EncryptedBlob, ProgramLogEvent};
pub use errors::RecoveryError;
pub use rpc::{RpcClient, SignatureRecord, TransactionRecord};
pub use scan::{recover_vault, Recovery, RecoveryProgress};
pub use state::{OwnedNote, VaultView};

/// Deployed mainnet program identifier. The recovery scanner defaults to
/// this program; devnet integrators override via [`Recovery::with_program`].
pub const MAINNET_POOL_PROGRAM: &str = "6ESjwd4u6qW8SP9PtNwNus1hBJTxKViWra91C36RRALu";
