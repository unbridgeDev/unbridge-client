# pool-recovery

Reconstruct an Unbridge vault's note set and balance from Solana chain
state plus the view key, with no reliance on local cache. Restoring on a
fresh device with only the view key rebuilds the same view of the vault
a locally-cached client would show.

## The flow

1. Enumerate every transaction that touched the pool program via
   `getSignaturesForAddress`. Pagination handled with the `before` cursor.
2. For each transaction, pull the `encrypted_output=<base64>` and
   `nullifier=<base64>` lines from the program-log stream.
3. Try decrypting each blob against the vault's view key. A successful
   ChaCha20-Poly1305 authentication tag confirms the note belongs to
   this vault; a miss is O(one AEAD verify).
4. Record revealed nullifiers so previously-owned notes can be marked
   spent by the caller once it has the nullifier key on hand.
5. Sum unspent owned-note amounts into the current balance.

## Usage

```rust
use pool_note::ViewKey;
use pool_recovery::{Recovery, RpcClient, RecoveryProgress};

let vk = ViewKey::new(vault_view_key_bytes);
let vault = Recovery::new(RpcClient::mainnet(), &vk)
    .with_page_size(200)
    .on_progress(|p| match p {
        RecoveryProgress::ScannedTransaction { signature, slot, owned_delta, .. } => {
            if owned_delta > 0 {
                println!("owned +{owned_delta} at slot {slot} ({signature})");
            }
        }
        RecoveryProgress::Finished { owned, spendable } => {
            println!("recovered {owned} notes; spendable balance {spendable} lamports");
        }
        _ => {}
    })
    .scan()?;
```

The scanner defaults to Solana mainnet-beta and the deployed pool program
`6ESjwd4u6qW8SP9PtNwNus1hBJTxKViWra91C36RRALu`. Override via
`Recovery::with_program` for devnet or a fork.

## What the vault view carries

- **Owned notes**, keyed by commitment; duplicates from repeated scans
  collapse to one entry.
- **Revealed nullifiers**, in scan order. The caller wires
  `record_nullifier(hash, matcher)` with its own nullifier-key logic to
  flip an owned note's `spent` flag; the recovery crate does not hold
  the nullifier key (that's the note owner's).
- **Spendable balance**: sum of unspent owned notes.

## Trust properties

- The scanner never trusts server-side state. The output is a pure
  function of chain data plus the view key.
- A malicious RPC endpoint can hide transactions or lie about
  confirmations, but it cannot fabricate a valid ciphertext-under-your-
  view-key. Recovery either sees a note or does not; it never sees a
  fake one.
- Running against two independent RPC providers and diffing the outputs
  is a cheap way to catch a censoring endpoint.

## Status

Reference implementation used by the recovery flow in the browser
client and available as a standalone crate for integrators. Unit tests
cover the log parser (encrypted-output extraction, nullifier reveals,
malformed lengths), the vault-view accounting (idempotent adds, spent
marking, balance sums), and the scan-transaction happy path against
synthetic log fixtures. End-to-end tests against a live RPC live in
`examples/`.
