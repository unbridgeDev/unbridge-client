# pool-note

Note primitives for the Unbridge shielded pool: Poseidon commitments,
nullifier derivation, view-key encryption, and boundary-denomination
validation. The reference implementation the client uses when constructing
transactions and the on-chain program checks against.

## What lives here

| Module          | What                                                        |
|-----------------|-------------------------------------------------------------|
| `denomination`  | The ten pool denominations plus the greedy chunker.         |
| `field`         | BN254 scalar helpers with strict range checks.              |
| `note`          | `Note { amount, owner, blinding, mint }` and its Poseidon commitment. |
| `nullifier`     | `Poseidon(commitment, leaf_index, nk)` with the ak/nk split. |
| `encryption`    | ChaCha20-Poly1305 wrapper for the on-chain encrypted-output field. |

## Why the ak/nk split

The nullifier key `nk` is deliberately separate from the spend-authorisation
public key `(Ax, Ay)`. That split is what makes FROST safe here: the group
signing key produces a fresh nonce per session (so the signature bytes
change), but the nullifier is derived from `nk` alone, so one note always
maps to exactly one nullifier regardless of which threshold signs it. If we
derived the nullifier from the signature we would either need signature
determinism (no fresh nonces, breaks FROST security) or accept that a note
can be spent twice with two different nullifiers (breaks double-spend
prevention).

## Usage

```rust
use pool_note::{Note, NullifierKey, ViewKey, encrypt_note, nullifier_for, is_valid_denomination};
use rand_core::OsRng;

let note = Note {
    amount: 1_000_000_000,
    owner: [/* Poseidon(Ax, Ay, nk) */; 32],
    blinding: [/* random */; 32],
    mint: [0u8; 32],
};

let commitment = note.commitment()?;
let nullifier = nullifier_for(&commitment, 42, &NullifierKey([/* nk */; 32]))?;

let view_key = ViewKey::new([/* team-shared */; 32]);
let encrypted = encrypt_note(&view_key, &note, &mut OsRng)?;

assert!(is_valid_denomination(note.amount));
```

## Tests

Unit tests cover determinism, key independence, boundary rejection, and
fail-closed behaviour on tampered ciphertext. Run:

```bash
cargo test -p pool-note
```
