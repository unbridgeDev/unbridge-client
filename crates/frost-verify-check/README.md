# frost-verify-check

Standalone off-chain verifier for Unbridge pool proofs.

Runs the exact `solana-bn254` (alt_bn128) pairing check the on-chain program
runs, but as a native binary. `cargo run` reads a Groth16 proof + verifying
key from disk and prints whether it verifies. Used during ceremony changes
to de-risk on-chain verification before flashing a new program version, and
during local development to iterate on circuits without shipping a program
upgrade.

## Build and run

```bash
cargo run -p frost-verify-check -- \
    --proof   circuits/build/pool_tx_proof.json \
    --public  circuits/build/pool_tx_public.json \
    --vkey    circuits/verifying-keys/pool_verifying_key.rs
```

Exits 0 on verify, 1 on reject.

## Why a separate crate

The on-chain program in `programs/zkcash` is a `cdylib` targeting the Solana
BPF loader; adding a native `main.rs` there would drag a `bin` target into
the workspace and complicate the BPF build. Keeping this as its own crate
means:

- Same `solana-bn254` pairing implementation as on-chain (no drift).
- Runs on any dev machine without cargo-build-sbf.
- The verification result is a check on the ceremony's verifying key, not
  on the on-chain deployment. If this rejects, the on-chain verifier will
  also reject.

## Status

Ceremony tooling. Not shipped to end users. Comments in `src/groth16.rs`
mark where behavior must stay in lockstep with `the on-chain BN254 pairing verify`.
