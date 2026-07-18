# Unbridge integration examples

Runnable binaries that wire the client crates together in end-to-end
flows. Each example lives in `src/bin/`.

## Running

```bash
# from the repo root
cargo run --release -p unbridge-examples --bin end_to_end
```

The `--release` flag matters for the DKG timing print: debug mode is
roughly 10x slower on the polynomial evaluations.

## Examples

### `end_to_end`

Full pipeline in one process:

1. **2-of-3 dealerless DKG** via `frost::DkgSession`. Every party derives
   the same group public key without any machine holding the group secret.
2. **Note lifecycle** via `pool_note`: build a `Note` on a boundary
   denomination, compute its Poseidon commitment, derive a nullifier for a
   hypothetical leaf index, and roundtrip the plaintext through
   ChaCha20-Poly1305 with a view key.
3. **Two-round FROST signing** of a spend-authorisation message: each
   signer draws a fresh nonce pair, publishes its commitment, produces a
   Lagrange-weighted partial, and any party aggregates the partials into
   the final 96-byte `(R8, S)` signature.
4. **Read the deployed pool program** from Solana mainnet-beta via the
   JSON-RPC `getAccountInfo` endpoint. Confirms owner is the standard
   upgradeable BPF loader, program is executable, and reports the on-chain
   data length.

The Groth16 proof step (spend proof over the commitment tree + FROST
signature) is delegated to snarkjs in the browser client; this example
stops at the boundary and prints where the proof plugs in. Rendering a
native Rust prover for the same circuit is on the roadmap.

## What this proves

- The four load-bearing client crates (`frost`, `pool-note`,
  `frost-verify-check`, `confidential-vault`) compose without adapters.
- The public-input shape the FROST signing produces matches what the
  spend circuit consumes.
- The deployed on-chain program is discoverable and shape-verifiable
  from a small Rust binary, with no client-side keys and no wallet.

## Adding a new example

Drop a new file at `src/bin/<name>.rs` with a `fn main()` and add a
`[[bin]]` entry in `Cargo.toml`. The `unbridge-examples` crate is
workspace-visible, so downstream integrators can copy an example verbatim
into their own tree.
