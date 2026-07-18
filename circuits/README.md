# Unbridge circuits

Groth16 arithmetic circuits (circom) that back the shielded-pool program at
`6ESjwd4u6qW8SP9PtNwNus1hBJTxKViWra91C36RRALu`.

## Files

| Circuit                 | Purpose                                                             | Public inputs                             |
|-------------------------|---------------------------------------------------------------------|-------------------------------------------|
| `spend_auth.circom`     | Prove a note spend was authorized by a Baby-Jubjub EdDSA signature. | `Ax, Ay, M`                               |
| `pool_deposit.circom`   | Deposit-only circuit. No spent inputs, so it skips the FROST + Merkle machinery. | `publicAmount, extDataHash, mintAddress, outputCommitment[nOuts]` |
| `pool_tx.circom`        | Full shielded transaction (2-in-2-out) with FROST-driven spend authority. | `root, publicAmount, extDataHash, mintAddress, inputNullifier[nIns], outputCommitment[nOuts]` |

## What is Unbridge-original here

Unbridge's shielded pool started from Privacy Cash's zkcash Tornado-Nova
implementation and made **one load-bearing modification** to unlock FROST-based
team custody:

- Privacy Cash proves note ownership by a **key-preimage check**:
  `publicKey == Poseidon(privateKey)`. The private key sits in the witness at
  proving time. FROST cannot participate because there is no single private
  key to sign with.
- Unbridge replaces that check with an **EdDSA-Poseidon signature verification**
  inside the circuit: the note is owned by a public key `A = (Ax, Ay)`, and
  the spend proof binds an `(R8, S)` signature over the spend message `M`.
  The signing key is never in the witness. It can be threshold-shared with
  FROST, and the heavy Groth16 proof is produced by a single party at ordinary
  proving speed (no MPC proving).

This changes the spend-authorization step from "prove you know the preimage"
to "prove someone with the group signing key signed this transaction." The
group signing key is reconstructed nowhere: FROST produces `(R8, S)` from
partial signatures that never combine into a private key.

The nullifier is derived from a separate key `nk` bound into the note
(Sapling ak/nk split), not from the randomised signature, so it stays
deterministic and double-spend safe.

The three files here are the outcome of that decision:

- `spend_auth.circom` is the earliest single-party spike proving the swap
  actually verifies against `@noble/curves` off-chain.
- `pool_deposit.circom` is a fast deposit-only circuit (no spent inputs,
  proves in ~0.3s vs 6s for the full transact circuit).
- `pool_tx.circom` is the production transact circuit with `nIns = 2`,
  `nOuts = 2`, and the FROST-in-Groth16 spend auth wired into the note
  commitment / Merkle-membership proof.

## Verifying keys

`verifying-keys/` holds the Rust byte arrays consumed by the on-chain program
(the deployed program's verifying keys). They are auto-generated from the
`.zkey` output of `snarkjs groth16 setup` after the trusted-setup ceremony's
current-epoch phase-two contribution. Rotating the setup means regenerating
these files and publishing them in a program upgrade tied to the ceremony
schedule.

Ceremony randomness for the current epoch was bootstrapped by the project
and is being replaced through an open ceremony at
[unbridge.dev/ceremony](https://unbridge.dev/ceremony); the setup is safe
the moment one honest external contributor participates. See
[`../docs/security.mdx`](../docs/security.mdx#what-you-trust).

## Building

The circuits depend on circomlib. Compile with circom 2.1+:

```bash
# From the repo root
circom circuits/pool_tx.circom --r1cs --wasm --sym -o build/
circom circuits/pool_deposit.circom --r1cs --wasm --sym -o build/
circom circuits/spend_auth.circom --r1cs --wasm --sym -o build/
```

Then run the ceremony scripts under `client/scripts/`:

```bash
client/scripts/ceremony.sh   # phase-2 contributions for each circuit
client/scripts/build.sh      # generate verifying keys and Rust byte arrays
```

The resulting `*_verifying_key.rs` files should be diff-clean against the
copies in `verifying-keys/` for the current epoch. If they differ, the
ceremony has advanced and a program upgrade is needed.

## Attribution

The join-split and Merkle-membership scaffolding are adapted from Privacy
Cash's zkcash circuits (MIT). Unbridge's contribution is the FROST-compatible
spend-authorization primitive above and the deposit/transact split that
follows from it. See individual file headers for line-level notes.
