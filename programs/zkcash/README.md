# zkcash

Reference on-chain deployment of Unbridge's FROST-in-Groth16 spend
authorisation on top of a shielded pool. Deployed at
`6ESjwd4u6qW8SP9PtNwNus1hBJTxKViWra91C36RRALu` on Solana mainnet.

Ten entrypoints; three are proof-gated and can move value (`deposit`,
`transact`, `transact_spl`), seven are admin-gated configuration only
(`initialize`, `update_deposit_limit`, `update_global_config`,
`push_association_root`, `set_asp_authority`,
`initialize_tree_account_for_spl_token`, `update_deposit_limit_for_spl_token`).
There is no `sweep`, `withdraw_admin`, or `emergency_drain`.

## What is Unbridge and what is inherited

The parts of the pool that make Unbridge different from any generic
shielded pool are:

- **Spend authorisation** proven by an EdDSA-Poseidon signature verified
  inside the Groth16 circuit, so a FROST group signature can drive
  spends without the private key ever being reconstructed. Circuits at
  [`../../circuits/`](../../circuits/).
- **Note primitives** using the Sapling ak/nk split so the nullifier stays
  deterministic under FROST's non-deterministic signatures. Reference
  implementation at [`../../crates/pool-note/`](../../crates/pool-note/).
- **Confidential-balance path** with an independently-generated ElGamal
  view key so the same threshold can own Token-2022 confidential accounts.
  Spike at [`../../crates/confidential-vault/`](../../crates/confidential-vault/).

The rest is the shielded-pool machinery any Tornado-Nova-style design
needs: sparse Merkle tree of note commitments, root history ring, spent
nullifier accounts, BN254 pairing verify. The Merkle tree and Groth16
verifier are adapted from Light Protocol (attributed in file headers).
The join-split account layout is adapted from Privacy Cash's zkcash pool
(MIT). Unbridge did not rewrite that infrastructure; it swapped the
spend-authorisation primitive above it and specialised the mainnet
configuration (admin key, program ID, SPL launch policy). The crate name
stays `zkcash` so the built binary matches the deployed one bit-for-bit;
renaming the crate would change the ELF and no longer verify against the
on-chain data length.

## Build

```bash
# from the repo root
cargo build-sbf --manifest-path programs/zkcash/Cargo.toml
```

The build output at `target/deploy/zkcash.so` should reproduce the same
502320-byte program that is currently deployed on mainnet. Compare with:

```bash
solana program show 6ESjwd4u6qW8SP9PtNwNus1hBJTxKViWra91C36RRALu \
  --url mainnet-beta \
  | grep 'Data Length'
```

## Layout

- `src/lib.rs`: the ten instruction handlers and their account contexts.
- `src/merkle_tree.rs`: sparse 26-level Merkle tree with a root history ring (adapted from Light Protocol).
- `src/groth16.rs`: pairing verify over BN254 via the Solana syscalls (adapted from Light Protocol groth16-solana).
- `src/verifying_keys.rs`: hardcoded verifying keys for the current setup epoch (regenerated with each ceremony rotation).
- `src/utils.rs`: field encoding, denomination checks, prepaid-fee math.
- `src/errors.rs`: typed error codes.
- `tests/unit/`: unit coverage for the modules above.

## Trust model

The program's `Authority` (upgrade authority) is
`YZykTqXgx91g2FSXoTh7q46HJnbwEH17jRhbNzbfppf`. It can push a new program
version. It cannot invoke a fund-moving instruction that does not exist in
the current binary. The authority is scheduled to be dropped
(set to `None`) after the trusted-setup ceremony closes.
