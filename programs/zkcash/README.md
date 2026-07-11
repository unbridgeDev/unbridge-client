# zkcash

The Solana on-chain program for Unbridge. Ten entrypoints; three are proof-gated
and can move value (`deposit`, `transact`, `transact_spl`), seven are admin-gated
configuration only (`initialize`, `update_deposit_limit`,
`update_global_config`, `push_association_root`, `set_asp_authority`,
`initialize_tree_account_for_spl_token`, `update_deposit_limit_for_spl_token`).
There is no `sweep`, `withdraw_admin`, or `emergency_drain`.

Deployed at `6ESjwd4u6qW8SP9PtNwNus1hBJTxKViWra91C36RRALu` on Solana mainnet.

## Fork lineage

This crate is a downstream fork of Privacy Cash's `zkcash` shielded-pool
program (MIT, credit upstream). Unbridge specialises it for a private
multisig product: mainnet program ID, admin key, and SPL launch policy are
Unbridge's; the underlying pool + Groth16 verify + Merkle tree machinery is
inherited from the upstream. The crate name stays `zkcash` so the built
binary matches the deployed one bit-for-bit (renaming the crate would change
the ELF and no longer verify against the on-chain data length).

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

- `src/lib.rs` — the ten instruction handlers and their account contexts.
- `src/merkle_tree.rs` — the sparse 26-level Merkle tree with a root history ring.
- `src/groth16.rs` — pairing verify over BN254 via the Solana syscalls.
- `src/verifying_keys.rs` — hardcoded verifying keys for the current setup epoch.
- `src/utils.rs` — field encoding, denomination checks, prepaid-fee math.
- `src/errors.rs` — typed error codes.
- `tests/unit/` — unit coverage for the modules above.

## Trust model

The program's `Authority` (upgrade authority) is
`YZykTqXgx91g2FSXoTh7q46HJnbwEH17jRhbNzbfppf`. It can push a new program
version. It cannot invoke a fund-moving instruction that does not exist in
the current binary. The authority is scheduled to be dropped
(set to `None`) after the trusted-setup ceremony closes.
