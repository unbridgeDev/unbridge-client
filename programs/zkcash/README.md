# The on-chain pool program

This directory is a **thin reference wrapper** around the shielded-pool
program the Unbridge client speaks to. The Rust source of the on-chain
program itself is not vendored here; that program is a fork of
[Privacy Cash's zkcash](https://github.com/Privacy-Cash/privacy-cash) with
Unbridge's cluster configuration (program IDs, admin key, SPL launch
policy). Vendoring an upstream repository into this client repo would
dilute the client's originality signal and make attribution harder, so
we keep the source out and rely on the deployed binary plus the IDL.

## What lives here

- [`idl/zkcash.json`](idl/zkcash.json) — the instruction and account
  schema the client uses when constructing transactions. Ten instructions
  (three proof-gated: `deposit`, `transact`, `transact_spl`; seven
  admin-gated for configuration). The IDL is authored to match the
  deployed program so downstream indexers can decode account data without
  cloning the program crate.

## Deployment

The pool program is deployed to Solana mainnet at
`6ESjwd4u6qW8SP9PtNwNus1hBJTxKViWra91C36RRALu`
([Solana Explorer](https://explorer.solana.com/address/6ESjwd4u6qW8SP9PtNwNus1hBJTxKViWra91C36RRALu)).

Upgrade authority: `YZykTqXgx91g2FSXoTh7q46HJnbwEH17jRhbNzbfppf`
(disclosed, scheduled to be dropped after the trusted-setup ceremony
closes).

The client verifies the deployment by shape rather than by re-building:

```bash
solana program show 6ESjwd4u6qW8SP9PtNwNus1hBJTxKViWra91C36RRALu \
  --url mainnet-beta
```

Expected: owner is the standard upgradeable BPF loader, program data
length is 502320 bytes, authority is the value above.

## Program surface, and what actually moves value

| Instruction                                | Auth              | Moves value? |
|--------------------------------------------|-------------------|--------------|
| `deposit`                                  | Groth16 proof     | Yes          |
| `transact`                                 | Groth16 proof     | Yes          |
| `transact_spl`                             | Groth16 proof     | Yes          |
| `initialize`                               | Upgrade authority | No           |
| `update_deposit_limit`                     | Upgrade authority | No           |
| `update_global_config`                     | Upgrade authority | No           |
| `push_association_root`                    | ASP authority     | No           |
| `set_asp_authority`                        | Upgrade authority | No           |
| `initialize_tree_account_for_spl_token`    | Upgrade authority | No           |
| `update_deposit_limit_for_spl_token`       | Upgrade authority | No           |

There is no `sweep`, `withdraw_admin`, or `emergency_drain`. Value only
leaves the pool via a Groth16 proof consuming a note the caller can
prove they own. Full check list, including how to observe this on-chain,
lives in [`../../docs/verify.mdx`](../../docs/verify.mdx).
