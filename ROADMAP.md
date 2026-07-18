# Roadmap

Shipped items are live and verifiable. Planned items are honest intentions, not promises.

## Shipped

- [x] Shielded pool program live on Solana mainnet (`6ESjwd4u6qW8SP9PtNwNus1hBJTxKViWra91C36RRALu`).
- [x] Personal vault: private 1-of-1 balance, deposit and relayed withdrawal to a fresh address.
- [x] Team vault: distributed key generation and `t`-of-`n` FROST threshold signing, with the group key never assembled.
- [x] Threshold spends verified inside a Groth16 proof, checked on-chain.
- [x] Relayer-paid withdrawals, so the recipient is unlinkable to the members.
- [x] Asynchronous, resumable approvals for team sends (durable-nonce backed, member-funded).
- [x] Vault recovery from on-chain data plus the wallet, with no reliance on local cache.
- [x] Open trusted-setup ceremony at unbridge.dev/ceremony.

## Planned

- [ ] Distribute the team view key to member keys so the coordinator never holds it.
- [ ] Adopt external ceremony contributions via an announced verifying-key rotation, then
      set the program's upgrade authority to `None`.
- [ ] Third-party audit of the program and circuits.
- [ ] Larger anonymity set through decoy seeding and broader usage.
- [ ] SPL-token pools. The program ships with SPL entrypoints
      (`initialize_tree_account_for_spl_token`, `transact_spl`) but launches with
      `ALLOW_ALL_SPL_TOKENS = false` and an empty allow-list, so every SPL path is
      unreachable on mainnet today. Enabling it means adding vetted mints to the list in
      a program upgrade.
- [ ] Reproducible-build script and pinned client release, so the on-chain program data
      length and the browser bundle can both be checked against source.

Planning happens in issues and discussions.
