# Changelog

Notable changes to Unbridge. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Current

Live on Solana mainnet.

- Shielded-pool program deployed to mainnet at `6ESjwd4u6qW8SP9PtNwNus1hBJTxKViWra91C36RRALu`.
- Personal and team vaults: deposit, `t`-of-`n` threshold-authorized withdrawal, relayed
  settlement to a fresh address.
- Distributed key generation and FROST threshold signing; the group key is never assembled.
- Threshold signatures verified inside a Groth16 proof and checked on-chain.
- Asynchronous, resumable team approvals over a member-funded durable nonce.
- Vault recovery from on-chain data plus the wallet.
- Open trusted-setup ceremony at unbridge.dev/ceremony.

Unaudited. Trusted-setup ceremony ongoing. See [`docs/security.mdx`](docs/security.mdx).
