# Changelog

Notable changes to Unbridge. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 0.5.0 — 2026-07-18

Repository realigned with the live product. Documentation only; the client that
produces proofs and runs the FROST ceremony continues to live at
[unbridge.dev](https://unbridge.dev).

### Added
- `docs/verify.mdx`: enumerates the full ten-instruction surface of the deployed
  program, states which three are proof-gated and which seven are admin-gated,
  and gives the CLI commands that back the "no sweep / no admin drain" claim.
- FAQ entries for the questions that come up when the repo is read cold: why the
  client is not on npm yet, whether the program is upgradable, and where the
  Rust source will live.
- `SECURITY.md`: GitHub private-advisory route, PGP fingerprint path, safe-harbor
  clause, 72-hour acknowledgement / 7-day triage window.

### Changed
- README now says plainly why the repo is docs-only and points at the verify page
  for the on-chain checks.
- Architecture doc names the actual seven admin instructions instead of the loose
  "deposit limit and verifying-key rotation" summary. The verifying key is frozen
  for the current epoch and only rotates through a scheduled upgrade tied to the
  ceremony.

### Removed
- Pre-pivot cross-chain threshold-signing scaffolding (Anchor.toml, Cargo, CI
  that built a program no longer in this repo, AUDITORS.md, MAINNET.md,
  OPERATORS.md). See commit `8ae2f81`.

## 0.4.1 — 2026-07-03

Pre-pivot release under the previous "One Solana account, every chain, no
bridges" framing (cross-chain threshold-signing coordinator). Superseded by 0.5.0
above. Kept in the tag history for the record; do not treat its notes as current.

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
