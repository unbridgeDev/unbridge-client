# Changelog

All notable changes to Unbridge are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.1] — 2026-07-04

### Added
- End-to-end native Bitcoin testnet transfer signed by a 2-of-3 GG20 group
  and broadcast via `mempool.space` Esplora. Shares never combined.
- Native Tron transfer (Shasta testnet) signed by the same group over the
  Tron `TransferContract` protobuf `txID` and broadcast via the node API.
- Segwit assembly (`SerializeSignedP2WPKHTx`, `DecodeBech32P2WPKH`,
  `P2WPKHScriptForPubkey`) — full witness `[DER||SIGHASH_ALL, pubkey]`.
- Ambient brand-video background for the web app (fixed, dimmed).
- 24/7 signerd on Fly.io — `Dockerfile.railway`, `fly.toml` worker.

### Changed
- Rebrand across web, docs, app, marketing.
- README leads with the on-chain Bitcoin proof (first-page evidence).

### Fixed
- Coordinator creates its log dir before spawning (pruned hosts panicked).
- Web `Activity` matched the wrong 32 bytes as requester (offset fix).
- On-chain program: dropped mismatched request-PDA seeds constraint after
  the `client_nonce` reseed (`submit_partial` no longer hits
  `ConstraintSeeds`). Redeployed to devnet.

## [0.3.0] — 2026-07-02

### Added
- Group Ed25519 verifier + independent verification path via `ed25519-dalek`.
- FROST networked path over C ABI (kobe cdylib driven by the Go operator).
- Litesvm integration tests loading the built `target/deploy/distin.so`.

### Changed
- Coordinator hardened for 24/7 hosting: per-request `catch_unwind`,
  RPC-blip tolerant.
- Web `Activity` polls every 6s while open.

## [0.2.0] — 2026-06-30

### Added
- On-chain `SigningRequest` lifecycle: create, submit_partial,
  aggregate_and_emit, cancel, close.
- Operator bond accounting (Token-2022 LST), staked-weight threshold,
  slot-based liveness deadline.
- FROST Ed25519 keygen → threshold sign → verify.

## [0.1.0] — 2026-06-29

### Added
- Initial repository. Skeleton of the on-chain `distin` program and the
  off-chain `kobe` (FROST Ed25519) and `kobe-ecdsa` (GG20 secp256k1) crates.
- Anchor 0.31 workspace, Solana toolchain 1.18.26.
- Program ID `4xy9dYHfAzi7cAcX5JHxNR6EoMJ9PGfeQDMHx6YUQQM6`.

[0.4.1]: https://github.com/unbridgeDev/unbridge/releases/tag/v0.4.1
[0.3.0]: https://github.com/unbridgeDev/unbridge/releases/tag/v0.3.0
[0.2.0]: https://github.com/unbridgeDev/unbridge/releases/tag/v0.2.0
[0.1.0]: https://github.com/unbridgeDev/unbridge/releases/tag/v0.1.0
