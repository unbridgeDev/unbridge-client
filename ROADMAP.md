# Roadmap

Only shipped items are listed. Planning happens in issues and discussions.

## Shipped

- [x] On-chain `distin` program: request lifecycle, staked-weight threshold,
      slot-deadline enforcement (Anchor 0.31, `4xy9dYHfAzi7cAcX5JHxNR6EoMJ9PGfeQDMHx6YUQQM6`).
- [x] FROST Ed25519 signer (`engine/kobe`) — 2-of-N keygen, sign, verify.
- [x] GG20 secp256k1 signer (`engine/kobe-ecdsa`) — 2-of-N keygen, sign.
- [x] Networked FROST over C ABI — Go operator drives the audited Rust crypto.
- [x] Independent verification via `ed25519-dalek` on-host, `Ecrecover` on-chain.
- [x] Native Bitcoin testnet transfer signed by the group and broadcast.
- [x] Native Tron (Shasta) transfer signed by the group and broadcast.
- [x] Native Ethereum path (EIP-1559 encoding + Ecrecover verification).
- [x] Coordinator daemon hardened for 24/7 hosting.
- [x] Litesvm integration tests loading the built program `.so`.
- [x] Web app with real-time activity feed, Solscan click-through, expiry.
- [x] Fly.io signerd deployment (`Dockerfile.railway`, `fly.toml`).
- [x] Devnet program redeployed against the client_nonce reseed.
- [x] Public brand: docs at unbridge.dev, banner, architecture diagram.
