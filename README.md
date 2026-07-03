<p align="center">
  <img src="banner.png?v=3" alt="Unbridge" width="100%"/>
</p>

<h1 align="center">Unbridge</h1>

<p align="center"><strong>One Solana account. Every chain. No bridges.</strong></p>

<p align="center">
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/github/license/unbridgeDev/unbridge?style=for-the-badge&color=6d5cff"/></a>
  <a href="https://github.com/unbridgeDev/unbridge/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/unbridgeDev/unbridge/ci.yml?style=for-the-badge&color=6d5cff"/></a>
  <a href="https://github.com/unbridgeDev/unbridge/releases"><img alt="Release" src="https://img.shields.io/github/v/release/unbridgeDev/unbridge?style=for-the-badge&color=6d5cff&include_prereleases"/></a>
  <a href="https://github.com/unbridgeDev/unbridge/commits/main"><img alt="Last commit" src="https://img.shields.io/github/last-commit/unbridgeDev/unbridge?style=for-the-badge&color=6d5cff"/></a>
  <a href="https://github.com/unbridgeDev/unbridge/stargazers"><img alt="Stars" src="https://img.shields.io/github/stars/unbridgeDev/unbridge?style=for-the-badge&color=6d5cff"/></a>
</p>

<p align="center">
  <a href="https://unbridge.dev"><img alt="Website" src="https://img.shields.io/badge/website-unbridge.dev-6d5cff?style=for-the-badge"/></a>
  <a href="https://x.com/unbridgeDev"><img alt="X" src="https://img.shields.io/badge/x-@unbridgeDev-1c1c1c?style=for-the-badge"/></a>
  <a href="#build--test"><img alt="Rust" src="https://img.shields.io/badge/rust-1.96-orange?style=for-the-badge"/></a>
  <a href="#build--test"><img alt="Anchor" src="https://img.shields.io/badge/anchor-0.31.1-blueviolet?style=for-the-badge"/></a>
  <a href="#build--test"><img alt="Solana" src="https://img.shields.io/badge/solana-1.18.26-14f195?style=for-the-badge"/></a>
</p>

Unbridge turns Solana into a control plane for cross-chain signing. Instead of wrapping an asset into a bridged IOU, a quorum of bonded operators runs a real threshold-signature ceremony off-chain and produces a *native* signature for the destination chain. The whole coordination, accounting, and slashing lives in one on-chain Anchor program. The destination chain (Ethereum, Bitcoin, Tron, Solana, Cosmos) sees an ordinary signature over its own curve. No bridge contract, no wrapped asset, no honeypot to drain.

The hard part is the cryptography, so this README leads with it. You can verify the core claim yourself in about two minutes.

The original protocol code is in `engine/` and `docs/`. `lib/` (if present in a future fork) is vendored dependencies via pinned git submodules, never source-copied.

## Feature status

| Component | Path | Curve | Status |
|---|---|---|---|
| FROST Ed25519 signer | `engine/kobe` | Ed25519 | stable |
| GG20 secp256k1 signer | `engine/kobe-ecdsa` | secp256k1 | stable |
| On-chain program | `engine/programs/distin` | n/a (control plane) | stable, devnet-live |
| Networked FROST (C ABI) | `engine/kobe/`, `engine/kobe-ecdsa/net` | Ed25519 | beta |
| Coordinator daemon | `engine/coordinator` | n/a | stable |
| Litesvm integration tests | `engine/tests-litesvm` | n/a | stable |
| Bitcoin native transfer | `engine/kobe-ecdsa/cmd/btc-send` | secp256k1 | stable |
| Tron native transfer | `engine/kobe-ecdsa/cmd/tron-send` | secp256k1 | stable |
| Mainnet deploy | `engine/programs/distin` | n/a | alpha, pre-audit |

## The proof, on-chain

Not a diagram. A quorum of operators threshold-signed a **native Bitcoin transaction** and it confirmed on Bitcoin's own network. It spends a UTXO from the group's address, pays a recipient, and returns change; Bitcoin consensus validated the witness. The group private key was never assembled, not at keygen and not at signing.

**[mempool.space/testnet/tx/d8d46e30…7cfba7a1](https://mempool.space/testnet/tx/d8d46e3068f5f11133eb0be5e45d1ba400b1148e2001155ee9ad57337cfba7a1)**

That signature was produced by the same GG20 path the tests below reproduce, and validated by Bitcoin itself. Everything under "Prove it yourself" reruns the cryptography from a clean clone in about two minutes.

## Prove it yourself

The central claim is: **`t` of `n` operators, each holding only a key share, produce one signature that an independent, standard verifier accepts, and the group secret is never reconstructed.** Two commands prove it on two curves. No devnet, no validator, no API keys.

### 1. FROST Ed25519, the SVM / Cosmos curve (Rust)

```bash
git clone --recurse-submodules https://github.com/unbridgeDev/unbridge.git
cd unbridge/engine/kobe
cargo test
```

This runs a 2-of-3 FROST Ed25519 ceremony (keygen, round 1, round 2, aggregate) and verifies the result two ways: under FROST's own verify path **and** under the independent `ed25519-dalek` crate, the exact RFC 8032 primitive a Solana or Cosmos chain runs. It also asserts the negative cases (wrong message, tampered signature, wrong group key, sub-threshold quorum) all fail, so a green test can't be a false positive.

```
running 3 tests
test one_share_cannot_sign - should panic ... ok
test two_of_three_aggregate_is_a_valid_ed25519_signature ... ok
test any_two_of_three_quorum_verifies ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

### 2. GG20 threshold ECDSA, the EVM / BTC / Tron curve (Go)

```bash
cd engine/kobe-ecdsa
go test -v -timeout 600s   # ~110s; GG20 safe-prime DKG is genuinely slow
```

This runs 2-of-3 GG20 threshold ECDSA over secp256k1 and proves the output is natively chain-valid on three chains, each with an *independent* verifier:

- **Ethereum**. The `(r,s,v)` recovers via go-ethereum's own `Ecrecover` to the same address derived from the group public key. That is exactly the check an ETH node performs.
- **Bitcoin**. A BIP-143 sighash is threshold-signed, DER + `SIGHASH_ALL` encoded, and verified under **decred secp256k1** (a different library than the one that signed). P2WPKH bech32 derivation matches the BIP-173 spec vector; low-S (BIP-62) enforced.
- **Tron**. keccak, `0x41`, base58check derivation is cross-checked against a known vector; the `(r,s,v)` recovers to the same Tron address.

## SDK example

TypeScript client, driving the same on-chain program from a browser wallet:

```ts
import { Connection, PublicKey } from '@solana/web3.js'
import { UnbridgeClient } from './sdk'

const conn = new Connection('https://api.devnet.solana.com')
const PROGRAM_ID = new PublicKey('4xy9dYHfAzi7cAcX5JHxNR6EoMJ9PGfeQDMHx6YUQQM6')

const client = new UnbridgeClient(conn, PROGRAM_ID)

const req = await client.createSigningRequest({
  targetVm: 'Evm',
  messageHash: '0xabcd...ef01',
  deadlineSlots: 1500,
})
// { requestId: 'BvP7...9zQx', slot: 348_112_003, threshold: 6700, deadline: 348_113_503 }

const status = await client.awaitAggregate(req.requestId)
// { signature: '0x30450221...', recovered: '0x9F4a...cE12', verified: true }
```

Rust host client for the coordinator:

```rust
use unbridge_client::{Client, TargetVm};

let client = Client::devnet();
let req = client.create_signing_request(TargetVm::Bitcoin, &sighash, 1500)?;
let agg = client.await_aggregate(req.request_id)?;
// agg.signature is DER + SIGHASH_ALL; agg.pubkey is the group compressed key.
```

## What's real vs what's next

Honesty is the point. Here is the exact line between what is built and verified and what is not.

**Real, built and independently verified (M1 through M7):**

- **FROST Ed25519 (M1).** 2-of-3 threshold Schnorr over Ed25519 via the ZF `frost-ed25519` 3.0 crate; aggregate verified by `ed25519-dalek`. (`engine/kobe`)
- **GG20 threshold ECDSA (M2).** 2-of-3 over secp256k1 via Binance `tss-lib` v2; ecrecover-verified by go-ethereum. (`engine/kobe-ecdsa`)
- **Bitcoin and Tron (M5/M6).** Real BIP-143 sighash signing, DER/bech32/base58check envelopes, verified against independent libraries and spec vectors.
- **On-chain coordination loop (M3/M4).** An on-chain `SigningRequest` drives the off-chain MPC; the real aggregate is recorded back on-chain and independently verified, end-to-end on a local validator. (`engine/coordinator`)
- **Networked operators (M7).** Three separate OS processes (distinct PIDs, ports, Ed25519 identity keys, share files) run the GG20 DKG and a 2-of-3 sign over authenticated TCP; an on-chain request triggers it; the wire signature ecrecover-verifies to the group address. (`engine/kobe-ecdsa/net`, `engine/coordinator` `net-demo`)
- **On-chain program, reconciled and live on devnet.** The fake byte-fold "signature" was removed; `aggregate_and_emit` now takes the *real* off-chain aggregate as input and enforces threshold plus slot deadline. Operator lifecycle, bonding, and slashing are implemented in full. Deployed to Solana **devnet** at `4xy9dYHfAzi7cAcX5JHxNR6EoMJ9PGfeQDMHx6YUQQM6`.

**Next, not done and not claimed to be:**

- **Networked-operator hardening.** Today's network proof is localhost: no TLS, no PKI/CA (a static pinned-key directory), and a fail-stop abort in this networked demo. GG20 *identifiable*-abort-to-slash is built and tested in SVM (`slash_operator_attested`), but the networked run and the on-chain slash are still proven in two halves over one canonical fault report, not yet in a single end-to-end run. Shares live in local files, not an HSM.
- **Security audit.** `tss-lib` and `frost-ed25519` are audited; *this integration and the on-chain program are not*. Nothing here is audited for real value.
- **FROST networked path.** Only the GG20/ETH path is proven networked end-to-end; the FROST signer follows the identical wiring but its `net/` operator isn't built yet.

No partners, no audit badge, no live token. When those exist, they'll be here.

## Architecture

<p align="center">
  <img src="docs/architecture.png" alt="Unbridge architecture" width="720"/>
</p>

Three layers, three responsibilities:

1. **On-chain coordinator** (`engine/programs/distin`). Owns accounting, economic security, threshold enforcement, liveness deadlines, and slashing. It does *not* do cryptography, it records a 32-byte intent and, later, the real aggregate bytes, gating on staked weight and a slot deadline.
2. **Off-chain MPC** (`engine/kobe`, `engine/kobe-ecdsa`). The actual ceremony. Each operator holds one Shamir share; the protocol combines partial signatures into one signature without ever reconstructing the group secret. FROST is 3-round, GG20 ~6-round, which is why a 400ms-slot chain hosts the coordination and slow-finality chains can't.
3. **Independent verifier.** The destination chain. It receives a signature indistinguishable from one a single key produced, and verifies it with its own native primitive.

### Why Solana hosts coordination

Multi-round MPC needs several network round-trips between operators. On a 12 to 15s chain each round costs over a minute; on Solana's 400ms slots an interactive ceremony finishes in seconds of wall-clock time. The control plane lives where coordination is cheap; the signature lands wherever it's needed.

### Signature schemes, branched per destination VM

| `TargetVm` | `SignatureScheme` | Off-chain signer |
|---|---|---|
| `Svm` / `Cosmos` | `FrostEd25519` (FROST Schnorr, Ed25519) | `engine/kobe` |
| `Evm` / `Bitcoin` | `Gg20Secp256k1` (GG20 threshold ECDSA, secp256k1) | `engine/kobe-ecdsa` |
| `Tron` | `Gg20Secp256k1` | `engine/kobe-ecdsa` |

The scheme is fixed on the request at creation and is immutable; a mismatched partial is rejected with `SchemeMismatch`.

### Round-trip cost table

| Chain | Slot / block time | 6-round GG20 wall-clock | Verdict |
|---|---:|---:|---|
| Solana | 0.4 s | ~2.4 s | hosts coordination |
| Base | 2 s | ~12 s | acceptable, slower than needed |
| Ethereum L1 | 12 s | ~72 s | too slow for interactive MPC |
| Bitcoin | ~600 s | ~1 hour | never |

## Project structure

`distin` is the engine's original codename; the on-chain program, its crate, and the daemon keep that name so the deployed Program ID and its source lineage stay byte-for-byte traceable. Unbridge is the name of the whole stack.

```
unbridge/
├── engine/
│   ├── programs/
│   │   └── distin/                on-chain Anchor program (Program ID above)
│   │       ├── src/lib.rs         instructions: initialize, register_operator,
│   │       │                                    create_signing_request,
│   │       │                                    submit_partial_signature,
│   │       │                                    aggregate_and_emit,
│   │       │                                    cancel_request, close_request,
│   │       │                                    slash_operator_attested,
│   │       │                                    unbond_start, unbond_complete
│   │       ├── src/state.rs       accounts: Config, Operator, SigningRequest,
│   │       │                                Partial, BondVault, SlashPool
│   │       └── src/errors.rs      typed errors: SchemeMismatch, BelowThreshold,
│   │                                            DeadlinePassed, ConstraintSeeds
│   ├── kobe/                       Rust FROST Ed25519 signer
│   │   ├── src/lib.rs             KeyGen, Round1, Round2, Aggregate, Verify
│   │   ├── src/net/               C ABI cdylib driven by the Go operator
│   │   └── tests/                 threshold ceremony + negative controls
│   ├── kobe-ecdsa/                 Go GG20 secp256k1 signer + envelopes
│   │   ├── tss.go                 KeyGen, Sign (per curve)
│   │   ├── eth.go                 EIP-1559 tx envelope, Ecrecover verify
│   │   ├── btc.go                 BIP-143 sighash, P2WPKH bech32, DER + low-S
│   │   ├── tron.go                TransferContract protobuf, base58check
│   │   ├── cmd/btc-send/          end-to-end native BTC transfer
│   │   ├── cmd/tron-send/         end-to-end native TRX transfer
│   │   └── net/                   authenticated TCP transport for operators
│   ├── coordinator/                Rust daemon: on-chain -> MPC -> on-chain
│   │   ├── src/main.rs            entrypoint, per-request catch_unwind isolation
│   │   ├── src/fulfill.rs         watch SigningRequest, drive MPC, submit agg
│   │   └── m7-demo.sh             networked capstone against a local validator
│   └── tests-litesvm/              in-process SVM loading target/deploy/distin.so
├── docs/                           protocol documentation (.mdx)
│   ├── architecture.mdx           layered diagram, threat boundary
│   ├── how-it-works.mdx           full round-by-round protocol
│   ├── security.mdx               threat model, invariants, audit scope
│   ├── api-reference.mdx          on-chain instructions and accounts
│   └── integration.mdx            SDK usage for dApps, wallets, relayers
├── product/                        launch-ready scripts and bootstrap helpers
├── Anchor.toml                     0.31 toolchain pin, per-cluster Program IDs
├── Cargo.toml                      workspace, shared deps, release profile
├── Dockerfile                      multi-stage, non-root, minimal runtime
├── Makefile                        build, test, lint, format, check, clean
└── .github/                        CI, release, issue and PR templates
```

## Build & test

Every command below runs against a clean clone. No packages to install, no faucet keys, no RPC quota.

```bash
git clone --recurse-submodules https://github.com/unbridgeDev/unbridge.git
cd unbridge
```

Off-chain signers (the proofs above):

```bash
cd engine/kobe       && cargo test                    # FROST Ed25519, ~10s
cd engine/kobe-ecdsa && go test -v -timeout 600s      # GG20 ECDSA (ETH/BTC/Tron), ~110s
```

On-chain program:

```bash
cargo check --workspace
cargo test -p distin
cargo fmt --all -- --check
anchor build     # SBF build (needs the Solana toolchain)
```

Full on-chain, MPC, on-chain loop on a local validator:

```bash
cd engine/coordinator && ./m7-demo.sh
```

Program ID (declared for every cluster in `Anchor.toml`): `4xy9dYHfAzi7cAcX5JHxNR6EoMJ9PGfeQDMHx6YUQQM6`

The reconciled bytecode is deployed and live on Solana devnet at that ID. Verify with `solana program show 4xy9dYHfAzi7cAcX5JHxNR6EoMJ9PGfeQDMHx6YUQQM6 --url devnet`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). PRs go through the template, get one CODEOWNER review, and must pass CI. Security-sensitive changes state their threat-model delta explicitly.

## License

[MIT](LICENSE).

## Links

- Website: <https://unbridge.dev>
- X: [@unbridgeDev](https://x.com/unbridgeDev)
- GitHub: [unbridgeDev/unbridge](https://github.com/unbridgeDev/unbridge)
- Docs: `docs/`
- Security: [SECURITY.md](SECURITY.md)
- Devnet Program ID: `4xy9dYHfAzi7cAcX5JHxNR6EoMJ9PGfeQDMHx6YUQQM6`
- Devnet Bitcoin proof: [mempool.space/testnet/tx/d8d46e30…](https://mempool.space/testnet/tx/d8d46e3068f5f11133eb0be5e45d1ba400b1148e2001155ee9ad57337cfba7a1)
