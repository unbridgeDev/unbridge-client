<p align="center">
  <img src="banner.png" alt="Unbridge" width="100%"/>
</p>

<h1 align="center">Unbridge</h1>

<p align="center"><strong>The private multisig on Solana.</strong></p>

<p align="center">
  A vault your team controls together. On-chain it looks like one ordinary wallet:
  no member list, no threshold, no visible balance, and no trail from one payment to the next.
</p>

<p align="center">
  <a href="https://unbridge.dev"><img alt="App" src="https://img.shields.io/badge/app-unbridge.dev-8B5CF6?style=for-the-badge"/></a>
  <img alt="Network" src="https://img.shields.io/badge/solana-mainnet-8B5CF6?style=for-the-badge"/>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-8B5CF6?style=for-the-badge"/></a>
</p>

---

This repository is the **protocol documentation** for Unbridge. The client that
produces proofs and runs the FROST ceremony is not distributed as a package: it runs in
your browser at [unbridge.dev](https://unbridge.dev), which is the only supported way to
use the vault. Publishing a client for reproducible-build verification is scheduled after
the trusted-setup ceremony closes; until then, the client bundle can be inspected in the
network tab (proving and signing are computed in-page against Solana RPC and the relayer).
The on-chain program is deployed and verifiable directly against mainnet:
see [`docs/verify.mdx`](docs/verify.mdx). The Rust source is at
[`programs/zkcash`](programs/zkcash) with a reproducible-build recipe that
checks against the deployed binary's data length.

## What it is

A team vault where several people jointly control the funds, but the chain shows none of it.

- **No member list, no threshold on-chain.** Authorization happens inside a zero-knowledge proof. The chain sees a valid proof, not who signed or how many.
- **No visible balance.** Funds live in a shielded pool as Poseidon commitments. The chain holds ciphertext, never amounts.
- **No trail.** Deposits and withdrawals cannot be linked. A withdrawal lands at a fresh address with no on-chain path back to the depositor or the vault.
- **The key is never assembled.** A `t`-of-`n` threshold signature is produced from key shares that are never combined, not even at signing time.

It is the Zcash shielded model applied to a Solana team treasury.

## How it works

1. **Deposit.** SOL enters the shielded pool. The deposit creates a note: a Poseidon commitment that hides the amount, the owner, and a blinding factor. Only the note's holders can later spend it.
2. **Authorize.** To spend, the members run a distributed threshold-signature ceremony (FROST over Baby Jubjub). Each member contributes a partial signature from their own key share. No member, and no server, ever holds the whole key.
3. **Prove.** The aggregated threshold signature is verified *inside* a Groth16 zero-knowledge proof, together with the note's membership in the pool's Merkle tree. The proof reveals nothing about the members, the amount, or which note is being spent.
4. **Settle.** The proof is checked on-chain by the program. A relayer submits the transaction and pays the network fee, so the recipient address is never linked to the members' wallets.

See [`docs/how-it-works.mdx`](docs/how-it-works.mdx) for the full flow and
[`docs/architecture.mdx`](docs/architecture.mdx) for the components.

## Custody

No single party can move the funds, by construction.

- **Members** hold key shares. A spend needs a threshold of them. One member cannot withdraw alone.
- **The coordinator** (a relay that helps members find each other during a ceremony) holds **no key shares**. It cannot sign, cannot move funds, and can be replaced.
- **The relayer** pays withdrawal gas and learns the recipient at submit time only. It cannot steal and cannot see who authorized the spend.
- **The admin** (program upgrade authority) cannot touch user funds. There is no instruction that lets anyone sweep the pool.

## Verify it yourself

The program is deployed and live on Solana mainnet:

```
Program: 6ESjwd4u6qW8SP9PtNwNus1hBJTxKViWra91C36RRALu
```

```bash
solana program show 6ESjwd4u6qW8SP9PtNwNus1hBJTxKViWra91C36RRALu --url mainnet-beta
```

Expected output: owner is the standard upgradeable BPF loader,
the upgrade authority is `YZykTqXgx91g2FSXoTh7q46HJnbwEH17jRhbNzbfppf`
(disclosed, not hidden), the program data length is 502320 bytes.

The program surface is ten instructions. Three take Groth16 proofs and can move
value (`deposit`, `transact`, `transact_spl`); seven are configuration-only and
gated on the upgrade authority. There is no `sweep`, `withdraw_admin`, or
`emergency_drain` instruction. See [`docs/verify.mdx`](docs/verify.mdx) for the
full check list.

## Trusted setup

The Groth16 proving system needs a one-time setup. Its first phase uses the public
Perpetual Powers of Tau. The circuit-specific second phase was bootstrapped by the
project, which means the operator must currently be trusted not to have kept the setup
randomness. We are removing that assumption in the open: anyone can contribute fresh
entropy at [unbridge.dev/ceremony](https://unbridge.dev/ceremony). The setup is safe the
moment one honest contributor is someone other than us. This is disclosed plainly rather
than glossed over. See [`docs/security.mdx`](docs/security.mdx).

## What is and is not hidden

Honest by default:

| Hidden on-chain | Visible on-chain |
|---|---|
| Who the members are | That a deposit or withdrawal happened |
| How many must sign | The standard denomination of a deposit |
| The vault's balance | That the program was invoked |
| The link between a deposit and a withdrawal | |

Privacy grows with the size of the anonymity set. A young pool offers less cover than a
busy one. The relayer sees the recipient at submit time. These are properties of shielded
pools, not defects, and they are documented in [`docs/security.mdx`](docs/security.mdx).

## Documentation

- [Overview](docs/index.mdx)
- [Architecture](docs/architecture.mdx)
- [How it works](docs/how-it-works.mdx)
- [Security and threat model](docs/security.mdx)
- [Verify it yourself](docs/verify.mdx)
- [Getting started](docs/getting-started.mdx)
- [FAQ](docs/faq.mdx)

## Status

Live on Solana mainnet. The client runs in the browser at
[unbridge.dev](https://unbridge.dev); proving and signing happen on your own device. The
protocol is unaudited and the setup ceremony is ongoing. Do not deposit more than you are
willing to expose to that risk.

## Links

- Website: https://unbridge.dev
- Docs: https://unbridge.dev/docs
- X: https://x.com/Unbridgedev
- GitHub: https://github.com/unbridgeDev/unbridge

## License

MIT. See [LICENSE](LICENSE).
