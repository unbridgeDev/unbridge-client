# Security policy

Unbridge holds user funds in a shielded pool authorized by threshold signatures verified
in zero-knowledge. A bug in a circuit, the program, or the signing protocol is a funds
bug. We take reports seriously and ask you to disclose privately.

## Reporting a vulnerability

Email **security@unbridge.dev** with:

- a description of the issue and its impact,
- steps or a proof of concept to reproduce it,
- the affected component (on-chain program, circuit, coordinator, relayer, client).

Please do not open a public issue for a vulnerability. We will acknowledge within a few
days and keep you updated through to a fix.

## Scope

In scope:

- The on-chain program `6ESjwd4u6qW8SP9PtNwNus1hBJTxKViWra91C36RRALu` (Solana mainnet).
- The spend and deposit circuits and their verifying keys.
- The threshold-signature and distributed-key-generation logic.
- Anything that lets a party move funds without a valid threshold-authorized proof, or that
  breaks the privacy guarantees in a way not already disclosed in
  [`docs/security.mdx`](docs/security.mdx).

Out of scope:

- Properties already documented as limitations (visible deposit denominations, anonymity
  set size, the relayer seeing the recipient at submit time, the coordinator holding an
  encrypted view key). These are known and disclosed, not vulnerabilities.
- The absence of a third-party audit. The protocol is knowingly unaudited.

## Honest status

Unbridge is unaudited and the trusted-setup ceremony is ongoing. These are stated plainly
in the documentation. Users should not deposit more than they are willing to expose to that
risk.
