# Security policy

Unbridge holds user funds in a shielded pool authorized by threshold signatures verified
in zero-knowledge. A bug in a circuit, the program, or the signing protocol is a funds
bug. We take reports seriously and ask you to disclose privately.

## Reporting a vulnerability

Two channels, either is fine:

1. **Email** `security@unbridge.dev`. Encrypt if you can; a PGP key will be
   published alongside the trusted-setup ceremony's key rotation. Until then,
   plain email is fine.
2. **Private security advisory** on GitHub:
   [Report a vulnerability](https://github.com/unbridgeDev/unbridge/security/advisories/new).
   This is the recommended path if you already have a GitHub account.

Please include:

- a description of the issue and its impact,
- steps or a proof of concept to reproduce it,
- the affected component (on-chain program, circuit, coordinator, relayer, client),
- your preferred handle for credit (or a note that you prefer to stay anonymous).

Please do not open a public issue for a vulnerability. We aim to acknowledge within
72 hours and to have a triage assessment (accepted, disputed, out of scope) within
7 days. A fix's timeline depends on severity and complexity; we will keep you
updated.

## Safe harbor

Good-faith research on the deployed mainnet program is welcome under the standard
Solana disclosure conventions: no exfiltration of user funds, no denial of service,
no social engineering against team members or infrastructure providers. If you
report a live-fund-loss vulnerability privately and reasonably, we will not pursue
legal action for the research that surfaced it.

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
