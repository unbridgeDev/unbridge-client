# Security Policy

Unbridge coordinates threshold signatures that authorize native transactions on
other chains. A signing bug is a funds bug, so we take reports seriously and ask
you to disclose privately.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Report it through GitHub's private vulnerability reporting:

- https://github.com/unbridgeDev/unbridge/security/advisories/new

Please include:

- the affected component (`engine/kobe`, `engine/kobe-ecdsa`, `engine/programs/distin`, `engine/coordinator`, or the web app),
- a description of the issue and its impact,
- steps or a proof-of-concept to reproduce, and
- any suggested fix.

We aim to acknowledge a report within 72 hours and to agree on a disclosure
timeline with you. We will credit reporters who want credit once a fix ships.

## Scope

In scope: the on-chain program, the off-chain signers and their per-chain
envelopes, the coordinator, and the operator transport.

Out of scope for now (documented, not hidden): the networked operator path is a
localhost demo with a static pinned-key directory and no TLS/PKI; shares live in
local files, not an HSM; the integration and the on-chain program are **not
audited**. See the threat boundary in [`engine/SECURITY.md`](engine/SECURITY.md)
and the engine self-audit in [`engine/AUDIT.md`](engine/AUDIT.md).

## Supported versions

This is pre-production software deployed on Solana devnet only. There is no
production release and no real value at stake. Security fixes land on `main`.
