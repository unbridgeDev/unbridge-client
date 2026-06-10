---
name: Bug report
about: Report a defect in the on-chain program, coordinator, or web app
title: 'bug: '
labels: bug
assignees: ''
---

## What happened

A clear description of the observed behavior.

## Expected behavior

What you expected instead.

## Reproduction

Minimal steps to reproduce. If the defect is on-chain, please include:

- Cluster (devnet / mainnet-beta)
- Program ID (`4xy9dYHfAzi7cAcX5JHxNR6EoMJ9PGfeQDMHx6YUQQM6` for the canonical deployment)
- Transaction signature(s) that surface the defect
- Instruction name (`create_signing_request`, `submit_partial`, `aggregate_and_emit`, …)

For the Go operator (`kobe-ecdsa`) or the Rust operator (`kobe`), include the OS,
Go / cargo version, and the full command line.

## Logs

Attach the relevant coordinator / operator log slice, or the Solscan link for
the failing transaction.

## Environment

- OS:
- Rust / Anchor version:
- Go version:
- Node / Next.js version (web only):

## Security note

If this bug has security implications, do NOT file a public issue — send it to
security@unbridge.dev (or see SECURITY.md).
