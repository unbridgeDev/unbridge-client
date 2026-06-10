---
name: Feature request
about: Propose a new signing scheme, destination chain, or protocol change
title: 'feat: '
labels: enhancement
assignees: ''
---

## Problem

What can't you do today, and why does it matter for the "one Solana account,
every chain, no bridges" premise?

## Proposal

Describe the change. If it touches the on-chain program, name the affected
instructions and accounts. If it adds a destination chain, describe the signing
scheme (FROST / GG20 / other) and the on-chain proof format.

## Alternatives considered

Alternative designs and why you didn't pick them.

## Scope check

- [ ] Does not add a trusted intermediary (bridge, custodian, oracle-signed message).
- [ ] Shares stay split at every stage (no full-key reconstruction).
- [ ] Threshold and slashing accounting continues to hold.
- [ ] Backward-compatible with existing operator sets, or migration path is stated.

## Additional context

Links to specs, papers, or reference implementations.
