# Distin — external audit scope & security notes

Prepared for the external auditor. Everything below is reproducible; commands
included. Honest-gaps section is exhaustive — nothing is claimed beyond what a
listed proof shows.

## What Distin is

Solana is the control plane for cross-chain threshold signing. Operators bond
LST (Token-2022) as slashable economic security and register a group public
key; users post signing intents (`SigningRequest`); operators submit partial
signatures; the program finalizes when distinct-operator count and staked
weight clear `threshold_bps` inside a slot deadline. Two signature schemes:

- **FROST Ed25519** (`engine/kobe`, wraps the audited ZF `frost-ed25519` 3.0)
  — Aptos / SVM / Cosmos targets.
- **GG20 secp256k1** (`engine/kobe-ecdsa`, wraps Binance `tss-lib` v2.0.2)
  — Bitcoin / Ethereum / Tron / Cosmos targets.

## Audit targets (in scope)

| Component | Path | Language |
|---|---|---|
| On-chain program | `engine/programs/distin/` | Anchor 0.31 / Rust |
| FROST wrapper + C ABI | `engine/kobe/` | Rust (cdylib) |
| GG20 + networked transport (mTLS/PKI, share storage, fault attestation) | `engine/kobe-ecdsa/` | Go |
| Signer daemon (poll loop, dispatch, key sealing) | `engine/coordinator/src/signerd.rs` | Rust |

Out of scope: product web (read-only client), marketing site.

## CRITICAL: which source is deployed

Devnet program `4xy9dYHfAzi7cAcX5JHxNR6EoMJ9PGfeQDMHx6YUQQM6` is built from
commit **dd45c54**'s `programs/distin/src/` plus two later deltas (Pyth price
parsing in `compute_stake_weight`, `set_lst_price_feed` admin ix). Commit
697d858 (repo HEAD at time of writing) added `attestation_pubkey` to
`Operator`, changing the account from 151 to 183 bytes — that version is **NOT
deployed** and is layout-incompatible with live operator accounts (deploying it
bricks deserialization; this was observed and rolled back on 2026-07-02).
**Pre-audit action: the deployed source (dd45c54 + Pyth deltas) must be
committed as the canonical audit ref.** Audit the deployed lineage, not HEAD.

## Trust model & boundaries

- **No single party can sign.** FROST 2-of-3 shares live in separate processes
  (networked mode) or one sealed KeySet (legacy in-process mode); GG20 shares
  live one-per-process, never assembled.
- **The coordinator is untrusted for signature validity**: it independently
  re-verifies every aggregate (ed25519-dalek for FROST, k256 ecrecover for
  GG20) against the on-chain-registered group key before submitting.
- **Transport**: operator mesh is mutual TLS; every connection requires a leaf
  chained to the operator-set CA plus a per-operator pinned key. Untrusted-CA
  peers are rejected at the handshake (test-covered).
- **Misbehavior**: a corrupt signature share triggers FROST identifiable
  abort naming the culprit, and the operator layer produces a signed fault
  attestation (verifiable off-chain against the operator-set PKI). In the
  **deployed** program, slashing itself is admin-authority `slash_operator`
  (bounded by `bonded_amount`, moves bond to the slash pool via protocol PDA,
  recomputes oracle-gated weight, jails below `min_bond`) — the on-chain
  attested-slashing variant exists only in undeployed HEAD (697d858) and is
  out of scope.
- **Economic weight** is gated on a live Pyth price (`compute_stake_weight`
  rejects non-positive prices; feed repointable only by admin via
  `set_lst_price_feed`).

## Key management

- FROST keyset + Solana operator authorities: sealed at rest —
  Argon2id(passphrase) → ChaCha20-Poly1305, `DSTNK1` header
  (`signerd.rs`, unit-tested: roundtrip, randomization, fail-closed AEAD,
  plaintext backward-compat). Passphrase injected via env
  (`DISTIN_KEY_PASSPHRASE`), never on the command line or in the image.
- Networked FROST / GG20 per-operator shares: AES-256-GCM/argon2id envelopes
  written by each operator process (`DISTIN_SHARE_PASSPHRASE`).
- Admin keypair: plaintext file (see gaps).

## Invariants the auditor should try to break

1. A request can only reach `Signed` with ≥ threshold distinct registered
   operators' partials inside the slot deadline.
2. No path mints, moves, or releases bonded LST except `register` /
   `unbond`-flow / `slash*`.
3. `slash_operator` is callable only by the protocol admin, can never move
   more than the operator's `bonded_amount`, always recomputes weight from
   the residual bond, and jails below `min_bond` — check for weight/total
   accounting drift across slash + unbond interleavings.
4. Operator account layout (151 bytes) is preserved by every upgrade
   (see CRITICAL above — history shows this is the live failure mode).
5. `compute_stake_weight` cannot be inflated via a stale/negative/foreign
   Pyth account (account is admin-set, but parsing is offset-based — check
   feed-id/ownership validation depth).
6. Sealed key files cannot be swapped/corrupted without detection (AEAD),
   and a wrong passphrase can never yield plaintext.

## Verification inventory (all reproducible)

- Unit/integration suites, all green 2026-07-02:
  `cd engine/kobe && cargo test --release` (3 passed);
  `cd engine/coordinator && cargo test --release --bin signerd` (4 passed);
  `cd engine/kobe-ecdsa && go test ./...` (net suite ok, ~120s — includes
  mTLS negative, share-envelope, fault-attestation, adversarial tests).
- Networked FROST full ceremony + negatives: `engine/kobe-ecdsa/net/frost_demo.sh`
  (3 PIDs, DKG, 2-of-3 sign, offline-peer abort, rogue-CA reject,
  identifiable abort).
- Live devnet evidence (program `4xy9dY…`, 2026-07-02): request id 5 — FROST
  signed from sealed keys, sig independently ed25519-verified against the
  on-chain operator account's group key; id 6 — GG20, r||s ecrecovers to the
  group ETH address; id 7 — networked FROST (3 processes), sig verifies against
  the networked group key `e9b979e6…265b7fd6` and NOT the legacy in-process key.
- Container artifact: `docker build -f engine/Dockerfile.signerd` → image
  decrypts sealed keys on Linux and enters the devnet watch loop.

## Known gaps (honest, pre-audit)

1. **Reference deployment is one host.** All operator processes (and both
   schemes' shares) run on one machine. The stack is the one third parties
   would run (see `OPERATORS.md`), but no independent operator exists yet, so
   collusion-resistance is procedural, not yet factual.
2. **Admin keypair is plaintext on disk** and is simultaneously protocol
   admin, fee payer, LST mint authority, and program upgrade authority — a
   single-key compromise-and-rug surface. Needs role separation + hardware
   custody before mainnet.
3. **Legacy in-process FROST KeySet still exists** (fallback path when no
   frostnet set is on disk): one sealed file holds all three shares — fine as
   a demo fallback, not a threshold custody story.
4. **GG20 keygen ran with a permissive threshold window**: the coordinator
   lowered `threshold_bps` during set expansion (3000→2000). Parameter change
   authority is admin-only but unilateral and instant; consider timelock.
5. **Pyth parsing is offset-based** (`price at offset 73 of PriceUpdateV2`);
   feed identity is pinned by admin config, but the program does not itself
   verify the account owner or embedded feed id — auditor should weigh the
   spoof surface given the account is admin-set.
6. **Deployed-source provenance** is working-tree state, not a tagged commit
   (see CRITICAL). Must be fixed before the audit hand-off.
7. **No fee/economic audit yet**: bond sizing, request fees, and slash
   fractions are demo constants (`BOND_AMOUNT`, `THRESHOLD_BPS`), not
   economically derived.
8. **Slashing is admin-discretionary in the deployed program.** The fault
   attestation produced by the operator layer is not verified on-chain; the
   admin decides slashes. Wiring attestation verification into the program
   (the HEAD design) requires an Operator account migration — schedule it as
   an audited upgrade, not a hotfix (see CRITICAL).
