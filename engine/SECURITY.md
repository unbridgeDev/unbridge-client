# Distin — Engine Security

Distin's on-chain program is the **control plane** for a threshold-signature
network. It does not perform the cryptography; it enforces the accounting,
economic security, threshold rules, liveness deadlines, and slashing that make
the off-chain signing libraries safe to trust. This document states what the
program defends, what it assumes, and where the trust boundary sits.

Program id: `4xy9dYHfAzi7cAcX5JHxNR6EoMJ9PGfeQDMHx6YUQQM6` (devnet).

## Trust model

| Actor | Trust | Powers |
|-------|-------|--------|
| Admin | Trusted, two-step transferable | tune params, pause, slash |
| Operator | Untrusted, bonded | register, sign, unbond |
| Requester | Untrusted | create / cancel own request, pay fee |
| Relayer | Untrusted, permissionless | finalize a threshold-met request |
| Off-chain signer libs (`kobe-*`) | Trusted for share *cryptography* | produce/verify shares, group-combine |
| Pyth feed | Trusted oracle (integration point) | price the LST bond |

The economic-security claim is **crypto-economic, not cryptographic**: an
operator that equivocates or withholds is punished by losing bonded collateral,
not prevented by the chain from misbehaving. Safety degrades gracefully with the
honest-bond fraction; it is not an impossibility result.

## What each on-chain check defends

**Signer / authority**
- Every admin action (`update_config`, `transfer_admin`, `pause`, `unpause`,
  `slash_operator`) gates on `has_one = admin`. Admin handover is two-step
  (`transfer_admin` nominates, `accept_admin` requires the nominee to sign), so
  a fat-fingered or hostile single transaction cannot strand the role.
- Operator lifecycle (`begin_unbonding`, `withdraw_bond`, `submit_partial_signature`)
  gates on `has_one = authority` against the operator PDA, so one operator can
  never act on another's account.
- `create_signing_request` / `cancel_request` require the requester to sign;
  `cancel_request` additionally enforces `has_one = requester` so **only the
  owner can tear down a still-pending request**. This closes a free griefing
  primitive (an attacker cancelling a victim's in-flight request mid-collection).
  Garbage-collecting someone else's request is only allowed once it has actually
  expired (`expire_request`, permissionless, refund still goes to the requester).

**PDA integrity**
- Every account is a program-derived address with fixed seeds and a stored bump
  validated on reuse (`bump = account.bump`): `protocol` (singleton),
  `bond_vault` / `slash_pool` (seeded by protocol), `operator` (seeded by
  protocol + authority), `request` (seeded by protocol + monotonic
  `request_id`), `partial` (seeded by request + operator). No account is
  attacker-substitutable; the seeds are frontend-derivable but program-enforced.
- The two `UncheckedAccount`s are both pinned with an explicit `address =`
  constraint (`lst_price_feed` against `protocol.lst_price_feed`; the close-time
  `requester` against `request.requester`), so neither is free-form.

**Account / owner validation**
- Token movements use `transfer_checked` (mint + decimals verified) into/out of
  protocol-owned Token-2022 accounts. The vault and slash pool are address-pinned
  to the values stored on `Protocol`, and the operator's token account is
  constrained to the operator authority.
- `partial` is `init` with a request+operator seed, so a second submission by the
  same operator on the same request **fails at the account layer** — double-submit
  is structurally impossible, not merely checked.
- Closes refund to the correct party: `cancel_request` / `expire_request` →
  requester; `withdraw_bond` → operator authority.

**Math**
- All accumulation is checked (`checked_add` / `checked_mul`) with an explicit
  `MathOverflow` error; protocol-wide weight decrements that may legitimately
  underflow (slash, unbond) use `saturating_sub` so accounting clamps at zero
  rather than wrapping. `overflow-checks = true` is also set in the release
  profile as a backstop.
- `required_stake_weight = total_bonded * threshold_bps / 10_000` floors the
  divide; flooring only ever lowers the target by at most one unit, so it cannot
  silently raise the security bar below the configured policy. Finalization gates
  on **both** the staked-weight target and a distinct-operator count, so a tiny
  stake that floors the weight target to zero still cannot finalize with zero
  partials.

**State machine**
- A request is `Pending → Aggregated` (success) or closed (`cancel`/`expire`).
  Every transition asserts the current `status` and the slot deadline:
  partials and finalization require `Pending` and `slot <= expiry_slot`;
  `expire_request` requires `slot > expiry_slot`. A request cannot be finalized
  twice, signed after expiry, or finalized after being closed.
- Operators cannot sign while `jailed` or once `unbonding_at != 0`; unbonding
  removes their weight from `total_bonded` immediately, so a leaving operator's
  stake stops counting toward live thresholds before its bond is returned.

**Economic / anti-gaming**
- Bond cannot be withdrawn until the full `unbonding_slots` window elapses
  (`withdraw_bond` checks `slot >= unbonding_at`), so collateral stays slashable
  across the liveness window after an operator stops signing.
- `slash_operator` moves collateral into the slash pool, recomputes the
  operator's weight from the residual bond, and jails it below `min_bond`,
  keeping `total_bonded` consistent for active operators only. The path is
  reachable by the admin (in production, gated by a verified fraud proof — see
  limitations).
- The per-request fee is charged in lamports to the protocol account before the
  request is created; there is no path to create a request without paying it
  when `request_fee > 0`.

**Legible failures**
- Every rejection carries its own `DistinError` variant (21 codes), so a revert
  reason is always specific (`SchemeMismatch`-style generic catch-alls were
  removed rather than left unreachable). No bare `ProgramError`.

## Honest limitations / marked integration points

These are deliberate trust boundaries, not oversights. They are marked inline in
the source with `=== ... point ===` banners.

1. **Off-chain share verification (`verify_partial_share`).** The on-chain layer
   enforces only the *structural* invariants it can: a non-zero share, bound to a
   non-empty message, with the correct scheme-specific half populated (FROST: the
   nonce-commitment half; GG20: the s-component half). The cryptographic validity
   of a share against the signer's committed nonce and public-key share is
   verified in the off-chain `kobe-{svm,evm,tron,cosmos}` libraries. A malicious
   operator submitting a structurally-valid but cryptographically-invalid share
   is caught off-chain and slashed, not rejected on-chain.

2. **Off-chain group-combine (`aggregate_and_emit`).** The canonical FROST/GG20
   group-combine that yields the broadcastable signature runs **off-chain** in the
   coordinator (`engine/coordinator`, real `frost::aggregate` over the quorum's
   round-2 shares). The chain **records** that finished signature; it does not and
   cannot recompute it.

   **Reconciled in Milestone 3 (model correction).** The earlier design folded
   each submitted `share` into `request.aggregate_sig` with a byte-wise
   `wrapping_add` and treated the result as the published aggregate. That was a
   *simplification that was actually wrong*: summing Ed25519/secp256k1 share bytes
   does not yield a valid signature, and a Solana program has no curve arithmetic
   to perform the real group-combine. Real FROST/GG20 signing happens in off-chain
   rounds; the chain's honest job is to **coordinate and record**, not to pretend
   to combine. So:
   - `submit_partial_signature` no longer folds bytes. A submitted partial is a
     **participation receipt**: it records *which* operator signed and *how much
     staked weight* it carries, which is exactly what the economic threshold is
     enforced against. (`PartialSignature.share` is retained as an audit/receipt
     field; it is not cryptographically combined on-chain.)
   - `aggregate_and_emit(aggregate_sig: [u8; 64])` now **takes the real aggregate
     signature as an argument** and stores it on the request, after enforcing the
     threshold (distinct-operator count + staked-weight target) and the slot
     deadline. The signature is bound to the request via its PDA and to the
     message via the request's `message_hash`; a relayer reads `aggregate_sig` and
     verifies it with an ordinary Ed25519/secp256k1 verifier before broadcasting.

   This is a bytecode-affecting change: the program was rebuilt with
   `cargo-build-sbf` (platform-tools v1.48 / rustc 1.84) and redeployed to
   **localnet only**. The IDL `aggregate_and_emit` entry was updated to carry the
   new `aggregate_sig` arg. Devnet still runs the pre-reconciliation bytecode and
   should be re-deployed by the operator when a newer SBF toolchain is wired into
   CI (see build status). The end-to-end loop is proven on localnet in
   `engine/coordinator` (read on-chain request → real FROST → record signature →
   independent Ed25519 verify of the on-chain-recorded sig). What is enforced
   on-chain (threshold, deadlines, bonding, slashing, the recorded signature being
   non-zero and bound to the request) is real; the cryptography is real and
   audited (ZF `frost-ed25519`); what remains simulated is the operator network
   (in-process, not networked) and the LST oracle.

3. **Pyth oracle (`compute_stake_weight`).** Until the Pyth feed is wired, the
   bond mint is treated as a 1:1 SOL-pegged LST, so the economic-security
   accounting is exact and deterministic. The account is still address-pinned to
   `protocol.lst_price_feed` and rejected if defaulted. The production code path
   (Pyth read + staleness guard via `StaleOraclePrice`) is documented inline at
   the integration point. **Wiring a real, possibly <1.0 LST/SOL price changes
   weight accounting and is a deploy-affecting change.**

4. **Slashing authority.** Two paths exist.
   - `slash_operator` is admin-gated (discretionary; for off-chain-adjudicated
     or governance slashes).
   - `slash_operator_attested` (**M9, identifiable abort**) is *permissionless*
     and gated by a cryptographic quorum, not the admin: it slashes the operator
     that GG20 itself identified as the signing-round culprit, when a threshold of
     honest operators have each signed the identical fault report. See the M9
     threat model below. The on-chain *effect* (move collateral, jail, rebalance
     weight) is identical between the two paths; only the authorization differs.

## M9 identifiable-abort — threat model (precise)

`slash_operator_attested` carries GG20's own culprit attribution on-chain. When a
signing round fails because a specific operator submitted an invalid MtA/ZK proof,
tss-lib blames that exact `*tss.PartyID` (`ecdsa/signing/round_3.go`,
`Culprits()`), and **every honest party independently reaches the same
attribution** — it is a verification result, not an opinion or a vote on conduct.
Each honest operator signs an identical canonical `FaultReport`
(`{session, message_hash, round, culprit_global, culprit_pubkey}`) with its
registered Ed25519 attestation key.

On-chain, the program (a) reconstructs the byte-identical report digest, (b) reads
the sibling **Ed25519 native-program** instruction through the instructions sysvar
and trusts only the runtime's signature verification (never a passed-in bool),
(c) requires each verified signer to be the `attestation_pubkey` of a *distinct
registered operator*, none of them the culprit, meeting
`required_attesters = ceil(operator_count · threshold_bps / 10_000)`, and (d) binds
the report's culprit key to the slashed operator account before applying the slash.

- **A minority cannot slash.** Below `required_attesters` the instruction reverts
  with `ThresholdNotMet`, so an honest operator is **not** slashable by a minority
  — proven in `net/fault_test.go` (single attester rejected) and the program's
  Rust tests (`required_attesters_is_ceiling_min_one`).
- **The residual framing risk requires a colluding MAJORITY** of the signing
  operators to sign a false report against an honest operator. That is exactly the
  honest-majority trust boundary the threshold-signature scheme **already**
  assumes: a dishonest majority can already produce group signatures and move
  funds. **Option A therefore introduces no new trust assumption** — it inherits
  the same boundary, and the same bonded stake secures both.
- **What this is NOT.** It is an attestation of a cryptographic fact, not an
  on-chain re-verification of the GG20 proof. The fully trustless upgrade — a
  RISC Zero **SNARK fault-proof** of the GG20 fault, verified on Solana, letting a
  single honest party slash a real cheater with no quorum — is documented as the
  next milestone in `HARDENING.md` and is deliberately not built here (pure
  on-chain Paillier/range-proof re-verification does not fit Solana's compute
  budget; a SNARK collapses it to one small proof + a cheap verifier).
- **Test-depth gap — CLOSED (M12).** The attested slash is now executed inside a
  real SVM transaction by the litesvm integration suite (`engine/tests-litesvm`):
  three operators register WITH bonded Token-2022 collateral, a real m-of-n
  Ed25519 native-program instruction is built (over the byte-identical fault
  digest the Go operators sign) and submitted in the same tx as
  `slash_operator_attested`, and the test asserts the culprit's bond **actually
  moves** from the vault into the slash pool and the operator is jailed below
  `min_bond`. The negatives are also proven on-chain: a single (minority)
  attestation reverts with `ThresholdNotMet` (6010); a full quorum signing the
  WRONG digest reverts with `MissingAttestationSignatures` (6022); and a single
  signature under a duplicated attestation key counts once (6010) — see the
  finding below. The test crate is a separate workspace with its own lock, so it
  cannot perturb the program's `cargo-build-sbf` lock.

### Finding fixed this pass — duplicate-attestation-key double-count (was: quorum-integrity)

`register_operator` does not force `attestation_pubkey` to be unique, so a party
willing to bond two operator accounts (real `min_bond` collateral each) could
register **both with the same attestation key**. The attester loop previously
deduped by the operator PDA (`op.key()`), so one Ed25519 signature under that
shared key was counted **once per duplicate account** — letting an attacker reach
`required_attesters` with fewer distinct witnesses than intended, undercutting
the "distinct honest attesters" guarantee. The integration test
`duplicate_attestation_key_cannot_double_count` reproduced it (the slash wrongly
succeeded). **Fix:** the loop now dedups on the **attestation key actually
signed** (`seen_keys: Vec<[u8;32]>`), so one signature counts exactly once
regardless of how many operator accounts claim that key; the test now sees the
bundle rejected with `ThresholdNotMet` and the bond untouched. (Defense in depth:
enforcing key-uniqueness at registration would also close it, but that needs an
index account or an O(n) scan; deduping at slash time is the minimal, complete
on-chain fix and is correct independent of registration.)

## Build / lint / audit status

- `cargo clippy --all-targets -- -D warnings`: **clean**. The only crate-level
  `#![allow(unexpected_cfgs, deprecated)]` covers warnings emitted by the
  anchor-lang 0.31 `#[program]` / `#[derive(Accounts)]` macros on the host
  toolchain (the `cfg(target_os = "solana")` family and an internal deprecated
  `realloc` call) — no project code relies on either.
- `cargo test`: **16 passing** unit tests over the security-critical pure logic
  (per-scheme share validation, every rejection path, threshold/overflow edges,
  and M9: the cross-language fault-report digest vector, the Ed25519
  introspection parser, and the attester-threshold math).
- **litesvm integration suite (`engine/tests-litesvm`): 2 passing** — the M9
  attested slash run in real SVM transactions: a quorum slash moving a real bond
  vault→slash-pool + jail, and the three on-chain negatives (minority,
  wrong-digest, duplicate-key). Run with
  `cd tests-litesvm && cargo test -- --nocapture`. Requires `target/deploy/distin.so`
  (built by `cargo-build-sbf`).
- `cargo audit`: **0 vulnerabilities**. Three `warning`-level advisories
  (`RUSTSEC-2025-0141` bincode unmaintained, `RUSTSEC-2025-0161` libsecp256k1
  unmaintained, `RUSTSEC-2026-0097` rand unsound) are all transitive through
  `anchor-lang` / `solana-program` and are not fixable per-project.
