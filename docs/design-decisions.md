# Design decisions — locked

Decisions made for the FROST shielded team-vault. These are committed choices, not
options. "Now" = built + devnet-verified. "Mainnet" = deliberately deferred to the
mainnet launch, design fixed here so it isn't re-litigated later.

---

## 1. Pool structure — variable inside, fixed denominations at the boundary

- **Inside the pool: variable amounts** (Zcash Sapling / Tornado-Nova note split+merge).
  Non-negotiable — this is a treasury: payroll (4,200), invoices (1,350), arbitrary
  amounts. Fixed-denomination-only (pure Tornado) fights the use case and is rejected.
- **Deposit/withdraw boundary: fixed denomination units only.** Amounts are hidden
  inside the pool, but public at the boundary (ext_amount), so a unique boundary amount
  fingerprints the user (variable amounts = anonymity ~zero, since a unique amount has a
  unique source no matter how big the set). Standardize the boundary to kill that vector.
- **Units: 0.1 / 1 / 10 / 100 SOL.** The CLIENT chunks: a deposit of 3.7 = 3×(1-SOL tx) +
  7×(0.1-SOL tx), each tx's public boundary amount a standard unit → indistinguishable.
  The user just types "3.7"; never sees the units. Internal spending stays arbitrary.
- **Cost trade-off:** chunking = more txs = more rent (nullifier accounts, ~0.002 SOL/tx,
  non-recoverable). Negligible on large treasury amounts, painful on tiny ones. "Buy
  anonymity with rent." Our target is team treasuries (large amounts) → cheap.
- **Low-volume nuance:** many units fragment an already-tiny anonymity set. Start with 1–2
  units (trim the DENOMS array) and add more as volume grows; don't ship 4 buckets into an
  empty pool.
- Status: **CLIENT CHUNKING BUILT + devnet-verified.** `frost.mjs` `denominate(lamports)`
  (greedy split, rejects non-0.1-multiples) + `depositAmount(cfg,total,log)` (one standard
  tx per chunk, notes accumulate into one vault). Verified: `denominate(3.7)` = 3×1+7×0.1;
  a real 0.2-SOL deposit → 2 txs (23No9bqJ…, 4y76f8tG…), each moving EXACTLY 0.1 SOL
  on-chain (checked balances), 4 notes accumulated. **UI: amount input + live fee quote
  BUILT** — the user types any amount, sees only "network fee ~X · you pay ~Y" (chunking
  hidden); rejects non-0.1-multiples. **Denomination set = 1-2-5 series (0.1/0.2/0.5/1/2/
  5/10/20/50/100 SOL), BUILT** — near-optimal chunk count (3.7 = 4 tx vs 10 with
  powers-of-10; 137.3 = 7 vs 14). Trade-off: 10 units fragment a low-volume set — trim the
  DENOMS array to concentrate. **Multi-note withdraw (`withdrawAll`) BUILT + devnet-verified.**
  A chunked deposit makes 2 notes/chunk; withdrawAll withdraws each chunk as a separate
  tx to a fresh address. **BUG found + fixed:** the merged-flat vault used ONE root for all
  notes, but a later chunk grows the tree and invalidates earlier chunks' upper Merkle
  paths against the final root (witness Assert Failed at ForceEqualIfEnabled). Fix: store
  per-chunk SUB-VAULTS `{notes,pathIndices,pathElements,root}` (each self-consistent), and
  withdraw each against ITS OWN deposit-time root (still in root_history, size 100). **e2e
  verified on devnet: 0.7 SOL deposit (2 chunks 0.5+0.2, 4 notes) → withdrawAll → 2 txs to
  2 DISTINCT fresh addresses, 0.6979 SOL received.** Stored vault shape is now
  `{mint, deposits:[subvault...], encBlobs:[flat, for audit]}`. TODO: on-chain unit
  enforcement (program check, needs redeploy).

## 2. Fees / rent / gas — prepaid at deposit, not recovered after

- Reject the current post-hoc model (relayer fronts gas+rent, recovers via in-circuit
  fee). It forces the relayer to hold working capital and carries settlement/loss risk;
  rent (a non-recoverable real cost — nullifier accounts persist forever) may not be
  fully covered.
- **New model: at deposit time, escrow a fee/rent/gas buffer** (deposits are the user's
  own tx, no privacy cost to charging there). The relayer settles from the escrow at
  withdrawal → no relayer working capital, zero recovery risk, rent prepaid by the
  depositor. Fixed denominations (decision 1) make the buffer per-bucket exact.
- Status: **mainnet.** Devnet: post-hoc (relayer = demo key), acceptable for test.

## 3. Relayer — independent operator in production

- Demo relayer = the project authority key (8h38); devnet-only shortcut.
- **Mainnet: independent relayer businesses** (multiple, competing). fee = gas + rent +
  margin. The client picks one; the relayer can't steal (recipient/amount committed in
  the proof) so it needs no trust, only liveness.
- Status: **mainnet.**

## 4. ASP (association-set provider) — independent third party

- The compliance gate proves "my note is in a vetted set" — NOT "my money is clean"
  (that's impossible). Real meaning: "did not come from a publicly-flagged bad address."
  Crude by nature; honest positioning only, never marketed as perfect compliance.
- Demo = self-attesting (the withdrawer publishes its own vetting root); meaningless as a
  gate, fine as a mechanism demo.
- **Mainnet: the push_association_root authority = an independent compliance provider**
  (or community sets). Opt-in — the base shielded pool works without it. Program/circuit
  unchanged; only who holds the authority changes.
- Status: **mainnet.** Circuit + on-chain gate built + devnet-verified now.

## 5. Anonymity-set seeding — decoys + individual access

- A public deposit is not a leak (every mixer's deposits are public — unhideable on a
  public ledger); privacy = the deposit↔withdrawal link is broken. BUT it only holds if
  the set is populated. An empty pool → public deposit + public withdrawal + timing = you.
- **Seed with fixed-denomination decoys** (`seed-pool.sh`, already built + run on devnet):
  fixed denominations make decoys perfectly interchangeable with real notes.
- **Individuals share the same pool** (1-of-1, already built): individual + team deposits
  grow one shared anonymity set. Recruiting real users beyond that = GTM, not code.
- Status: decoy mechanism + individual access **now**; real population = mainnet/GTM.

## 6. Vault keys — derived from the wallet signature (DONE)

- x (spend) and vk (view) are DERIVED from a wallet signature over a fixed message
  (deterministic), never random, never stored. Reconnect the wallet → same keys →
  funds always recoverable; nothing spend-authorizing touches disk.
- Only non-spend note data (amounts, seeds, blindings, commitments, paths) is cached in
  localStorage so a reload can withdraw; cleared after a spend.
- Status: **DONE + devnet-verified** (demo-seed path; Phantom path wired, needs a real
  wallet to test end-to-end).

---

## Summary table

| # | Decision | Now (devnet) | Mainnet |
|---|---|---|---|
| 1 | Variable inside, fixed buckets (0.1/1/10/100) at boundary | variable e2e | + fixed boundary |
| 2 | Fees/rent/gas prepaid at deposit | post-hoc (demo) | prepaid escrow |
| 3 | Relayer = independent operator | demo authority | independent, competing |
| 4 | ASP = independent third party, opt-in | self-attesting demo | independent authority |
| 5 | Seeding: decoys + individual access | mechanism built | real population (GTM) |
| 6 | Vault keys derived from wallet, never stored | DONE | DONE |

Cryptographic core (FROST threshold sign, shielded pool circuit, on-chain SNARK verify,
view-key audit, association proof) is built and devnet-verified. Everything marked
"mainnet" is a productization/operations choice, not unbuilt crypto.

---

## Mainnet-prep progress (2026-07-10, "everything except the external audit")

- **ASP authority SEPARATED (done, local-validator verified).** GlobalConfig +`asp_authority:
  Pubkey` (init = admin; `set_asp_authority` hands it off). `push_association_root` now
  gated on a `PublishAssociationRoot` ctx checking `asp_authority` (NOT admin/upgrade
  authority) → an independent compliance provider can run the ASP with a key that can't
  touch the program or funds. Verified: correct ASP key publishes; wrong key → Unauthorized
  (0x1770). **This also unblocks a public A demo** (a throwaway ASP key, not 8h38, signs).
- **On-chain denomination ENFORCED (done, local-validator verified).** `DENOMINATIONS`
  const (1-2-5, 0.1→100 SOL); deposit requires `ext_amount ∈ DENOMINATIONS` else
  `NonStandardDenomination` (0x1774). Verified: 1 SOL ok, 0.7 SOL rejected. (Withdrawal-side
  denom cleanliness depends on prepaid fees — see below.)
- **Trusted-setup ceremony HARDENED (done).** `ceremony.sh` rewritten for the 8-input
  association circuit (ptau17) with 3 independent named phase-2 contributions + public
  beacon; `zkey verify` = ZKey Ok!, a proof under it verifies (functional). Emits
  `pool_ceremony_verifying_key.rs` (nr_pubinputs 8) = the MAINNET vkey. For real mainnet,
  swap the 3 local contributions for real named humans (same structure).
- **Fresh mainnet program keypair generated:** `6ESjwd4u6qW8SP9PtNwNus1hBJTxKViWra91C36RRALu`
  (`frost-pool-spike/keys/frost-pool-mainnet-program.json`, NEVER used on any cluster).
  Upgrade-authority plan: multisig or burn at mainnet deploy (TBD at deploy time).
- Program with asp_authority + denom enforcement built (`zkcash.so` 506KB). NOT on devnet
  (GlobalConfig grew 336B; a devnet upgrade would need a global_config migration) — this is
  the MAINNET program (fresh deploy, clean init). Verified on local validator.
- **Prepaid fees DONE (local-validator verified).** PREPAID model in the program: a deposit
  transfers `denom + PREPAID_FEE` (3_000_000 lamports) into tree_token (the note is worth
  exactly `denom`; the extra is a prepaid buffer); the withdrawal circuit fee is forced to 0
  (`require!(fee == 0)`), so the recipient gets the FULL clean denomination, and the program
  pays the relayer PREPAID_FEE out of tree_token. Removed `validate_fee`. Client (frost.mjs +
  withdraw_witness.mjs) set withdrawal fee = 0. Verified: deposit 1 SOL → pool +1.003;
  withdrawal → recipient got EXACTLY 1.000000000 SOL (round, no fingerprint) + fee_recipient
  +0.003 from the buffer. So payouts are denomination-clean and the relayer never fronts from
  the note.
- **Distributed DKG: PROTOCOL DONE (headlessly verified), transport = follow-on.**
  `frost_sign.mjs` `dkg(n,t)` = dealerless Feldman VSS over Baby Jubjub: each member has its
  own polynomial, broadcasts coeff·B8 commitments, sends poly_i(j) points; member j verifies
  every share against commitments then sets share = Σ poly_i(j). Group secret x = Σ poly_i(0)
  is NEVER assembled; A = Σ (constant-term commitments). Output shape == shamir() so the
  signer is unchanged. Verified in Node: 5-member DKG → 3-of-5 threshold sig verifies (and a
  different 3-of-5 subset → same A); below-threshold rejected. NOTE: this replaces the dealer
  for TEAM vaults (x distributed, recovery from members' shares, not a single wallet — solo
  vaults keep wallet-derived keys). The multi-BROWSER transport (broadcast commitments then
  shares across members via the coordinator) is NOT wired and can't be verified headlessly;
  it mirrors kobe's existing Ed25519 DKG transport.
- Then: **external audit** (excluded here) + legal + real ceremony participants + DKG
  transport wiring + mainnet deploy (real SOL, user-gated).
