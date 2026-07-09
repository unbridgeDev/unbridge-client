# Compliance layer — design

Two features, one thesis: **make regulation a feature, not a liability.** The pool's
customers (DAO treasuries, trading desks, payroll) are the entities that most need to
*prove* their money is clean — the opposite of a mixer's users. Tornado's fatal flaw
was that it offered privacy with no way to demonstrate legitimacy; we close that gap
with (A) association-set proofs and (B) selective view-key disclosure. Both reuse
machinery the pool already has, so neither is a rewrite.

Status: **design only.** Building either changes the circuit → new trusted-setup phase-2
→ new verifying key → program redeploy. Scope decision at the end.

---

## A. Association-set proofs (Privacy Pools model)

**Goal.** On withdrawal, prove *"the funds I'm spending trace to a deposit in this
vetted set"* — without revealing *which* deposit — in addition to the existing "this
note is in the pool tree." An honest user picks an association set that excludes known-
illicit deposits; a bad actor can't produce a valid membership proof against it. This is
Buterin/Soleimani/Fabrega *Privacy Pools* (2023), adapted to our note model.

**What exists.** Each input already carries a Merkle proof into the pool's commitment
tree (`MerkleProof(26)`, `inCheckRoot`). Association proof is a **second** membership
proof against a different root — same template, no new crypto.

**The label problem.** Value flows through join/splits, so a withdrawn note isn't the
same commitment as the deposit that funded it. Privacy Pools solves this with a **label**:
every deposit mints a unique `label`; every note carries the label of its originating
deposit; internal transfers propagate the parent's label. Withdrawal proves
`label ∈ associationRoot`.

Our note is `{amount, owner=Poseidon(Ax,Ay,nk), blinding, mint}` (Poseidon arity 4).
Add `label` so the association set is a set of *labels* (one per deposit):

- Note commitment becomes `Poseidon(amount, owner, blinding, mint, label)` (arity 5).
- Deposit: `label = Poseidon(depositCommitment0, depositIndex)` — unique per deposit,
  publicly derivable at deposit time (goes in the ASP's candidate list).
- Output notes copy an input's label (transfer) or set a fresh deposit label (deposit).
  Constraint: for non-deposit inputs, `outLabel[j] === inLabel[some i]`. v1 (team vault,
  deposits only, no internal transfers yet) can shortcut: `label = depositCommitment`,
  and the association leaf *is* the note's originating deposit commitment.

**Circuit delta (`pool_tx.circom`).**
```
signal input associationRoot;                    // NEW public input
signal input inLabel[nIns];                       // NEW private
signal input assocPathElements[nIns][levels];     // NEW private
signal input assocPathIndices[nIns];              // NEW private
// commitment hasher: arity 4 → 5, add inLabel[tx]
// per input, second membership proof:
assocTree[tx] = MerkleProof(levels);
assocTree[tx].leaf <== inLabel[tx];
assocTree[tx].pathIndices/pathElements <== assoc*[tx];
assocCheck[tx] = ForceEqualIfEnabled();
assocCheck[tx].in[0] <== associationRoot;
assocCheck[tx].in[1] <== assocTree[tx].root;
assocCheck[tx].enabled <== inAmount[tx];          // padding inputs skip
```
Cost: ~+`nIns` Merkle proofs ≈ +50% constraints (50k → ~75k). Still <1ptau bump; proof
time ~2–2.5s in-browser (from 1.5s). Public inputs 7 → 8.

**Root distribution / who curates.** `associationRoot` is a public input, so the program
must pin it to a trusted source, else a user forges their own set:
- New `association_config` PDA holds the current valid root(s), updated by an **ASP
  authority** (a Merkle root of vetted deposit labels). Program checks the withdrawal's
  `associationRoot` ∈ {recent valid roots} (keep a small ring buffer for liveness during
  root rotation).
- **Curation tiers** (the product knob): (1) *self-attested* — the team runs its own ASP
  over its own deposits (weakest, but fine for "our treasury only touches our deposits");
  (2) *third-party ASP* — a compliance vendor publishes roots; (3) *community exclusion
  set* — everyone minus flagged addresses. Ship (1) as default, allow pointing the config
  at (2)/(3). The circuit is identical; only who signs the root changes.

**Inclusion vs exclusion.** The above is *inclusion* (member of a good-set) — simplest,
and what Privacy Pools ships. *Exclusion* (non-member of a bad-set) needs a
non-membership proof (sorted Merkle / SMT) — heavier, deferred. Inclusion covers the
"prove clean" use case.

---

## B. Selective view-key disclosure

**Goal.** A vault can hand a specific auditor a **viewing key** that decrypts the vault's
full transaction history — amounts, recipients, timing — while **never** granting spend
power. Time-boxable and per-vault. Turns "trust me, it's clean" into "here, verify."

**What exists.** The Sapling-style split is already in place: `nk` (nullifier key) sits in
the note and gives *linkability* (recompute nullifiers, follow the note) but no spend —
only the FROST group signature spends. The coordinator already stores a per-vault
`viewKey` field (currently a v1 balance-view convenience). And each transact carries two
`enc` blobs (`enc1`/`enc2`) — today placeholders (`"note-1"`), sized in `extDataHash`.

**The design: make the enc blobs real ciphertexts under a vault viewing key.**
- Vault viewing keypair `(vk, VK=vk·B8)` on Baby Jubjub, generated at vault creation
  alongside the FROST setup. `VK` is public; `vk` is the disclosure secret.
- On every output note, encrypt `{amount, owner, blinding, label}` to `VK` via ECDH:
  ephemeral `r`, shared `s = r·VK`, `enc = note_fields ⊕ KDF(s)`, ship ephemeral `R=r·B8`
  in the blob. This is exactly what `enc1`/`enc2` are *for* in Tornado-Nova (recipient
  note recovery) — we just target the viewing key too (or a second blob for the auditor).
- **Auditor flow:** given `vk`, scan the pool's `enc` blobs, decrypt every note belonging
  to the vault, reconstruct the complete amount/owner/label history. With `nk` too, they
  can also confirm which notes were spent (nullifier match). No `vk`/`nk` combination
  yields a FROST share → **cannot move funds**. Cryptographically enforced read-only.
- **Selective:** disclosure is just handing over `vk` (or a per-epoch subkey
  `vk_epoch = KDF(vk, epoch)` if you encrypt per-epoch, so you can scope an audit to a
  time window without exposing all history). Nothing on-chain changes for disclosure — it's
  an off-chain key handoff; the on-chain data was always there, just encrypted.

**Circuit delta.** *Minimal to none.* The circuit never sees the enc blobs (they're in
ext data, only bound via `extDataHash = hash(borsh(...enc...))`, which already exists). So
turning placeholders into real ciphertexts is a **client + program-hash** change, not a
circuit change — unless we want to *prove* the ciphertext is well-formed (that the
encrypted amount matches the note's amount). That proof (`enc correctly encrypts this
note under VK`) is a nice-to-have that binds honesty into the ZK; it adds ECDH+symmetric
constraints. **Recommend v1 without the well-formedness proof** (auditor detects a lying
encryptor by the plaintext not matching observed on-chain effects), add it later if a
customer needs non-repudiation.

**Coordinator caveat (tracked, not solved here).** The coordinator currently holds the
viewKey to show balances. That's the "coordinator can read" weakness already on the
roadmap; real selective disclosure means the *vault*, not the coordinator, holds `vk` and
hands it out deliberately. Fold this into the coordinator-decentralization work.

---

## Build scope (decision needed)

| Piece | Circuit change | Program change | Ceremony/vkey redo | Redeploy | Effort |
|---|---|---|---|---|---|
| A. Association sets | yes (arity 5 + 2nd Merkle, +50% constraints) | yes (association_config PDA, root check) | yes | yes | large |
| B. View-key disclosure (no wf-proof) | **no** | yes (enc blobs are real ct; hash unchanged shape) | **no** | client + minor program | **small** |
| B+. View-key with well-formedness proof | yes (ECDH in-circuit) | via A's redo | yes | yes | medium |

**Recommendation:** do **B first** (small, no circuit/ceremony/redeploy — it's a client
encryption change + wiring the viewing key at vault creation; immediately gives auditable
vaults and a real compliance story). Then decide on **A** as a deliberate circuit-v2
milestone bundled with any *other* pending circuit change (e.g. internal transfers), since
A alone forces a full ceremony + redeploy and shouldn't be spent on one feature. Exclusion
sets and in-circuit encryption proofs are v3.
