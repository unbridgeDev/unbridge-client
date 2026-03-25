# Distin operator hardening — M8–M11 plan (grounded in the actual code)

Status legend: **DONE** (real verified artifact) · **PLANNED** · **FORK** (needs operator decision).

This plan takes the verified PoC (`core.verified`, M1–M7) from "works on localhost"
to "safe to run for real value", on the off-chain operator path
(`engine/kobe-ecdsa/net/`) and its hook into the on-chain program
(`engine/programs/distin/`). It does not touch mainnet or devnet.

## Starting point (what M7 actually left us)

`engine/kobe-ecdsa/net/` already had, before M8:

- Real TCP transport, length-prefixed frames, full-mesh (i<j dials), one conn/pair
  (`transport.go`, `network.go`).
- **Application-layer auth**: every `Envelope` is Ed25519-signed by the sender's
  identity key over `(session, from, to, is_broadcast, fin, payload)`; receiver
  verifies against a *pinned* identity pubkey. Session binding + routing binding
  stop replay/re-address. A challenge-response handshake pins the peer's identity
  key before any protocol byte flows. (`transport.go: signingBytes/Verify`,
  `network.go: handshake`).
- Negative tests: spoofed identity key rejected at handshake; peer-drop → clean
  abort (`net/demo.sh`, `transport_test.go`).

The gap M8 closes: **the bytes were cleartext** (an observer reads every tss-lib
message) and the only thing protecting the channel was our own handshake code,
not a vetted TLS stack. There was no PKI — just a flat directory of pinned keys
with no notion of issuance.

---

## M8 — Operator transport hardening (mutual TLS + PKI) — **DONE**

**What was built** (all wrapping Go's audited `crypto/tls`, never hand-rolled):

- `net/pki.go` — an operator-set CA (self-signed Ed25519 root) that issues one
  leaf certificate per operator. The leaf's subject key **is** the operator's
  Ed25519 identity key, so an operator has exactly one secret and the TLS
  identity == the Envelope-signing identity.
- `net/tlsconf.go` — mutual-TLS configs: listener uses
  `tls.RequireAndVerifyClientCert`, both ends pin TLS 1.3, both run
  `VerifyPeerCertificate` to require the peer's leaf key be pinned for the set.
  The application handshake then binds the in-band claimed index to the index the
  TLS *certificate* actually belongs to (`network.go: tlsPeerIndex`,
  `handshake`), so a member can't present a valid cert for index A while claiming
  index B.
- `net/network.go` — `NewNetworkTLS` + `wrapServerTLS`/`wrapClientTLS`; every peer
  connection is wrapped in mutual TLS before the handshake. The Envelope Ed25519
  signature is KEPT on top (defence in depth: TLS authenticates the channel, the
  signature authenticates the message end-to-end).
- `cmd/gen-operators -tls` mints the CA + leaves and writes the TLS config fields;
  `cmd/operator` brings up the mTLS transport when the config enables it.

**Verified artifacts:**

1. `TestMutualTLSDKGAndSignVerifies` — 3 operators run GG20 DKG + a 2-of-3 sign
   over mutual TLS; the signature ecrecovers to the group address. PASS (24.5s).
2. `TestUntrustedCertRejected` — an operator presenting a leaf from a *rogue* CA
   (even with the right identity key) is rejected at the TLS handshake
   (`x509: certificate signed by unknown authority`). PASS.
3. `net/demo.sh` — the same over 3 separate OS processes, plus the untrusted-CA
   process-level rejection (NEGATIVE C).

**Still PoC / next production steps (called out honestly):**

- Static enrolment: the CA mints N leaves up front then goes offline. No online
  enrolment, **no revocation (CRL/OCSP)**, no intermediate hierarchy, no cert
  rotation. For a fixed operator set this is defensible; a churning set needs
  revocation.
- The CA private key is ephemeral in `gen-operators` (never written). A real
  deployment puts the CA root in an HSM/offline machine.
- Localhost addressing only; no peer discovery / reconnection.

---

## M9 — Identifiable abort (GG20) — **DONE (Option A)**

The operator chose **Option A** (m-of-n signed fault report), built rigorously.
The culprit is not voted on by opinion — it is the operator that GG20's own
cryptography blames; Option A only carries that cryptographic attribution
on-chain with a quorum of independent signatures.

**Grounding (unchanged):** tss-lib attributes a failed signing round to the
offending `*tss.PartyID` (failed MtA/ZK-proof verification in
`ecdsa/signing/round_3.go`, surfaced via `(*tss.Error).Culprits()`).

**What was built:**

- *Off-chain capture* (`net/protocol.go`): `feed()` and the party-error path no
  longer collapse a culprit-bearing `*tss.Error` into `perr.Cause()`. A new
  `faultFromTSSError` converts it into a `*FaultError{Round, CulpritLocal}`
  (`net/fault.go`). `RunSign` returns that error so the caller can act on the
  named culprit. Every honest party independently reaches the same attribution —
  it is a verification result, not an opinion.
- *Signed fault report* (`net/fault.go`): `FaultReport` is the canonical
  statement `{session, message_hash, round, culprit_global, culprit_pubkey}`
  bound to the exact signing run. `digest32` is a fixed-width, length-prefixed
  SHA-256 preimage. `SignFaultReport` signs it with the operator's Ed25519
  identity key (the same key pinned in the peer directory and on-chain).
  `VerifyAttestation` / `CollectFault` assemble an m-of-n bundle, refusing to
  count a self-accusation or a duplicate signer — the off-chain mirror of the
  on-chain threshold.
- *On-chain consumer* (`programs/distin`): `slash_operator_attested` (no admin)
  reconstructs the byte-identical `fault_report_digest`, reads the **sibling
  Ed25519 native-program instruction via the instructions sysvar** and trusts
  only the runtime's verification result (it never accepts a passed-in "valid"
  bool), requires each verified signer to be the `attestation_pubkey` of a
  distinct registered operator (passed in `remaining_accounts`), none the
  culprit, meeting `required_attesters = ceil(operator_count·threshold_bps/1e4)`,
  binds the report's culprit key to the slashed operator account, and applies the
  same economic slash as `slash_operator` with `reason = REASON_IDENTIFIABLE_ABORT`.
  Operators now register an `attestation_pubkey` (added to the `Operator`
  account + `register_operator`).

**Verified artifacts (real, not "it compiles"):**

1. `net/fault_test.go::TestIdentifiableAbortAttestsCulprit` — a REAL GG20 3-of-3
   sign over mutual TLS where op2 corrupts its round-2 MtA proof; tss-lib blames
   op2 at BOTH honest operators (round 3); each signs an identical attestation;
   the 2-of-3 bundle assembles and names op2; a single attester does NOT reach
   quorum; a minority cannot frame an honest operator. **PASS (~14s).**
2. `net/fault_demo.sh` — the same over 3 separate OS processes (DKG + misbehaving
   sign + `cmd/fault-verify` assembling the on-chain bundle). The honest
   operators print `identifiable abort: round 3 culprit = global operator 2`;
   `fault-verify` emits the agreed culprit, the 32-byte digest, and the Ed25519
   native-instruction data the relayer attaches; the 1-attester negative is
   rejected. Real run pasted in the campaign report.
3. `programs/distin` Rust unit tests: `fault_digest_matches_go_vector`
   (on-chain `fault_report_digest` is byte-identical to the Go `digest32` — a
   pinned cross-language vector, so an honest signature reconstructs to the exact
   bytes the program checks), `ed25519_parser_extracts_only_digest_signers` /
   `_rejects_truncated` (the introspection counts only signers over the right
   digest and rejects malformed bundles), `required_attesters_is_ceiling_min_one`.
   **16 tests PASS.**
4. The SBF program builds with M9 (`cargo build-sbf` → `target/deploy/distin.so`).

**Threat model (honest).** Option A is an *attestation of a cryptographic fact*,
not an on-chain re-verification of the GG20 proof. The residual framing risk —
slashing an honest operator — requires a colluding **MAJORITY** of the signing
operators to sign a false fault report (a minority cannot reach
`required_attesters`, proven by the negative tests). That is the SAME
honest-majority trust boundary the threshold-signature scheme itself already
assumes: a dishonest majority can already forge group signatures / move funds.
**Option A therefore adds NO new trust assumption.** See `SECURITY.md` for the
full statement.

**What is NOT yet a runtime artifact (called out plainly):** the on-chain slash
was verified by the program's Rust unit tests (digest identity + Ed25519
introspection + threshold math) and an SBF build, NOT by executing
`slash_operator_attested` inside a validator/litesvm transaction (no litesvm /
`solana-program-test` is cached locally and pulling it would churn the pinned
`solana-sdk = 1.18.26` lock). The instruction's *logic* is unit-tested against
hand-built real Ed25519-native-program instruction data; a litesvm/anchor-mocha
integration test that actually moves the bond is the remaining step before real
value. No new trust assumption rides on that gap — it is a test-depth gap.

**Trustless upgrade = a SNARK fault-proof (next step, NOT built).** The fully
trustless version removes even the honest-majority framing risk: prove the GG20
fault *off-chain* in a zero-knowledge VM (RISC Zero — already installed at
`~/.risc0`), producing a succinct proof that "operator X's round-2 MtA proof
fails verification against the transcript," and verify that SNARK on Solana. Then
a SINGLE honest party (or anyone holding the transcript) can slash a real cheater
with no vote. Pure on-chain GG20 fraud-proof verification (Option B) is
impractical on Solana directly: re-checking Paillier/range proofs is heavy
BN-field math over large ciphertexts that does not fit the compute budget, and
the transcripts are large to post on-chain. A SNARK collapses that to one small
proof + a cheap verifier. This is the documented M9→trustless path; it is the
recommended next milestone, deliberately out of scope here.

---

## M10 — Secure share storage — **DONE**

**What was built** (`net/share.go`): `SaveOperatorShareEncrypted` /
`LoadOperatorShareEncrypted` encrypt the share at rest with **AES-256-GCM** (an
audited AEAD: confidentiality + integrity) under a key derived from the
operator's passphrase with **Argon2id** (memory-hard KDF, 64 MiB / 3 passes).
The on-disk envelope is self-describing (KDF id + salt + parameters + GCM nonce +
ciphertext); the passphrase never touches the disk. The operator binary reads it
from `DISTIN_SHARE_PASSPHRASE` (env, not a flag, so it stays out of process
listings) and encrypts on keygen / decrypts on sign; `IsEncryptedShare` lets it
auto-detect envelope vs the legacy plaintext form. An empty passphrase is
refused. Wrong passphrase fails the GCM tag — a clean reject, never a
silently-wrong share.

**Verified artifacts:**

1. `net/share_test.go::TestEncryptedShareAtRest` — a planted secret share scalar
   is provably ABSENT from the on-disk bytes; the file is recognized as an
   encrypted envelope; it round-trips with the right passphrase and is rejected
   with a wrong one. **PASS.**
2. `net/share_test.go::TestEncryptedShareStillSigns` — a REAL GG20 DKG writes
   every share ENCRYPTED, each operator reloads ONLY via the passphrase-gated
   loader, and the quorum produces a valid 2-of-3 signature that ecrecovers to
   the group address. **PASS (~18s).** Proves encryption-at-rest does not degrade
   the signer.

**Share-compromise threat model.** A share is this operator's piece of the group
key; any `t` shares reconstruct it. Plaintext-at-0600 protects nothing against a
stolen disk/backup or a root/sibling process. With M10:
- A single stolen **encrypted** share leaks nothing without the passphrase
  (Argon2id makes brute force expensive; GCM rejects tampering).
- Even a single stolen **plaintext** share is below threshold — it cannot sign or
  reconstruct alone.
- The real catastrophe is `t` shares AND their passphrases compromised together
  (full key recovery), which is why operators must hold DISTINCT passphrases.
- **Higher tier (noted, not built):** an HSM/enclave-bound key so the share key
  never exists in process memory. M10 is software AEAD; it does not defend a
  compromised live process that already holds the decrypted share in RAM.

---

## M11 — Adversarial operator network — **DONE (GG20 + FROST both on-chain-slashable)**

### Part 1 — GG20 hostile-set survival — **DONE**

The GG20 networked path is proven to terminate-correctly **or
identifiably-abort** under every hostile behavior, never hang, never forge:

- **(a) operator drops mid-round → clean abort.** Already proven by
  `net/demo.sh` NEGATIVE A (op exits nonzero, no garbage signature) and the
  `readLoop` "peer disconnected" path.
- **(b) garbage protocol bytes that pass wire-auth → rejected.**
  `net/adversarial_test.go::TestGarbagePassingWireAuthIsRejected` — an
  authenticated random payload (valid signature, session, sender binding) fails
  `tss.ParseWireMessage` before it ever reaches a party. Never accepted, never a
  panic, never forged. **PASS.**
- **(c) operator stalls → terminates via timeout.**
  `net/adversarial_test.go::TestStallTerminatesViaTimeout` — a real DKG then a
  sign whose quorum peer never appears; the run RETURNS a timeout/abort error
  within the deadline instead of hanging. **PASS.**
- **(d) malicious proof (garbage that parses but fails the ZK check) →
  identifiable abort.** This is M9: the specific culprit is named and slashable.
  A teardown race (the culprit drops its socket the beat before our own round
  surfaces the fault) was found and fixed — `runSign` now gives the local party a
  short grace window on a transport drop to surface a `*FaultError` first, so
  identifiable abort is deterministic, not sometimes-collapsed-to-"peer
  disconnected" (verified by running the M9 test repeatedly).

### Part 2 — FROST networking — **DONE (decision F1)**; Part 3 — FROST on-chain slash — **DONE**

Today **only GG20 is networked** (`engine/kobe-ecdsa/net`, in Go). FROST lives in
`engine/kobe` as a **Rust** crate (ZF `frost-ed25519`), proven in-process
(`kobe/tests/frost_verify.rs`) but NOT over a real operator network. Extending the
networked, adversarial path to FROST is net-new engineering and forks on
language/architecture:

- **Option F1 — a Rust transport for `kobe`.** Build the mutual-TLS + Ed25519
  envelope + mesh transport again in Rust around `frost-ed25519`'s round-1/round-2
  message types. Pro: stays in the audited Rust FROST crate; one binary per
  scheme in its native language. Con: re-implements the whole `net/` layer (TLS,
  PKI, handshake, framing, FIN barrier, adversarial tests) a second time in a
  second language — large surface, easy to drift from the Go version's
  guarantees.
- **Option F2 — FROST in Go, reuse `kobe-ecdsa/net` verbatim.** Swap the GG20
  party for a Go FROST implementation (e.g. taurus `multi-party-sig`, Go) behind
  the SAME `RunKeygen`/`RunSign` shape, so the existing transport, mTLS/PKI,
  identifiable-abort plumbing and adversarial tests are reused unchanged. Pro: one
  hardened transport for both schemes; all M8–M11 work applies immediately. Con:
  changes the FROST library from the ZF Rust reference to a Go one (a new audited
  dependency to vet), and FROST's identifiable-abort story differs from GG20's.
- **Option F3 — defer.** Ship GG20 (EVM/BTC/Tron — the harder, flagship ECDSA
  path) networked-and-hardened now; keep FROST in-process until a chain that needs
  it (SVM/Cosmos Schnorr) is actually targeted. Pro: no duplicated transport, no
  new dependency, focus stays on the verified path. Con: SVM/Cosmos signing is not
  yet networked.

### Decision — F1, but as an FFI variant (chosen and justified, not a toss-up)

DISTIN launches on **Solana**, so the FROST/Ed25519 path is a real value-bearing
path, not a someday. It is now networked + hardened. The fork was decided **F1**,
and the decision was forced by what is actually available — not a coin flip:

**F2 was evaluated first (as instructed) and REJECTED on its own gating
condition** ("you must vet the Go FROST lib is trustworthy"). The Go FROST-Ed25519
landscape:

- **taurus `multi-party-sig`** (the maintained taurus lib): its FROST is
  **secp256k1 / Taproot-Schnorr only — no Ed25519.** Unusable for Solana.
- **taurus `frost-ed25519`** (the one Go lib that does Ed25519): the repo's own
  README says *"This library has yet to be audited and fully vetted for production
  usage. Use at your own risk,"* it is **explicitly NOT side-channel-free**, and it
  has a **single v0.1 release dated March 2021** (unmaintained for ~5 years).

Swapping the **NCC-Group-audited** ZF Rust `frost-ed25519` (the RFC 9591 ciphersuite
`FROST(Ed25519, SHA-512)`, audited at v0.6.0) for an unaudited, side-channel-leaky,
abandoned Go library — to custody real Solana keys — would be a **downgrade in
crypto provenance**, directly against the campaign rule *"never roll your own
crypto / wrap audited, battle-tested libraries."* So F2 fails.

**Chosen: F1, FFI variant.** Classic F1 ("rebuild TLS/PKI/handshake in Rust")
duplicates the entire hardened `net/` layer in a second language — large surface,
easy to drift. We avoid that: the existing Go transport is **byte-transparent**
(`Network.Broadcast([]byte)` / `SendTo(idx,[]byte)` / `Inbox()→Envelope.Payload`;
it never parsed tss-lib), so we keep the hardened Go transport **verbatim** and
drive the **audited ZF Rust crate** over a thin C ABI:

- `engine/kobe/src/ffi.rs` — a `cdylib` exposing the audited crate's real DKG
  (`dkg::part1/2/3`, no trusted dealer), signing (`round1`/`round2`/`aggregate`),
  and serialization. Every function is **pure** (bytes in, bytes out, no state),
  so all secret material round-trips as opaque blobs the Go operator owns. The
  aggregate is re-verified under `ed25519-dalek` **inside the FFI** before it ever
  leaves the process.
- `engine/kobe-ecdsa/net/frost_ffi.go` — the CGO binding to that ABI.
- `engine/kobe-ecdsa/net/frost.go` — `RunFrostKeygen` / `RunFrostSign`, mirroring
  the GG20 `protocol.go` shape but routing FROST round bytes over the **SAME**
  `Network`: mutual TLS + operator-set PKI + per-operator pin + identity-key
  envelopes + the FIN barrier. **Zero new crypto, zero duplicated transport.**
- `engine/kobe-ecdsa/cmd/frost-operator` — the per-process operator binary;
  `engine/kobe-ecdsa/net/frost_demo.sh` — the N-separate-process demo.

**Net result: ALL M8–M10 hardening applies to FROST unchanged** — mutual
TLS/PKI/pinning (M8), and encrypted-at-rest shares (M10, the FROST `KeyPackage`
sealed with the same AES-256-GCM + Argon2id envelope via
`SaveFrostShareEncrypted`).

**FROST's abort story (documented honestly — it differs from GG20's).** FROST is
**fail-stop with share-level attribution**, not GG20's multi-round identifiable
abort. There is no Paillier/MtA ZK transcript to pin a cheater across rounds;
instead the **aggregator's `frost::aggregate` verifies each signature share
against that signer's public verifying share**, and a bad share names its signer
(`Error::InvalidSignatureShare{culprits}`). `RunFrostSign` surfaces that as a
`*FrostCulpritError{Operator}`. This is **non-anonymous** (the cheater is named)
but its mechanism differs from GG20's. A drop / garbage / stall is handled by the
SAME transport machinery as GG20 (clean, non-hanging abort; the bad share never
aggregates into a forged signature).

**FROST is now on-chain-slashable too (M11-Part-3), reusing M9 unchanged.** The
share-level detection is **not** aggregator-only: signature shares are broadcast in
round 2, so EVERY honest quorum member holds the same public inputs (msg,
commitments, shares, group `PublicKeyPackage`) the aggregator does, and
`frost::aggregate`'s per-share verification is a deterministic function of them.
`RunFrostSign` therefore runs that verification on every quorum member, so each
honest operator independently reaches the SAME `*FrostCulpritError` — exactly the
honest-majority attribution GG20 gets from its failed ZK proof. Each honest
operator turns that into the canonical M9 `FaultReport` (`FrostFaultReport` in
`net/fault.go`) and signs it with its pinned Ed25519 identity key. The report uses
a **distinct session/round tag** (`SessionFrostSign = "distin-frost-sign"`,
`FaultRoundFrostShare = 1001`) hashed into the SAME digest the on-chain program
reconstructs, so a FROST fault can never collide with or be replayed as a GG20 one.
The on-chain `slash_operator_attested` is **scheme-agnostic** (it treats
`session`/`round` as opaque digest inputs), so it consumes the FROST bundle
**unchanged — no fork, no new instruction**. The existing `cmd/fault-verify`
collector assembles the m-of-n bundle for FROST with zero changes.

**Verified artifacts (real, pasted in the campaign report — not "it compiles"):**

1. `net/frost_test.go::TestFrostMutualTLSDKGAndSignVerifies` — 3 operators run a
   REAL FROST DKG + a 2-of-3 sign over mutual TLS; the aggregate verifies under Go's
   INDEPENDENT `crypto/ed25519` (the RFC 8032 primitive Solana checks) against the
   group key; a wrong message is rejected. **PASS.**
2. `net/frost_test.go::TestFrostIdentifiableAbort` — a quorum member contributes an
   INVALID signature share; **every** honest quorum member (aggregator AND
   non-aggregator) independently names that exact operator, signs the canonical M9
   `FaultReport`, and the 2-of-3 honest bundle assembles while a 1-of-3 minority is
   rejected. Run under `-race`. **PASS.**
3. `tests-litesvm::frost_fault_quorum_slashes_culprit_and_rejects_minority` — a REAL
   SVM transaction submits the FROST attestation bundle to `slash_operator_attested`;
   the culprit's **bond actually MOVES** (vault 15→12, slash_pool 0→3 tokens), a
   single attester is rejected (`ThresholdNotMet`), and a GG20-tagged bundle is
   rejected under FROST tags (no cross-scheme replay). **PASS.**
4. `net/frost_demo.sh` — the honest signing path over **3 SEPARATE OS processes**
   (distinct PIDs/ports/identity keys, each share ENCRYPTED at rest), plus the
   adversarial set: an UNTRUSTED-CA operator rejected at the mutual-TLS handshake,
   a peer offline → clean abort, and a misbehaving operator → identifiable abort.
5. `net/frost_fault_demo.sh` — the FULL FROST fault→slash path over **3 SEPARATE OS
   processes** over mTLS: op2 broadcasts a tampered share, op0 + op1 independently
   attest, and `fault-verify` assembles the on-chain m-of-n bundle (FROST-tagged
   digest + Ed25519 native-program instruction data); a single attester is rejected.
6. `engine/kobe`'s existing Rust tests still PASS — the FFI memory-ownership fix did
   not regress the in-process path.

**Still PoC / next production steps (called out plainly):**

- The Go↔Rust seam is **CGO/FFI in one host**, not separate-language services; the
  crypto is audited but the FFI glue (`ffi.rs` + `frost_ffi.go`) is new code. It was
  reviewed this milestone: the Rust→Go buffer ownership was hardened to transfer via
  `Box<[u8]>` (guaranteed `cap == len`) instead of relying on `shrink_to_fit`, which
  is permitted to leave `cap > len` and would make `frost_free`'s
  `from_raw_parts(ptr, len, len)` deallocate with the wrong layout (UB). The item
  framing and error-path buffer hygiene (every out-buf is null on an error return;
  the two `ok()` writes are back-to-back with no fallible op between them, so there
  is no partial-success leak) were audited and are sound.
- Localhost addressing, static enrolment, no revocation — the SAME M8 caveats as
  GG20 (the transport is literally shared), not new ones.
- The crate's `KeyPackage` holds the decrypted share in process RAM during signing;
  HSM/enclave binding is the noted higher tier (same as GG20 M10).

This does not touch the on-chain program (scheme-agnostic) and does not weaken the
GG20 path — the transport is shared, so GG20's M8–M11 artifacts are unchanged.

---

## M12 — Mainnet deploy-readiness — **DONE (prepared, not deployed)**

- **Slash integration test (the prior milestone's open gap) — CLOSED.** The M9
  attested slash is now executed inside a real SVM transaction by a litesvm suite
  (`engine/tests-litesvm`): operators register WITH bonded Token-2022 collateral,
  a real m-of-n Ed25519 native instruction over the byte-identical fault digest is
  submitted alongside `slash_operator_attested`, and the test ASSERTS the culprit
  bond actually moves vault→slash-pool + jail, while minority / wrong-digest /
  duplicate-key bundles are rejected on-chain. The test crate is its own workspace
  (own lock), so it does not perturb the program's SBF build lock.
- **Adversarial re-read found and FIXED one real bug:** the attester dedup keyed
  on the operator PDA, letting a single signature under a duplicated
  `attestation_pubkey` count multiple times; now deduped on the signed key. See
  `SECURITY.md`.
- **Build/lint/audit:** `cargo-build-sbf` clean on the 3.1.10 toolchain
  (rustc 1.89, platform-tools v1.52); `cargo clippy -- -D warnings` clean;
  `cargo audit` 0 vulnerabilities (3 transitive warning-level advisories only).
- **Deploy artifacts:** `Anchor.toml` mainnet cluster wired (+ a commented
  `[provider.mainnet]` for the multisig authority), `deploy.sh` (reproducible
  build + gated mainnet deploy + multisig-authority guidance), and `DEPLOY.md`
  (exact commands, ~7.2 SOL for program+ProgramData at default 2x headroom /
  ~3.6 SOL exact, the program-keypair note, and upgrade-authority = Squads
  multisig, not a hot key). **Not deployed — that is the operator's step.**

---

## Audit

A third-party security audit of both the on-chain program and the off-chain core
remains the operator's separate risk call (per `core.verified`). It is NOT a
blocker for this hardening campaign, but no real value should touch the code
until it is done.
