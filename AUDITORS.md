# External audit — researched firm shortlist (2026-07)

Companion to `AUDIT_SCOPE.md`. Distin needs two competences that rarely live in
one firm: (A) Solana/Anchor program review, (B) threshold-cryptography /
MPC implementation review (FROST Ed25519 + GG20 ECDSA, Rust + Go + cgo
boundary). The recommended shape is a **two-track engagement** — one firm per
track — or a single firm only if it can staff both.

## Track A — Solana program (Anchor)

Per the 2025 empirical review of 163 multi-auditor Solana security reviews,
the active specialist firms are Sec3, Neodyme, OtterSec, Zellic, Pashov,
Offside Labs, Zenith, and Accretion. Strongest general reputations for
Anchor-program work:

| Firm | Why relevant to Distin |
|---|---|
| **OtterSec** | The default Solana auditor (Jupiter, Drift, Marinade lineage); deep Anchor account-model experience — exactly invariant 4 (layout preservation) territory. |
| **Neodyme** | Solana-core security lineage; strongest at runtime/account-model edge cases (weight accounting, PDA authority, Token-2022 vault flows). |
| **Zellic** | Cross-chain protocol experience — useful because Distin's product surface is cross-chain intents. |
| **Sec3 / Offside Labs / Accretion / Zenith** | Credible alternatives if lead choices are booked out. |

## Track B — threshold crypto / MPC layer

| Firm | Why relevant to Distin |
|---|---|
| **NCC Group** | Audited the exact FROST crates Distin wraps (Zcash Foundation frost, 2023, incl. DKG + signing). Reviewing `kobe`'s wrapper + serialization + C ABI against the crate they know is the highest-leverage pairing. |
| **Kudelski Security** | Audited Binance tss-lib itself (2019, v1.0.0) — the GG20 engine Distin drives from Go. |
| **Verichains** | Discovered TSSHOCK (key-extraction attacks on TSS implementations); the right adversarial eyes for the GG20 integration and share handling. |
| **Trail of Bits** | Audited tBTC's threshold-ECDSA (tss-lib fork); broad crypto+systems depth, strong on the Rust/Go/cgo boundary class of bugs. |

## Specific questions the audit must answer (beyond AUDIT_SCOPE invariants)

1. **tss-lib version vs. known TSS attacks.** Distin vendors tss-lib v2.0.2.
   Confirm this includes the CVE-2023-33241 (GG18/GG20 Paillier proof) fixes
   (landed in v2.0.0) and assess exposure to TSSHOCK-class implementation
   leaks. Context: a May 2026 THORChain drain (~$10.7M) was attributed to an
   old TSS-vulnerability class — this is an active exploitation area, not a
   theoretical one.
2. **cgo boundary**: the Go operators reach the audited Rust FROST cdylib over
   a C ABI (`kobe`'s FFI + `net/frost_ffi.go`). Memory ownership, error
   propagation, and share zeroization across that boundary.
3. **Share-at-rest envelopes**: AES-256-GCM/argon2id (Go side) and
   ChaCha20-Poly1305/Argon2id `DSTNK1` (Rust side) — parameter choices, nonce
   handling, and the fail-closed properties (unit-tested, but audit-grade
   review wanted).
4. **DKG transcript binding**: both DKGs run over the mTLS mesh — verify a
   malicious minority cannot bias or grind the group key.

## Engagement notes

- Audit ref: pin the commit recorded in `AUDIT_SCOPE.md` (deployed lineage —
  NOT repo HEAD; see the CRITICAL section there).
- The devnet deployment + signerd daemon give auditors a live reproduction
  environment; `frost_demo.sh` and the request/request-gg20 CLI reproduce
  every ceremony offline.
- Budget anchor: the ZF FROST assessment was 25 person-days for the crypto
  core alone; Distin's two tracks together are plausibly 4–8 person-weeks.

Sources: [Solana Security Ecosystem Review 2025 (SSRN)](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=6552478),
[NCC Group — Zcash FROST Security Assessment](https://www.nccgroup.com/research-blog/public-report-zcash-frost-security-assessment/),
[Binance tss-lib (Kudelski audit, v1.0.0 notes)](https://github.com/bnb-chain/tss-lib),
[Verichains — TSSHOCK](https://verichains.io/tsshock/),
[Fireblocks — GG18/GG20 Paillier CVE-2023-33241](https://www.fireblocks.com/blog/gg18-and-gg20-paillier-key-vulnerability-technical-report),
[THORChain May-2026 exploit coverage](https://www.theopensourcepress.com/thorchain-vault-exploit-may-2026/).
