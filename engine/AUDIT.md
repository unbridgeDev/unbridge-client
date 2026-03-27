# Engine Security Audit (solana)

Result: **PASS** (0 high/medium open)

- `cargo clippy --all-targets -- -D warnings`: clean (program + litesvm test crate)
- `cargo test`: 16 unit tests passing (share validation, threshold/overflow math,
  M9 fault-digest vector + Ed25519 parser + attester math)
- `engine/tests-litesvm`: 2 integration tests passing — the M9 attested slash run
  in real SVM transactions (bond actually moves vault→slash-pool; minority,
  wrong-digest, and duplicate-attestation-key bundles rejected on-chain)
- `cargo audit`: 0 vulnerabilities (3 transitive warning-level advisories, not per-project fixable)

Findings fixed this pass (see `SECURITY.md` for the full threat model):
- HIGH (M12): `slash_operator_attested` deduped attesters by operator PDA, so a
  single Ed25519 signature under a duplicated `attestation_pubkey` (two operator
  accounts sharing one key) counted multiple times toward the quorum — reaching
  the slash threshold with fewer distinct witnesses than required. Found by the
  new litesvm test; fixed by deduping on the signed attestation key. The bond no
  longer moves for a double-counted single signature.
- (prior pass) HIGH: `cancel_request` could be called by anyone on any pending
  request (free griefing) — now requires `has_one = requester`; foreign requests
  are only closable once expired.
- (prior pass) CLEANUP: removed unreachable `SchemeMismatch` error code (error
  count 22 → 21). LINT: `manual_range_contains`, `needless_range_loop` resolved.

NOTE: the dedup fix alters program bytecode → rebuild (`cargo-build-sbf`) and
re-deploy to take effect; the localnet `target/deploy/distin.so` was rebuilt.
