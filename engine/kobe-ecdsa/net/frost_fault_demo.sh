#!/usr/bin/env bash
# FROST identifiable-abort → on-chain-slash demo over SEPARATE OS processes (mTLS).
# The FROST counterpart to net/fault_demo.sh (GG20). It closes the campaign's last
# gap: a misbehaving FROST operator is now economically punishable on-chain through
# the SAME `slash_operator_attested` instruction GG20 uses — no fork.
#
#   cd engine/kobe-ecdsa && ./net/frost_fault_demo.sh
#
# 1. 3 frost-operator processes run a real FROST-Ed25519 DKG over mutual TLS
#    (audited ZF frost-ed25519 crate over the C ABI; same hardened transport as
#    GG20).
# 2. A 3-of-3 sign in which op2 MISBEHAVES (broadcasts a tampered signature share).
#    EVERY honest operator (op0 + op1) independently runs frost::aggregate's
#    per-share verification over the broadcast shares, names op2 as the culprit,
#    and emits an Ed25519-signed fault attestation — the same m-of-n attestation
#    GG20 produces from its failed ZK proof.
# 3. `fault-verify` collects the m-of-n attestations, confirms the quorum agrees on
#    the SAME culprit, prints the 32-byte fault-report digest, and builds the
#    Ed25519 native-program instruction data the relayer attaches on-chain to
#    `slash_operator_attested`. The fault carries the FROST tags
#    (session "distin-frost-sign", round 1001) so it can never be confused with a
#    GG20 report. The matching REAL-SVM slash (bond actually moves, minority
#    rejected) is in engine/tests-litesvm `frost_fault_quorum_slashes_culprit_*`.
# 4. NEGATIVE: a single attestation does NOT reach the 2-of-3 quorum.
#
# Localhost only; touches no devnet.
set -euo pipefail
cd "$(dirname "$0")/.."

ROOT="$(cd ../kobe && pwd)"
DYLIB="$ROOT/target/release"
if [ ! -f "$DYLIB/libkobe.dylib" ] && [ ! -f "$DYLIB/libkobe.so" ]; then
  echo "building the audited FROST cdylib (engine/kobe)…"
  ( cd "$ROOT" && cargo build --release >/dev/null 2>&1 )
fi
export CGO_ENABLED=1
export CGO_LDFLAGS="-L$DYLIB -lkobe -Wl,-rpath,$DYLIB"
export DYLD_LIBRARY_PATH="$DYLIB:${DYLD_LIBRARY_PATH:-}"
export LD_LIBRARY_PATH="$DYLIB:${LD_LIBRARY_PATH:-}"
export DISTIN_SHARE_PASSPHRASE="demo-operator-passphrase-not-for-prod"

WORK="$(mktemp -d /tmp/distin-frost-m9.XXXXXX)"
BIN="$WORK/bin"; OPS="$WORK/operators"; LOG="$WORK/logs"; OUT="$WORK/out"
mkdir -p "$BIN" "$OPS" "$LOG" "$OUT"
MSG="a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00"

echo "### building frost-operator + gen-operators + fault-verify"
go build -o "$BIN/frost-operator" ./cmd/frost-operator
go build -o "$BIN/gen-operators" ./cmd/gen-operators
go build -o "$BIN/fault-verify" ./cmd/fault-verify

echo; echo "### minting 3 operator identities + operator-set CA (mutual TLS)"
"$BIN/gen-operators" -n 3 -base-port 9300 -dir "$OPS" -tls >/dev/null

echo; echo "### PHASE 1: FROST distributed key generation (3 processes, mutual TLS)"
for i in 2 1 0; do
  "$BIN/frost-operator" -config "$OPS/op$i.json" -phase keygen -timeout 120s \
    >"$OUT/kg$i.json" 2>"$LOG/kg$i.log" &
done
wait
echo "group pubkey agreed by all 3 operators:"
for i in 0 1 2; do echo "  op$i: $(grep -o '"group_pubkey":"[0-9a-f]*"' "$OUT/kg$i.json")"; done

echo; echo "### PHASE 2: 3-of-3 sign with op2 MISBEHAVING (tampered signature share)"
echo "message (32B): $MSG"
"$BIN/frost-operator" -config "$OPS/op2.json" -phase sign -quorum 0,1,2 -msg "$MSG" -aggregator 0 -misbehave -timeout 60s \
  >"$OUT/sg2.json" 2>"$LOG/sg2.log" &
"$BIN/frost-operator" -config "$OPS/op1.json" -phase sign -quorum 0,1,2 -msg "$MSG" -aggregator 0 -timeout 60s \
  >"$OUT/sg1.json" 2>"$LOG/sg1.log" &
"$BIN/frost-operator" -config "$OPS/op0.json" -phase sign -quorum 0,1,2 -msg "$MSG" -aggregator 0 -timeout 60s \
  >"$OUT/sg0.json" 2>"$LOG/sg0.log" &
wait

echo "honest operators' identifiable-abort log lines (each named the culprit independently):"
grep -h "identifiable abort" "$LOG/sg0.log" "$LOG/sg1.log" || true
echo "honest operators' emitted attestations:"
for i in 0 1; do
  echo "  op$i: $(grep -o '"fault":true' "$OUT/sg$i.json" >/dev/null && echo "fault $(grep -o '"culprit_global":[0-9]*' "$OUT/sg$i.json")" || echo "(no fault)")"
done

echo; echo "### PHASE 3: relayer collects the m-of-n bundle → on-chain slash payload"
"$BIN/fault-verify" -need 2 -in "$OUT/sg0.json" -in "$OUT/sg1.json"

echo; echo "### NEGATIVE: a single attestation must NOT reach the 2-of-3 slash quorum"
set +e
"$BIN/fault-verify" -need 2 -in "$OUT/sg0.json" >/dev/null 2>"$LOG/neg.log"
echo "fault-verify exit with one attester: $?  (nonzero = minority correctly rejected)"
cat "$LOG/neg.log"
set -e

echo; echo "### DONE — work dir: $WORK"
