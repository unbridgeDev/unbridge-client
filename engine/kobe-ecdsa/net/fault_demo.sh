#!/usr/bin/env bash
# M9 identifiable-abort end-to-end demo over SEPARATE OS processes (mutual TLS).
#
#   cd engine/kobe-ecdsa && ./net/fault_demo.sh
#
# 1. 3 operator processes run a real GG20 DKG over mutual TLS.
# 2. A 3-of-3 sign is attempted in which op2 MISBEHAVES (corrupts its round-2 MtA
#    proof). GG20's own cryptography (tss-lib Culprits) makes the two HONEST
#    operators (op0, op1) identify op2 as the culprit; each emits an Ed25519
#    signed fault attestation.
# 3. `fault-verify` collects the m-of-n attestations, confirms the quorum agrees
#    on the SAME culprit, prints the 32-byte fault-report digest, and builds the
#    Ed25519 native-program instruction data the relayer attaches on-chain to
#    `slash_operator_attested` — which slashes exactly op2.
# 4. NEGATIVE: a single attestation does NOT reach the 2-of-3 quorum, so a
#    minority cannot slash an operator.
#
# Localhost only; touches no devnet, no on-chain program (the on-chain consumer is
# verified separately by the program's Rust unit tests).
set -euo pipefail
cd "$(dirname "$0")/.."

WORK="$(mktemp -d /tmp/distin-m9.XXXXXX)"
BIN="$WORK/bin"; OPS="$WORK/operators"; LOG="$WORK/logs"; OUT="$WORK/out"
mkdir -p "$BIN" "$OPS" "$LOG" "$OUT"
HASH="a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00"

echo "### building binaries"
go build -o "$BIN/operator" ./cmd/operator
go build -o "$BIN/gen-operators" ./cmd/gen-operators
go build -o "$BIN/fault-verify" ./cmd/fault-verify

echo; echo "### minting 3 operator identities + operator-set CA (mutual TLS)"
"$BIN/gen-operators" -n 3 -base-port 9300 -dir "$OPS" -tls >/dev/null

echo; echo "### PHASE 1: GG20 distributed key generation (3 processes, mutual TLS)"
for i in 2 1 0; do
  "$BIN/operator" -config "$OPS/op$i.json" -phase keygen -threshold 2 -timeout 300s \
    >"$OUT/kg$i.json" 2>"$LOG/kg$i.log" &
done
wait
echo "group address agreed by all 3 operators:"
for i in 0 1 2; do echo "  op$i: $(grep -o '"group_eth_address":"[^"]*"' "$OUT/kg$i.json")"; done

echo; echo "### PHASE 2: 3-of-3 sign with op2 MISBEHAVING (induced identifiable abort)"
echo "message hash: $HASH"
"$BIN/operator" -config "$OPS/op2.json" -phase sign -quorum 0,1,2 -hash "$HASH" -threshold 2 -misbehave -timeout 120s \
  >"$OUT/sg2.json" 2>"$LOG/sg2.log" &
"$BIN/operator" -config "$OPS/op1.json" -phase sign -quorum 0,1,2 -hash "$HASH" -threshold 2 -timeout 120s \
  >"$OUT/sg1.json" 2>"$LOG/sg1.log" &
"$BIN/operator" -config "$OPS/op0.json" -phase sign -quorum 0,1,2 -hash "$HASH" -threshold 2 -timeout 120s \
  >"$OUT/sg0.json" 2>"$LOG/sg0.log" &
wait

echo "honest operators' identifiable-abort log lines:"
grep -h "identifiable abort" "$LOG/sg0.log" "$LOG/sg1.log" || true
echo "honest operators' emitted attestations (culprit naming):"
for i in 0 1; do echo "  op$i: $(grep -o '"fault":true' "$OUT/sg$i.json" >/dev/null && echo "fault culprit=$(grep -o '"culprit_global":[0-9]*' "$OUT/sg$i.json")" || echo "(no fault)")"; done

echo; echo "### PHASE 3: relayer collects the m-of-n bundle → on-chain slash payload"
"$BIN/fault-verify" -need 2 -in "$OUT/sg0.json" -in "$OUT/sg1.json"

echo; echo "### NEGATIVE: a single attestation must NOT reach the 2-of-3 slash quorum"
set +e
"$BIN/fault-verify" -need 2 -in "$OUT/sg0.json" >/dev/null 2>"$LOG/neg.log"
echo "fault-verify exit with one attester: $?  (nonzero = minority correctly rejected)"
cat "$LOG/neg.log"
set -e

echo; echo "### DONE — work dir: $WORK"
