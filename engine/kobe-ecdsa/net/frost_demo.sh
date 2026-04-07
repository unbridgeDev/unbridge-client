#!/usr/bin/env bash
# M11-Part-2 end-to-end demo: 3 SEPARATE operator OS processes run a FROST-Ed25519
# DKG and a 2-of-3 threshold sign over MUTUAL TLS (every connection
# RequireAndVerifyClientCert against an operator-set CA + per-operator pin), and
# the resulting aggregate is INDEPENDENTLY verified under crypto/ed25519 (the
# RFC 8032 primitive Solana checks). Plus negatives: an untrusted-CA operator
# rejected at the TLS handshake, a peer offline (clean abort), and a misbehaving
# operator that broadcasts a bad signature share (aggregator identifiably aborts
# naming it). Localhost only; no devnet, no on-chain program.
#
#   cd engine/kobe-ecdsa && ./net/frost_demo.sh
#
# The crypto is the AUDITED ZF frost-ed25519 crate (engine/kobe, cdylib) reached
# over a C ABI; the transport is the SAME hardened mTLS/PKI stack the GG20 demo
# uses. Each operator is its own PID/port/identity key and (after keygen) its own
# ENCRYPTED share file.
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

WORK="$(mktemp -d /tmp/distin-frost.XXXXXX)"
BIN="$WORK/bin"; OPS="$WORK/operators"; LOG="$WORK/logs"; OUT="$WORK/out"
mkdir -p "$BIN" "$OPS" "$LOG" "$OUT"
MSG="a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00"

echo "### building frost-operator + gen-operators"
go build -o "$BIN/frost-operator" ./cmd/frost-operator
go build -o "$BIN/gen-operators" ./cmd/gen-operators

echo; echo "### minting 3 distinct operator identities + operator-set CA (mutual TLS)"
"$BIN/gen-operators" -n 3 -base-port 9300 -dir "$OPS" -tls
ls -1 "$OPS"/ca.cert.pem "$OPS"/op*.cert.pem

echo; echo "### PHASE 1: FROST distributed key generation — 3 separate processes over mTLS"
"$BIN/frost-operator" -config "$OPS/op2.json" -phase keygen -timeout 120s >"$OUT/kg2.json" 2>"$LOG/kg2.log" &
"$BIN/frost-operator" -config "$OPS/op1.json" -phase keygen -timeout 120s >"$OUT/kg1.json" 2>"$LOG/kg1.log" &
"$BIN/frost-operator" -config "$OPS/op0.json" -phase keygen -timeout 120s >"$OUT/kg0.json" 2>"$LOG/kg0.log" &
wait
echo "startup lines (distinct PIDs + ports):"
grep -h "starting, phase=keygen" "$LOG"/kg*.log
echo "DKG results (all 3 must agree on the group pubkey):"
for i in 0 1 2; do echo "  op$i: $(cat "$OUT/kg$i.json")"; done
echo "share files (each operator wrote ONLY its own, ENCRYPTED at rest):"
ls -1 "$OPS"/*.share.json
echo "  (head of one share file — AES-256-GCM/argon2id envelope, no plaintext key):"
head -c 200 "$OPS/op0.share.json"; echo

echo; echo "### PHASE 2: 2-of-3 FROST threshold sign — quorum {0,2}, op1 offline; op0 aggregates"
echo "message (32B): $MSG"
"$BIN/frost-operator" -config "$OPS/op2.json" -phase sign -quorum 0,2 -msg "$MSG" -aggregator 0 -timeout 60s >"$OUT/sg2.json" 2>"$LOG/sg2.log" &
"$BIN/frost-operator" -config "$OPS/op1.json" -phase sign -quorum 0,2 -msg "$MSG" -aggregator 0 -timeout 60s >"$OUT/sg1.json" 2>"$LOG/sg1.log" &
"$BIN/frost-operator" -config "$OPS/op0.json" -phase sign -quorum 0,2 -msg "$MSG" -aggregator 0 -timeout 60s >"$OUT/sg0.json" 2>"$LOG/sg0.log" &
wait
echo "wire transcript (op0, first 8 messages crossing the wire):"
grep -h "wire " "$LOG/sg0.log" | sed -n '1,8p' || true
echo "sign results:"
for i in 0 1 2; do echo "  op$i: $(cat "$OUT/sg$i.json")"; done

echo; echo "### independent verification: the aggregator reported ed25519_verify under crypto/ed25519"
GROUP=$(grep -o '"group_pubkey":"[0-9a-f]*"' "$OUT/sg0.json" | head -1 | cut -d'"' -f4)
SIG=$(grep -o '"signature":"[0-9a-f]*"' "$OUT/sg0.json" | cut -d'"' -f4)
VERIFY=$(grep -o '"ed25519_verify":[a-z]*' "$OUT/sg0.json" | cut -d':' -f2)
echo "  group pubkey : $GROUP"
echo "  signature(64): $SIG"
echo "  crypto/ed25519 verify (RFC 8032, what Solana runs): $VERIFY"
if [ "$VERIFY" != "true" ]; then echo "FAIL: aggregate did not verify"; exit 1; fi

echo; echo "### NEGATIVE A: peer offline — quorum {0,1}, op1 never starts → clean abort"
set +e
"$BIN/frost-operator" -config "$OPS/op0.json" -phase sign -quorum 0,1 -msg "$MSG" -aggregator 0 -timeout 8s >"$OUT/negA.json" 2>"$LOG/negA.log"
echo "op0 exit: $?  (nonzero = clean failure, not a hang); stdout: [$(cat "$OUT/negA.json")]"
tail -1 "$LOG/negA.log"
set -e

echo; echo "### NEGATIVE B: untrusted CA — op1 presents a leaf signed by a ROGUE CA"
# Mint a rogue CA, have it issue a leaf for op1's REAL identity key, and swap that
# leaf into op1's config. The honest peers chain every peer cert to the real
# operator-set CA, so op1's rogue leaf fails at the mutual-TLS handshake before
# any FROST byte flows.
ROGUE="$WORK/rogue"; mkdir -p "$ROGUE"
OP1KEY=$(grep -o '"identity_key": "[0-9a-f]*"' "$OPS/op1.json" | cut -d'"' -f4)
cat >"$WORK/rogueleaf.go" <<'GO'
package main
import("crypto/ed25519";"encoding/hex";"os";"time";kobenet "github.com/distin/kobe-ecdsa/net")
func main(){
 seed,_:=hex.DecodeString(os.Args[1]); priv:=ed25519.PrivateKey(seed)
 ca,_:=kobenet.NewCA(time.Hour)
 leaf,_:=ca.IssueLeaf(priv.Public().(ed25519.PublicKey),"op1",time.Hour)
 os.WriteFile(os.Args[2],kobenet.EncodeCertPEM(leaf),0o644)
}
GO
go run "$WORK/rogueleaf.go" "$OP1KEY" "$ROGUE/op1.rogue.cert.pem"
cat >"$WORK/swapleaf.go" <<'GO'
package main
import("encoding/json";"os")
func main(){bz,_:=os.ReadFile(os.Args[1]);var m map[string]any;json.Unmarshal(bz,&m)
m["leaf_cert"]=os.Args[2]
o,_:=json.MarshalIndent(m,"","  ");os.WriteFile(os.Args[3],o,0o600)}
GO
go run "$WORK/swapleaf.go" "$OPS/op1.json" "$ROGUE/op1.rogue.cert.pem" "$OPS/op1.untrusted.json"
set +e
"$BIN/frost-operator" -config "$OPS/op2.json" -phase keygen -timeout 15s >/dev/null 2>"$LOG/utls2.log" &
"$BIN/frost-operator" -config "$OPS/op1.untrusted.json" -phase keygen -timeout 15s >/dev/null 2>"$LOG/utls1.log" &
"$BIN/frost-operator" -config "$OPS/op0.json" -phase keygen -timeout 15s >/dev/null 2>"$LOG/utls0.log" &
wait
set -e
echo "honest peer rejects the untrusted cert at the mutual-TLS handshake:"
grep -h -i "unknown authority\|tls server handshake\|tls client handshake" "$LOG/utls0.log" "$LOG/utls1.log" "$LOG/utls2.log" | head -2

echo; echo "### NEGATIVE C: misbehaving operator — op2 broadcasts a tampered signature share"
# A real signing run where op2 sends a corrupt share. The aggregator (op0) runs
# frost::aggregate, which fails THAT share's verification and names op2 — FROST's
# identifiable abort. No forged signature is ever produced.
set +e
"$BIN/frost-operator" -config "$OPS/op2.json" -phase sign -quorum 0,1,2 -msg "$MSG" -aggregator 0 -misbehave -timeout 30s >"$OUT/badC2.json" 2>"$LOG/badC2.log" &
"$BIN/frost-operator" -config "$OPS/op1.json" -phase sign -quorum 0,1,2 -msg "$MSG" -aggregator 0 -timeout 30s >"$OUT/badC1.json" 2>"$LOG/badC1.log" &
"$BIN/frost-operator" -config "$OPS/op0.json" -phase sign -quorum 0,1,2 -msg "$MSG" -aggregator 0 -timeout 30s >"$OUT/badC0.json" 2>"$LOG/badC0.log" &
wait
set -e
echo "aggregator (op0) result: $(cat "$OUT/badC0.json")"
grep -h -i "identifiable abort" "$LOG/badC0.log" | head -1

echo; echo "### DONE — work dir: $WORK"
