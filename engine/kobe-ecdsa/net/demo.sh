#!/usr/bin/env bash
# Milestone 6+8 end-to-end demo: 3 SEPARATE operator processes run a GG20 DKG and
# a 2-of-3 threshold sign over MUTUAL TLS (M8: every connection is
# RequireAndVerifyClientCert against an operator-set CA + per-operator pin), and
# the resulting signature is INDEPENDENTLY verified (go-ethereum ecrecover, in a
# process that shares nothing with the operators). Plus negative cases: a peer
# killed mid-protocol (clean abort), a spoofed identity key (handshake
# rejection), and an operator presenting a cert from an UNTRUSTED CA (TLS
# handshake rejection). Localhost only; touches no devnet, no on-chain program.
#
#   cd engine/kobe-ecdsa && ./net/demo.sh
#
# Each operator is its OWN os process (distinct PID, port, identity key, and —
# after keygen — its own single share file). Watch the [opN pid=… port=…] log
# prefixes and the "wire ►/◄" lines to see messages cross the wire.
set -euo pipefail
cd "$(dirname "$0")/.."

WORK="$(mktemp -d /tmp/distin-m6.XXXXXX)"
BIN="$WORK/bin"; OPS="$WORK/operators"; LOG="$WORK/logs"; OUT="$WORK/out"
mkdir -p "$BIN" "$OPS" "$LOG" "$OUT"
HASH="a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00"

echo "### building operator binaries"
go build -o "$BIN/operator" ./cmd/operator
go build -o "$BIN/gen-operators" ./cmd/gen-operators
go build -o "$BIN/verify-sig" ./cmd/verify-sig

echo; echo "### minting 3 distinct operator identities + an operator-set CA (mutual TLS)"
"$BIN/gen-operators" -n 3 -base-port 9100 -dir "$OPS" -tls
echo "operator-set PKI written:"; ls -1 "$OPS"/ca.cert.pem "$OPS"/op*.cert.pem

echo; echo "### PHASE 1: distributed key generation — 3 separate processes over TCP"
"$BIN/operator" -config "$OPS/op2.json" -phase keygen -threshold 1 -timeout 300s >"$OUT/kg2.json" 2>"$LOG/kg2.log" &
"$BIN/operator" -config "$OPS/op1.json" -phase keygen -threshold 1 -timeout 300s >"$OUT/kg1.json" 2>"$LOG/kg1.log" &
"$BIN/operator" -config "$OPS/op0.json" -phase keygen -threshold 1 -timeout 300s >"$OUT/kg0.json" 2>"$LOG/kg0.log" &
wait
echo "startup lines (distinct PIDs + ports):"
grep -h "starting, phase=keygen" "$LOG"/kg*.log
echo "DKG results (all 3 must agree on the group address):"
for i in 0 1 2; do echo "  op$i: $(cat "$OUT/kg$i.json")"; done
echo "share files (each operator wrote ONLY its own):"
ls -1 "$OPS"/*.share.json

echo; echo "### PHASE 2: 2-of-3 threshold sign — quorum {0,2}, op1 offline"
echo "message hash: $HASH"
"$BIN/operator" -config "$OPS/op2.json" -phase sign -quorum 0,2 -hash "$HASH" -timeout 120s >"$OUT/sg2.json" 2>"$LOG/sg2.log" &
"$BIN/operator" -config "$OPS/op1.json" -phase sign -quorum 0,2 -hash "$HASH" -timeout 120s >"$OUT/sg1.json" 2>"$LOG/sg1.log" &
"$BIN/operator" -config "$OPS/op0.json" -phase sign -quorum 0,2 -hash "$HASH" -timeout 120s >"$OUT/sg0.json" 2>"$LOG/sg0.log" &
wait
echo "wire transcript (op0, first 10 messages crossing the wire):"
grep -h "wire " "$LOG/sg0.log" | sed -n '1,10p' || true
echo "sign results:"
for i in 0 1 2; do echo "  op$i: $(cat "$OUT/sg$i.json")"; done

SIG=$(grep -o '"sig65":"[0-9a-f]*"' "$OUT/sg0.json" | cut -d'"' -f4)
ADDR=$(grep -o '"group_eth_address":"[^"]*"' "$OUT/sg0.json" | cut -d'"' -f4)
echo; echo "### independent verification (separate process; no tss-lib, no shares)"
"$BIN/verify-sig" -hash "$HASH" -sig65 "$SIG" -expect "$ADDR"

echo; echo "### NEGATIVE A: peer offline — quorum {0,1}, op1 never starts → clean abort"
set +e
"$BIN/operator" -config "$OPS/op0.json" -phase sign -quorum 0,1 -hash "$HASH" -timeout 8s >"$OUT/negA.json" 2>"$LOG/negA.log"
echo "op0 exit: $?  (nonzero = clean failure, not a hang); stdout empty = no garbage sig: [$(cat "$OUT/negA.json")]"
tail -1 "$LOG/negA.log"
set -e

echo; echo "### NEGATIVE B: spoofed operator — op1 presents a key not matching its pin"
cat >"$WORK/forge.go" <<'GO'
package main
import("crypto/ed25519";"crypto/rand";"encoding/hex";"encoding/json";"os")
func main(){bz,_:=os.ReadFile(os.Args[1]);var m map[string]any;json.Unmarshal(bz,&m)
_,p,_:=ed25519.GenerateKey(rand.Reader);m["identity_key"]=hex.EncodeToString(p)
o,_:=json.MarshalIndent(m,"","  ");os.WriteFile(os.Args[2],o,0o600)}
GO
go run "$WORK/forge.go" "$OPS/op1.json" "$OPS/op1.forged.json"
set +e
"$BIN/operator" -config "$OPS/op2.json" -phase keygen -threshold 1 -timeout 20s >/dev/null 2>"$LOG/spoof2.log" &
"$BIN/operator" -config "$OPS/op1.forged.json" -phase keygen -threshold 1 -timeout 20s >/dev/null 2>"$LOG/spoof1.log" &
"$BIN/operator" -config "$OPS/op0.json" -phase keygen -threshold 1 -timeout 20s >/dev/null 2>"$LOG/spoof0.log" &
wait
set -e
echo "honest peers reject the impostor at the mutual-TLS handshake:"
# Under M8 the forged identity key cannot produce a valid TLS client-certificate
# signature for op1's pinned leaf, so the impostor is rejected at the TLS layer
# (a strictly stronger rejection than the old application-handshake one).
grep -h -i "invalid signature by the client certificate\|impersonation rejected\|verification failure" \
  "$LOG/spoof0.log" "$LOG/spoof2.log" | head -1

echo; echo "### NEGATIVE C: untrusted CA — op1 presents a leaf signed by a ROGUE CA"
# Mint a rogue operator-set CA and have IT issue a leaf for op1's REAL identity
# key. op1 keeps the real peer directory + real CA pin (so it can pin its peers),
# but presents the rogue-CA leaf as its OWN certificate. The honest peers chain
# every peer cert to the real operator-set CA, so op1's rogue leaf fails chain
# validation at the mutual-TLS handshake — before any protocol byte flows.
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
"$BIN/operator" -config "$OPS/op2.json" -phase keygen -threshold 1 -timeout 20s >/dev/null 2>"$LOG/utls2.log" &
"$BIN/operator" -config "$OPS/op1.untrusted.json" -phase keygen -threshold 1 -timeout 20s >/dev/null 2>"$LOG/utls1.log" &
"$BIN/operator" -config "$OPS/op0.json" -phase keygen -threshold 1 -timeout 20s >/dev/null 2>"$LOG/utls0.log" &
wait
set -e
echo "honest peer rejects the untrusted cert at the mutual-TLS handshake:"
grep -h -i "unknown authority\|tls server handshake\|tls client handshake" "$LOG/utls0.log" "$LOG/utls1.log" "$LOG/utls2.log" | head -2

echo; echo "### DONE — work dir: $WORK"
