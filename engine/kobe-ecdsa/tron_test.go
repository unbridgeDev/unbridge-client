package kobeecdsa

import (
	"encoding/hex"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// TestTronAddressKnownVector pins the Tron address derivation against a fixed,
// externally-verifiable input: a known private key's public key must produce its
// well-known Tron base58 address. The vector is privkey
// 0x0000...0001 -> Tron address TJRyWwFs9wTFGZg3JbrVriFbNfCug5tDeC. This proves
// the keccak256 -> 0x41 -> base58check path independent of the threshold path.
// The expected address was cross-checked with an independent Python derivation
// (separate secp256k1 point math + keccak + base58): privkey 0x...01 has the
// well-known account 0x7e5f4552091a69125d5dfcb7b8c2659029395bdf, which is Tron
// address TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC.
func TestTronAddressKnownVector(t *testing.T) {
	priv, err := ethcrypto.HexToECDSA("0000000000000000000000000000000000000000000000000000000000000001")
	if err != nil {
		t.Fatalf("bad test key: %v", err)
	}
	addr := TronAddress(&priv.PublicKey)
	const want = "TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC"
	if addr != want {
		t.Fatalf("Tron vector mismatch\n  got  %s\n  want %s", addr, want)
	}
	// Round-trip: base58check-decode back to the 20-byte account.
	gotEth, err := tronAddressToEth(addr)
	if err != nil {
		t.Fatalf("decode address: %v", err)
	}
	if gotEth != ethcrypto.PubkeyToAddress(priv.PublicKey) {
		t.Fatal("address round-trip mismatch")
	}
	t.Logf("privkey 0x...01 -> Tron %s (matches the known vector)", addr)
}

// TestTronThresholdSignRecovers is the flagship Tron check: a 2-of-3 GG20
// signature over a real Tron tx id (SHA256 of raw_data) must recover — via
// go-ethereum's Ecrecover, the exact primitive a Tron node runs — to the SAME
// Tron base58 address derived from the group key.
func TestTronThresholdSignRecovers(t *testing.T) {
	shares, groupPub, err := DistributedKeyGen(3, 1)
	if err != nil {
		t.Fatalf("DKG: %v", err)
	}

	groupAddr := TronAddress(groupPub)
	t.Logf("group Tron address: %s", groupAddr)

	// A stand-in for a serialized protobuf transaction.raw_data. The crypto only
	// cares that we SHA256 it the way Tron does; serializing real protobuf is the
	// wallet's job and orthogonal to the signature.
	rawData := []byte("tron raw_data: TransferContract 10 TRX -> TRecipient...")
	txid := TronTxID(rawData)
	t.Logf("Tron tx id (sha256 raw_data): %s", hex.EncodeToString(txid[:]))

	sig, err := ThresholdSign([]KeyShare{shares[0], shares[2]}, txid[:])
	if err != nil {
		t.Fatalf("threshold sign: %v", err)
	}
	sig65 := TronSignature(sig)
	if len(sig65) != 65 {
		t.Fatalf("expected 65-byte recoverable sig, got %d", len(sig65))
	}
	t.Logf("Tron signature (r||s||v): %s", hex.EncodeToString(sig65))

	// --- INDEPENDENT verification (go-ethereum Ecrecover, not tss-lib) ---
	recovered, err := RecoverTronAddress(txid[:], sig)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if recovered != groupAddr {
		t.Fatalf("RECOVERED TRON ADDRESS MISMATCH\n  group     = %s\n  recovered = %s", groupAddr, recovered)
	}
	t.Logf("recovered Tron address: %s — MATCHES the group address", recovered)

	// --- negative control: a different tx id must NOT recover the group addr ---
	badTxid := TronTxID([]byte("a different transaction"))
	if other, _ := RecoverTronAddress(badTxid[:], sig); other == groupAddr {
		t.Fatal("wrong tx id still recovered the group Tron address — verifier broken")
	}
	// --- negative control: a tampered S must NOT recover the group addr ---
	tampered := *sig
	tampered.S[31] ^= 0x01
	if other, err := RecoverTronAddress(txid[:], &tampered); err == nil && other == groupAddr {
		t.Fatal("tampered signature still recovered the group Tron address — verifier broken")
	}
	t.Log("negative controls pass: wrong tx id and tampered signature both fail to recover the group address")
}
