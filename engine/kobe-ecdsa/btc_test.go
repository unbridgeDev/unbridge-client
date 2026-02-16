package kobeecdsa

import (
	"encoding/hex"
	"testing"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// TestBtcP2WPKHKnownVector pins the address derivation against the canonical
// BIP-173 test vector: the secp256k1 generator pubkey must produce the mainnet
// P2WPKH address bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4. This proves the
// bech32 + HASH160 path is correct independent of the threshold machinery — a
// fixed, externally-known input/output pair.
func TestBtcP2WPKHKnownVector(t *testing.T) {
	pubBytes, _ := hex.DecodeString("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
	pub, err := ethcrypto.DecompressPubkey(pubBytes)
	if err != nil {
		t.Fatalf("decompress generator pubkey: %v", err)
	}
	addr, err := BtcP2WPKHAddress(pub)
	if err != nil {
		t.Fatalf("address: %v", err)
	}
	const want = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
	if addr != want {
		t.Fatalf("BIP-173 vector mismatch\n  got  %s\n  want %s", addr, want)
	}
	t.Logf("BIP-173 generator pubkey -> %s (matches the spec vector)", addr)
}

// TestBtcThresholdSignVerifies is the flagship Bitcoin check: a 2-of-3 GG20
// signature over a real BIP-143 P2WPKH sighash, DER+SIGHASH_ALL encoded, must
// verify against the derived pubkey under an INDEPENDENT secp256k1 library
// (decred secp256k1 via btcec/v2/ecdsa) — Bitcoin's own consensus rule, not
// tss-lib's verifier.
func TestBtcThresholdSignVerifies(t *testing.T) {
	shares, groupPub, err := DistributedKeyGen(3, 1)
	if err != nil {
		t.Fatalf("DKG: %v", err)
	}

	addr, err := BtcP2WPKHAddress(groupPub)
	if err != nil {
		t.Fatalf("address: %v", err)
	}
	t.Logf("group BTC P2WPKH address: %s", addr)

	// A realistic spend: 1 input (0.5 BTC) of the group's own P2WPKH UTXO, one
	// output paying 0.4 BTC (rest is fee), SIGHASH_ALL.
	var prevTxID [32]byte
	copy(prevTxID[:], mustHex(t, "8d9b6f3c1e0a4d2b7c5e9f0a1b2c3d4e5f607182930a4b5c6d7e8f9a0b1c2d3e"))
	inputs := []BtcTxInput{{PrevTxID: prevTxID, Vout: 0, ValueSat: 50_000_000, Sequence: 0xffffffff}}
	// Output scriptPubKey: OP_0 <20-byte hash> (P2WPKH to some recipient).
	outScript := append([]byte{0x00, 0x14}, mustHex(t, "751e76e8199196d454941c45d1b3a323f1433bd6")...)
	outputs := []BtcTxOutput{{ValueSat: 40_000_000, ScriptPubKey: outScript}}

	sighash, err := BtcSegwitSighash(2, inputs, outputs, 0, groupPub, 0)
	if err != nil {
		t.Fatalf("sighash: %v", err)
	}
	t.Logf("BIP-143 sighash: %s", hex.EncodeToString(sighash[:]))

	sig, err := ThresholdSign([]KeyShare{shares[0], shares[2]}, sighash[:])
	if err != nil {
		t.Fatalf("threshold sign: %v", err)
	}

	der, err := EncodeBtcDERSignature(sig)
	if err != nil {
		t.Fatalf("DER encode: %v", err)
	}
	if der[len(der)-1] != SighashAll {
		t.Fatalf("missing SIGHASH_ALL byte, got 0x%02x", der[len(der)-1])
	}
	t.Logf("DER+SIGHASH_ALL signature: %s", hex.EncodeToString(der))

	// --- INDEPENDENT verification (decred secp256k1, not tss-lib) ---
	ok, err := VerifyBtcDERSignature(der, sighash[:], groupPub)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if !ok {
		t.Fatal("decred secp256k1 REJECTED the DER signature for the BIP-143 sighash")
	}
	t.Log("decred secp256k1 ACCEPTED the DER signature over the BIP-143 sighash under the derived pubkey")

	// --- negative control: a different sighash must NOT verify ---
	badSighash := doubleSHA256([]byte("a different transaction"))
	if ok, _ := VerifyBtcDERSignature(der, badSighash[:], groupPub); ok {
		t.Fatal("signature verified against the WRONG sighash — verifier is broken")
	}
	// --- negative control: a tampered DER signature must NOT verify ---
	tampered := make([]byte, len(der))
	copy(tampered, der)
	tampered[len(tampered)-5] ^= 0x01 // flip a byte inside S
	if ok, _ := VerifyBtcDERSignature(tampered, sighash[:], groupPub); ok {
		t.Fatal("tampered DER signature still verified — verifier is broken")
	}
	t.Log("negative controls pass: wrong sighash and tampered signature both rejected")
}

// TestBtcDERIsLowS asserts the encoder enforces BIP-62 low-S: the S value in the
// emitted DER must never exceed n/2, or a Bitcoin node rejects it as
// non-canonical (malleable).
func TestBtcDERIsLowS(t *testing.T) {
	shares, _, err := DistributedKeyGen(3, 1)
	if err != nil {
		t.Fatalf("DKG: %v", err)
	}
	hash := doubleSHA256([]byte("low-s check"))
	sig, err := ThresholdSign([]KeyShare{shares[0], shares[1]}, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	der, err := EncodeBtcDERSignature(sig)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var encS btcec.ModNScalar
	encS.SetByteSlice(derS(t, der[:len(der)-1]))
	if encS.IsOverHalfOrder() {
		t.Fatal("encoded S is high — BIP-62 low-S not enforced")
	}
	t.Log("encoded DER signature is low-S (BIP-62 canonical)")
}

// derS extracts the S integer bytes from a DER-encoded ECDSA signature
// (0x30 len 0x02 rlen R 0x02 slen S).
func derS(t *testing.T, der []byte) []byte {
	t.Helper()
	if len(der) < 8 || der[0] != 0x30 || der[2] != 0x02 {
		t.Fatalf("not a DER sig")
	}
	rlen := int(der[3])
	sOff := 4 + rlen
	if sOff >= len(der) || der[sOff] != 0x02 {
		t.Fatalf("malformed DER: no S integer")
	}
	slen := int(der[sOff+1])
	return der[sOff+2 : sOff+2+slen]
}
