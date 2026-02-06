package kobeecdsa

import (
	"bytes"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// keccak256 of an arbitrary "transaction-like" message. On Ethereum the value a
// signer signs is keccak256 of the RLP-encoded tx (or an EIP-191/712 digest);
// here we just need a real 32-byte keccak digest to sign and recover against.
func keccakHash(s string) []byte {
	return ethcrypto.Keccak256([]byte(s))
}

// The flagship assertion for milestone 2: a 2-of-3 GG20 threshold signature over
// a keccak256 message hash recovers — via go-ethereum's own Ecrecover — to the
// SAME Ethereum address derived from the group public key. That is exactly the
// check a real ETH node performs on a transaction signature, so a match proves
// the signature is natively chain-valid.
func TestTwoOfThreeRecoversGroupEthAddress(t *testing.T) {
	shares, groupPub, err := DistributedKeyGen(3, 1) // 3 parties, t=1 => any 2 sign
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}
	if len(shares) != 3 {
		t.Fatalf("expected 3 shares, got %d", len(shares))
	}

	groupAddr := GroupAddress(groupPub)
	hash := keccakHash("distin: one account, every chain")

	// Sign with shares {0, 2} — party 1 stays offline.
	sig, err := ThresholdSign([]KeyShare{shares[0], shares[2]}, hash)
	if err != nil {
		t.Fatalf("threshold sign failed: %v", err)
	}

	recovered, err := RecoverAddress(hash, sig)
	if err != nil {
		t.Fatalf("ecrecover failed: %v", err)
	}

	if recovered != groupAddr {
		t.Fatalf("RECOVERED ADDRESS MISMATCH\n  group     = %s\n  recovered = %s", groupAddr.Hex(), recovered.Hex())
	}
	t.Logf("group ETH address : %s", groupAddr.Hex())
	t.Logf("recovered address : %s", recovered.Hex())
	t.Logf("RECOVERED ADDRESS MATCHES — 2 of 3 shares produced a chain-valid ECDSA signature")

	// Negative control: a tampered message must NOT recover the group address.
	bad := keccakHash("distin: a different message")
	if other, _ := RecoverAddress(bad, sig); other == groupAddr {
		t.Fatal("tampered-message hash still recovered the group address — verifier is broken")
	}

	// Negative control: a tampered S must NOT recover the group address.
	tampered := *sig
	tampered.S[31] ^= 0x01
	if other, err := RecoverAddress(hash, &tampered); err == nil && other == groupAddr {
		t.Fatal("tampered signature still recovered the group address — verifier is broken")
	}
}

// Every 2-of-3 quorum must sign for the same group account — the threshold
// property: the signing committee is interchangeable.
func TestAnyTwoOfThreeQuorum(t *testing.T) {
	shares, groupPub, err := DistributedKeyGen(3, 1)
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}
	groupAddr := GroupAddress(groupPub)
	hash := keccakHash("distin quorum interchangeability")

	quorums := [][2]int{{0, 1}, {0, 2}, {1, 2}}
	for _, q := range quorums {
		sig, err := ThresholdSign([]KeyShare{shares[q[0]], shares[q[1]]}, hash)
		if err != nil {
			t.Fatalf("quorum {%d,%d} sign failed: %v", q[0], q[1], err)
		}
		recovered, err := RecoverAddress(hash, sig)
		if err != nil {
			t.Fatalf("quorum {%d,%d} recover failed: %v", q[0], q[1], err)
		}
		if recovered != groupAddr {
			t.Fatalf("quorum {%d,%d} recovered %s, want group %s", q[0], q[1], recovered.Hex(), groupAddr.Hex())
		}
	}
	t.Logf("all three 2-of-3 quorums recovered the same group address %s", groupAddr.Hex())
}

// Sanity: the signature is well-formed for go-ethereum (65 bytes, V in {0,1}),
// i.e. directly consumable by SigToPub / VerifySignature without reshaping.
func TestSignatureIsEthWireFormat(t *testing.T) {
	shares, groupPub, err := DistributedKeyGen(3, 1)
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}
	hash := keccakHash("wire format check")
	sig, err := ThresholdSign([]KeyShare{shares[0], shares[1]}, hash)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	wire := sig.Bytes()
	if len(wire) != 65 {
		t.Fatalf("expected 65-byte signature, got %d", len(wire))
	}
	if sig.V != 0 && sig.V != 1 {
		t.Fatalf("recovery byte must be 0 or 1, got %d", sig.V)
	}
	// go-ethereum's VerifySignature wants the 64-byte [R||S] form against the
	// compressed group pubkey — a second independent check path.
	pubBytes := ethcrypto.CompressPubkey(groupPub)
	if !ethcrypto.VerifySignature(pubBytes, hash, wire[:64]) {
		t.Fatal("go-ethereum VerifySignature rejected the threshold signature")
	}
	if !bytes.Equal(wire[0:32], sig.R[:]) {
		t.Fatal("R serialization mismatch")
	}
}
