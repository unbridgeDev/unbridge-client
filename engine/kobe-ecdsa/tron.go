package kobeecdsa

// Tron support for Distin's GG20 threshold-ECDSA signer.
//
// Tron is an EVM-cousin: it uses the same secp256k1 curve, the same keccak256
// pubkey->address derivation as Ethereum, and the same 65-byte recoverable
// (r, s, v) signature. The per-chain differences are exactly two:
//
//   - address ENCODING : Ethereum shows keccak256(pub)[12:] as 0x-hex; Tron
//     prepends a 0x41 version byte and base58check-encodes it ("T..." address).
//   - what gets signed : the Tron tx id is SHA256 of the protobuf-serialized
//     transaction.raw_data (Tron signs sha256(raw), not keccak256(rlp)).
//
// The signature itself is identical to the EVM branch: 32-byte R, 32-byte S, and
// a recovery byte. Tron's `ECRecover` precompile / node recovers the signer the
// same way Ethereum does, so the independent check (see tron_test.go) recovers
// the public key from (r, s, v) with go-ethereum's Ecrecover — the exact
// primitive a Tron full node runs — re-derives the Tron base58 address, and
// asserts it equals the address derived from the group key.

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"

	"github.com/btcsuite/btcutil/base58"
	ethcommon "github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// tronAddrPrefix is the Tron mainnet address version byte (0x41). It is
// prepended to the 20-byte keccak address before base58check encoding, which is
// why every Tron base58 address starts with "T".
const tronAddrPrefix byte = 0x41

// tronRawAddress returns the 21-byte raw Tron address: 0x41 || keccak256(pub)[12:].
// This is the same 20-byte account hash Ethereum uses, with Tron's version byte.
func tronRawAddress(pub *ecdsa.PublicKey) []byte {
	eth := ethcrypto.PubkeyToAddress(*pub) // keccak256(uncompressed[1:])[12:]
	raw := make([]byte, 0, 21)
	raw = append(raw, tronAddrPrefix)
	raw = append(raw, eth.Bytes()...)
	return raw
}

// TronAddress derives the base58check Tron address ("T..." form) of the group
// public key. Encoding is base58( raw || doubleSHA256(raw)[:4] ) where raw is
// 0x41 || keccak256(pub)[12:]. This is the account the threshold network
// controls on Tron — no single private key exists behind it.
func TronAddress(pub *ecdsa.PublicKey) string {
	raw := tronRawAddress(pub)
	checksum := doubleSHA256(raw)
	full := append(raw, checksum[:4]...)
	return base58.Encode(full)
}

// TronTxID computes the Tron transaction id / signing digest: SHA256 of the
// protobuf-serialized `transaction.raw_data`. Tron signs this 32-byte hash (it
// uses SHA256 for the tx id, unlike Ethereum's keccak256-of-RLP). The caller
// passes the already-serialized raw_data bytes; serializing protobuf is the
// wallet's job and orthogonal to the signing crypto.
func TronTxID(rawData []byte) [32]byte {
	return sha256.Sum256(rawData)
}

// TronSignature is the 65-byte recoverable signature Tron expects: [R || S || V]
// with V in {0, 1}. It is byte-identical in shape to the Ethereum signature.
func TronSignature(sig *EthSignature) []byte {
	return sig.Bytes()
}

// RecoverTronAddress recovers the Tron address from a (r, s, v) signature over a
// 32-byte tx id, using go-ethereum's Ecrecover (the same primitive Tron's
// ECRecover runs) and re-encoding the recovered 20-byte account as a Tron
// base58check address. An INDEPENDENT verifier: it does not touch tss-lib, so a
// match with TronAddress proves the signature is genuinely valid under Tron's
// recovery rules.
func RecoverTronAddress(txid []byte, sig *EthSignature) (string, error) {
	if len(txid) != 32 {
		return "", fmt.Errorf("txid must be 32 bytes, got %d", len(txid))
	}
	pub, err := ethcrypto.SigToPub(txid, sig.Bytes())
	if err != nil {
		return "", fmt.Errorf("ecrecover failed: %w", err)
	}
	return TronAddress(pub), nil
}

// tronAddressToEth is a small helper used by tests to cross-check the Tron
// base58 decoding round-trips to the expected 20-byte Ethereum-style account.
func tronAddressToEth(addr string) (ethcommon.Address, error) {
	decoded := base58.Decode(addr)
	if len(decoded) != 25 {
		return ethcommon.Address{}, fmt.Errorf("decoded length %d, want 25", len(decoded))
	}
	raw := decoded[:21]
	want := doubleSHA256(raw)
	if string(decoded[21:]) != string(want[:4]) {
		return ethcommon.Address{}, fmt.Errorf("base58check checksum mismatch")
	}
	if raw[0] != tronAddrPrefix {
		return ethcommon.Address{}, fmt.Errorf("bad version byte 0x%02x", raw[0])
	}
	return ethcommon.BytesToAddress(raw[1:]), nil
}
