package kobeecdsa

// Bitcoin support for Distin's GG20 threshold-ECDSA signer.
//
// Bitcoin reuses the EXACT same secp256k1 signature the EVM branch produces —
// the (r, s) the GG20 protocol outputs IS a Bitcoin-valid ECDSA signature. The
// per-chain work is entirely in the envelope around it:
//
//   - address derivation  : group pubkey -> P2WPKH (native segwit, bech32)
//   - what gets signed     : a BIP-143 segwit sighash (double-SHA256 preimage)
//   - signature encoding   : DER (canonical, low-S) + a trailing SIGHASH_ALL byte
//
// We pick P2WPKH (BIP-141/143 native segwit, "bc1..." bech32) over legacy
// P2PKH because it is the modern default: lower fees (witness discount), the
// well-defined BIP-143 sighash (no quadratic-hashing footgun), and it is what a
// new threshold-custody account would actually use today. Legacy P2PKH would be
// a strictly worse choice with no offsetting benefit here.
//
// Independent verification (see btc_test.go) parses the DER signature and checks
// it against the derived pubkey with the decred secp256k1 library (via
// btcec/v2/ecdsa) — a DIFFERENT secp256k1 implementation than the one tss-lib
// used to produce it, so a passing Verify proves the signature is valid under
// Bitcoin's own rules, not merely "valid under the library that made it".

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	btcececdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcutil/bech32"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/ripemd160" //nolint:staticcheck // RIPEMD160 is mandated by the Bitcoin HASH160 spec.
)

// SighashAll is Bitcoin's SIGHASH_ALL flag: the signature commits to all inputs
// and all outputs of the transaction. It is appended to the DER signature in the
// witness/scriptSig.
const SighashAll byte = 0x01

// hash160 is Bitcoin's HASH160 = RIPEMD160(SHA256(data)). It is how a public key
// is compressed into the 20-byte program of a P2WPKH / P2PKH address.
func hash160(data []byte) []byte {
	sha := sha256.Sum256(data)
	r := ripemd160.New()
	r.Write(sha[:])
	return r.Sum(nil)
}

// doubleSHA256 is Bitcoin's HASH256 = SHA256(SHA256(data)). Bitcoin commits to
// transaction data (and BIP-143 sighash preimages) with this, not a single hash.
func doubleSHA256(data []byte) [32]byte {
	first := sha256.Sum256(data)
	return sha256.Sum256(first[:])
}

// compressedPubkey returns the 33-byte compressed SEC1 encoding of a secp256k1
// public key (0x02/0x03 by Y-parity, then the 32-byte X). This is the form
// hashed into a modern Bitcoin address and pushed into the witness.
func compressedPubkey(pub *ecdsa.PublicKey) []byte {
	return ethcrypto.CompressPubkey(pub)
}

// BtcP2WPKHAddress derives the native-segwit (P2WPKH, "bc1...") Bitcoin address
// for the group public key on mainnet. The address is bech32(hrp="bc") of
// witness version 0 || HASH160(compressed pubkey). The 20-byte HASH160 is the
// witness program a spender must satisfy.
//
// This is the account the threshold network controls on Bitcoin: there is no
// single private key behind it — only the group key, split across shares.
func BtcP2WPKHAddress(pub *ecdsa.PublicKey) (string, error) {
	return btcP2WPKHAddressHRP(pub, "bc")
}

// btcP2WPKHAddressHRP is the network-parameterised form (hrp "bc" = mainnet,
// "tb" = testnet). Kept separate so tests can assert against testnet vectors
// without exposing a network knob on the production entrypoint.
func btcP2WPKHAddressHRP(pub *ecdsa.PublicKey, hrp string) (string, error) {
	witnessProg := hash160(compressedPubkey(pub)) // 20 bytes
	// BIP-173: the 20-byte program is regrouped from 8-bit to 5-bit, and the
	// witness version (0) is prepended as its own 5-bit value (not converted).
	conv, err := bech32.ConvertBits(witnessProg, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("convert witness program to 5-bit: %w", err)
	}
	data := append([]byte{0x00}, conv...) // version 0 || program
	addr, err := bech32.Encode(hrp, data)
	if err != nil {
		return "", fmt.Errorf("bech32 encode: %w", err)
	}
	return addr, nil
}

// BtcTxInput identifies the UTXO being spent and its value. For a P2WPKH input
// the BIP-143 sighash needs the outpoint (prev txid + index), the value in
// satoshis, and the sequence; the scriptCode is derived from the pubkey hash.
type BtcTxInput struct {
	PrevTxID [32]byte // little-endian internal byte order, as stored in the tx
	Vout     uint32
	ValueSat uint64
	Sequence uint32
}

// BtcTxOutput is one transaction output: a value and its locking scriptPubKey.
type BtcTxOutput struct {
	ValueSat     uint64
	ScriptPubKey []byte
}

// BtcSegwitSighash computes the BIP-143 signature hash for spending a single
// P2WPKH input at index `inIndex` of a transaction with the given inputs and
// outputs, under SIGHASH_ALL. This is the exact 32-byte digest a Bitcoin node
// computes and that the input's signature must commit to.
//
// BIP-143 preimage (SIGHASH_ALL):
//
//	nVersion | hashPrevouts | hashSequence | outpoint | scriptCode |
//	amount   | nSequence    | hashOutputs  | nLocktime | sighashType
//
// where hashPrevouts/hashSequence/hashOutputs are double-SHA256 of the
// concatenations, and the result is double-SHA256 of the whole preimage.
//
// `inputPubkey` is the pubkey controlling the input being signed; its HASH160
// forms the P2WPKH scriptCode (0x1976a914{20-byte-hash}88ac).
func BtcSegwitSighash(
	version uint32,
	inputs []BtcTxInput,
	outputs []BtcTxOutput,
	inIndex int,
	inputPubkey *ecdsa.PublicKey,
	locktime uint32,
) ([32]byte, error) {
	if inIndex < 0 || inIndex >= len(inputs) {
		return [32]byte{}, fmt.Errorf("inIndex %d out of range (have %d inputs)", inIndex, len(inputs))
	}

	le32 := func(v uint32) []byte {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, v)
		return b
	}
	le64 := func(v uint64) []byte {
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, v)
		return b
	}

	// hashPrevouts = HASH256(all outpoints: 32-byte txid || 4-byte vout, LE).
	var prevouts bytes.Buffer
	for _, in := range inputs {
		prevouts.Write(in.PrevTxID[:])
		prevouts.Write(le32(in.Vout))
	}
	hashPrevouts := doubleSHA256(prevouts.Bytes())

	// hashSequence = HASH256(all nSequence values, LE).
	var seqs bytes.Buffer
	for _, in := range inputs {
		seqs.Write(le32(in.Sequence))
	}
	hashSequence := doubleSHA256(seqs.Bytes())

	// hashOutputs = HASH256(all outputs: 8-byte value LE || varint scriptLen || script).
	var outs bytes.Buffer
	for _, out := range outputs {
		outs.Write(le64(out.ValueSat))
		outs.Write(varint(uint64(len(out.ScriptPubKey))))
		outs.Write(out.ScriptPubKey)
	}
	hashOutputs := doubleSHA256(outs.Bytes())

	// scriptCode for P2WPKH: OP_DUP OP_HASH160 <20-byte pkh> OP_EQUALVERIFY OP_CHECKSIG,
	// serialized in the preimage as a length-prefixed script (0x19 = 25 bytes).
	pkh := hash160(compressedPubkey(inputPubkey))
	scriptCode := make([]byte, 0, 26)
	scriptCode = append(scriptCode, 0x19, 0x76, 0xa9, 0x14)
	scriptCode = append(scriptCode, pkh...)
	scriptCode = append(scriptCode, 0x88, 0xac)

	in := inputs[inIndex]

	var pre bytes.Buffer
	pre.Write(le32(version))            // nVersion
	pre.Write(hashPrevouts[:])          // hashPrevouts
	pre.Write(hashSequence[:])          // hashSequence
	pre.Write(in.PrevTxID[:])           // outpoint txid
	pre.Write(le32(in.Vout))            // outpoint index
	pre.Write(scriptCode)               // scriptCode (length-prefixed)
	pre.Write(le64(in.ValueSat))        // amount of the input being spent
	pre.Write(le32(in.Sequence))        // nSequence of the input being spent
	pre.Write(hashOutputs[:])           // hashOutputs
	pre.Write(le32(locktime))           // nLocktime
	pre.Write(le32(uint32(SighashAll))) // sighash type (4 bytes LE)

	return doubleSHA256(pre.Bytes()), nil
}

// varint encodes a Bitcoin CompactSize (varint). Only the small-value path is
// exercised by the sample transactions here, but the full range is handled.
func varint(n uint64) []byte {
	switch {
	case n < 0xfd:
		return []byte{byte(n)}
	case n <= 0xffff:
		b := make([]byte, 3)
		b[0] = 0xfd
		binary.LittleEndian.PutUint16(b[1:], uint16(n))
		return b
	case n <= 0xffffffff:
		b := make([]byte, 5)
		b[0] = 0xfe
		binary.LittleEndian.PutUint32(b[1:], uint32(n))
		return b
	default:
		b := make([]byte, 9)
		b[0] = 0xff
		binary.LittleEndian.PutUint64(b[1:], n)
		return b
	}
}

// EncodeBtcDERSignature converts a threshold ECDSA (r, s) into the form a
// Bitcoin witness/scriptSig carries: a canonical DER-encoded signature with a
// low-S value, followed by the SIGHASH_ALL byte.
//
// Bitcoin requires low-S (BIP-62 malleability rule): if s > n/2 the verifier
// rejects it as non-canonical, so we normalise s to n-s. The recovery byte v is
// irrelevant on Bitcoin (Bitcoin signatures are not recoverable; the pubkey is
// supplied in the witness), so it is dropped here.
func EncodeBtcDERSignature(sig *EthSignature) ([]byte, error) {
	var r, s btcec.ModNScalar
	if overflow := r.SetByteSlice(sig.R[:]); overflow {
		return nil, fmt.Errorf("r overflows the secp256k1 group order")
	}
	if overflow := s.SetByteSlice(sig.S[:]); overflow {
		return nil, fmt.Errorf("s overflows the secp256k1 group order")
	}
	// Enforce low-S (BIP-62): if s is in the upper half of the order, use n-s.
	if s.IsOverHalfOrder() {
		s.Negate()
	}
	der := btcececdsa.NewSignature(&r, &s).Serialize()
	return append(der, SighashAll), nil
}

// VerifyBtcDERSignature parses a DER(+SIGHASH_ALL) signature and verifies it
// against the public key over the 32-byte sighash, using the DECRED secp256k1
// ECDSA implementation (via btcec/v2/ecdsa) — a different secp256k1 library than
// the one tss-lib used to produce the signature. A passing result is exactly the
// consensus check a Bitcoin node runs on a witness signature, so it proves the
// signature is valid under Bitcoin's own rules, not merely under the producing
// library. The trailing SIGHASH_ALL byte is stripped before parsing.
func VerifyBtcDERSignature(der, sighash []byte, pub *ecdsa.PublicKey) (bool, error) {
	if len(der) == 0 || der[len(der)-1] != SighashAll {
		return false, fmt.Errorf("missing or wrong sighash byte")
	}
	parsed, err := btcececdsa.ParseDERSignature(der[:len(der)-1])
	if err != nil {
		return false, fmt.Errorf("parse DER: %w", err)
	}
	btcPub, err := btcec.ParsePubKey(compressedPubkey(pub))
	if err != nil {
		return false, fmt.Errorf("parse pubkey: %w", err)
	}
	return parsed.Verify(sighash, btcPub), nil
}

// P2WPKHScriptForPubkey returns the scriptPubKey (0x00 0x14 || HASH160(pubkey))
// that locks funds to the given key's native-segwit address — used for the
// change output that pays value back to the group's own address.
func P2WPKHScriptForPubkey(pub *ecdsa.PublicKey) []byte {
	return append([]byte{0x00, 0x14}, hash160(compressedPubkey(pub))...)
}

// DecodeBech32P2WPKH parses a native-segwit (bech32, "bc1..."/"tb1...") address
// into its scriptPubKey (0x00 0x14 || 20-byte program). Only witness v0 P2WPKH
// (20-byte program) is accepted — the address type this signer produces and pays.
func DecodeBech32P2WPKH(addr string) ([]byte, error) {
	_, data, err := bech32.Decode(addr)
	if err != nil {
		return nil, fmt.Errorf("bech32 decode: %w", err)
	}
	if len(data) == 0 || data[0] != 0x00 {
		return nil, fmt.Errorf("not a witness-v0 address")
	}
	prog, err := bech32.ConvertBits(data[1:], 5, 8, false)
	if err != nil {
		return nil, fmt.Errorf("convert program from 5-bit: %w", err)
	}
	if len(prog) != 20 {
		return nil, fmt.Errorf("expected 20-byte P2WPKH program, got %d", len(prog))
	}
	return append([]byte{0x00, 0x14}, prog...), nil
}

// SerializeSignedP2WPKHTx assembles the complete, broadcast-ready segwit
// transaction: BIP-141 marker/flag, the inputs (empty scriptSig), the outputs,
// and one witness stack [DER(r,s)||SIGHASH_ALL, compressed-pubkey] per input,
// all signed by the same key. Returns the raw wire bytes to broadcast and the
// txid (internal byte order; reverse for the explorer display form).
func SerializeSignedP2WPKHTx(
	version uint32,
	inputs []BtcTxInput,
	outputs []BtcTxOutput,
	locktime uint32,
	derSigs [][]byte,
	compressedPub []byte,
) ([]byte, [32]byte, error) {
	if len(derSigs) != len(inputs) {
		return nil, [32]byte{}, fmt.Errorf("need one signature per input (%d sigs, %d inputs)", len(derSigs), len(inputs))
	}
	le32 := func(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }
	le64 := func(v uint64) []byte { b := make([]byte, 8); binary.LittleEndian.PutUint64(b, v); return b }

	writeBody := func(w *bytes.Buffer) {
		w.Write(varint(uint64(len(inputs))))
		for _, in := range inputs {
			w.Write(in.PrevTxID[:])
			w.Write(le32(in.Vout))
			w.Write(varint(0)) // empty scriptSig (native segwit)
			w.Write(le32(in.Sequence))
		}
		w.Write(varint(uint64(len(outputs))))
		for _, out := range outputs {
			w.Write(le64(out.ValueSat))
			w.Write(varint(uint64(len(out.ScriptPubKey))))
			w.Write(out.ScriptPubKey)
		}
	}

	// Legacy (no marker/flag/witness) serialization defines the txid.
	var legacy bytes.Buffer
	legacy.Write(le32(version))
	writeBody(&legacy)
	legacy.Write(le32(locktime))
	txid := doubleSHA256(legacy.Bytes())

	// Full segwit serialization is what gets broadcast.
	var w bytes.Buffer
	w.Write(le32(version))
	w.Write([]byte{0x00, 0x01}) // segwit marker + flag
	writeBody(&w)
	for i := range inputs {
		w.Write(varint(2)) // two witness items
		w.Write(varint(uint64(len(derSigs[i]))))
		w.Write(derSigs[i])
		w.Write(varint(uint64(len(compressedPub))))
		w.Write(compressedPub)
	}
	w.Write(le32(locktime))
	return w.Bytes(), txid, nil
}

// BtcP2WPKHAddressTestnet is BtcP2WPKHAddress with the testnet HRP ("tb1..."),
// so a threshold group can be funded from a free testnet faucet for live sends.
func BtcP2WPKHAddressTestnet(pub *ecdsa.PublicKey) (string, error) {
	return btcP2WPKHAddressHRP(pub, "tb")
}
