// kobe-ecdsa is the CLI seam the Rust coordinator drives to obtain a real GG20
// threshold-ECDSA signature for the EVM (Gg20Secp256k1) branch of a Distin
// signing request. It speaks JSON on stdout so the coordinator can invoke it as
// a subprocess and parse the result. Two subcommands:
//
//	kobe-ecdsa keygen -n 3 -t 1 -out shares.json
//	    Runs distributed key generation (no dealer) and writes the shares +
//	    group public key to -out. Prints {group_pub, group_eth_address} as JSON.
//
//	kobe-ecdsa sign -shares shares.json -hash <64-hex> -quorum 0,2
//	    Loads the shares, threshold-signs the 32-byte hash with the given quorum
//	    of share indices, and prints {r, s, v, sig65, recovered_eth_address,
//	    group_eth_address, match} as JSON. The signature is a standard secp256k1
//	    ECDSA (r,s,v); `recovered_eth_address` is computed with go-ethereum's
//	    own Ecrecover, independent of tss-lib.
//
//	kobe-ecdsa btc -shares shares.json -sighash <64-hex> -quorum 0,2
//	    Derives the group's P2WPKH (bech32) address, threshold-signs the BIP-143
//	    sighash, and prints {btc_address, der_sighash_all, verified} where the
//	    DER+SIGHASH_ALL signature is verified against the derived pubkey with the
//	    decred secp256k1 library (independent of tss-lib).
//
//	kobe-ecdsa tron -shares shares.json -txid <64-hex> -quorum 0,2
//	    Derives the group's Tron base58check address, threshold-signs the Tron tx
//	    id (sha256 of raw_data), and prints {tron_address, sig65,
//	    recovered_tron_address, match} where the address is recovered from the
//	    signature with go-ethereum's Ecrecover (independent of tss-lib).
//
// The group secret is never reconstructed: keygen and signing both run the GG20
// protocol over Shamir shares. The seam is intentionally a plain subprocess +
// JSON, the smallest thing that lets the Rust loop bridge into the Go signer.
package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	kobe "github.com/distin/kobe-ecdsa"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}

func emit(v any) {
	bz, err := json.Marshal(v)
	if err != nil {
		fail("marshal output: %v", err)
	}
	fmt.Println(string(bz))
}

func main() {
	if len(os.Args) < 2 {
		fail("usage: kobe-ecdsa <keygen|sign> ...")
	}
	switch os.Args[1] {
	case "keygen":
		keygenCmd(os.Args[2:])
	case "sign":
		signCmd(os.Args[2:])
	case "btc":
		btcCmd(os.Args[2:])
	case "tron":
		tronCmd(os.Args[2:])
	default:
		fail("unknown subcommand %q (want keygen|sign|btc|tron)", os.Args[1])
	}
}

func keygenCmd(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	n := fs.Int("n", 3, "number of parties")
	t := fs.Int("t", 1, "tss-lib threshold (t+1 parties sign)")
	out := fs.String("out", "", "path to write the shares JSON file")
	_ = fs.Parse(args)
	if *out == "" {
		fail("keygen: -out is required")
	}

	shares, groupPub, err := kobe.DistributedKeyGen(*n, *t)
	if err != nil {
		fail("keygen: %v", err)
	}
	if err := kobe.SaveShares(*out, shares, groupPub, *t); err != nil {
		fail("keygen: save: %v", err)
	}

	emit(map[string]any{
		"n":                 *n,
		"threshold":         *t,
		"shares_path":       *out,
		"group_pub":         "04" + hex.EncodeToString(ethcrypto.FromECDSAPub(groupPub)[1:]),
		"group_eth_address": kobe.GroupAddress(groupPub).Hex(),
	})
}

func signCmd(args []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	sharesPath := fs.String("shares", "", "path to the shares JSON file from keygen")
	hashHex := fs.String("hash", "", "32-byte message hash, hex (64 chars)")
	quorum := fs.String("quorum", "", "comma-separated share indices to sign, e.g. 0,2")
	_ = fs.Parse(args)
	if *sharesPath == "" || *hashHex == "" || *quorum == "" {
		fail("sign: -shares, -hash and -quorum are all required")
	}

	hash, err := hex.DecodeString(strings.TrimPrefix(*hashHex, "0x"))
	if err != nil || len(hash) != 32 {
		fail("sign: -hash must be 32 bytes of hex (got %d bytes)", len(hash))
	}

	allShares, groupPub, err := kobe.LoadShares(*sharesPath)
	if err != nil {
		fail("sign: load shares: %v", err)
	}

	var quorumShares []kobe.KeyShare
	for _, part := range strings.Split(*quorum, ",") {
		idx, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || idx < 0 || idx >= len(allShares) {
			fail("sign: bad quorum index %q", part)
		}
		quorumShares = append(quorumShares, allShares[idx])
	}

	sig, err := kobe.ThresholdSign(quorumShares, hash)
	if err != nil {
		fail("sign: %v", err)
	}

	// Independent verification, inside the signer too: recover the address from
	// (r,s,v) with go-ethereum and compare to the group key's address. The Rust
	// coordinator repeats this from the ON-CHAIN bytes — this is a local sanity
	// gate so a broken sig never even reaches the chain.
	groupAddr := kobe.GroupAddress(groupPub)
	recovered, err := kobe.RecoverAddress(hash, sig)
	if err != nil {
		fail("sign: ecrecover: %v", err)
	}

	emit(map[string]any{
		"r":                     hex.EncodeToString(sig.R[:]),
		"s":                     hex.EncodeToString(sig.S[:]),
		"v":                     sig.V,
		"sig65":                 hex.EncodeToString(sig.Bytes()),
		"group_eth_address":     groupAddr.Hex(),
		"recovered_eth_address": recovered.Hex(),
		"match":                 recovered == groupAddr,
	})
}

// loadAndSign is the shared body of btc/tron: parse the 32-byte hash, load the
// shares, select the quorum, and threshold-sign. It returns the signature plus
// the group public key (so the caller can derive the chain address).
func loadAndSign(sharesPath, hashHex, quorum string) (*kobe.EthSignature, *ecdsa.PublicKey, []byte) {
	hash, err := hex.DecodeString(strings.TrimPrefix(hashHex, "0x"))
	if err != nil || len(hash) != 32 {
		fail("hash must be 32 bytes of hex (got %d bytes)", len(hash))
	}
	allShares, groupPub, err := kobe.LoadShares(sharesPath)
	if err != nil {
		fail("load shares: %v", err)
	}
	var quorumShares []kobe.KeyShare
	for _, part := range strings.Split(quorum, ",") {
		idx, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || idx < 0 || idx >= len(allShares) {
			fail("bad quorum index %q", part)
		}
		quorumShares = append(quorumShares, allShares[idx])
	}
	sig, err := kobe.ThresholdSign(quorumShares, hash)
	if err != nil {
		fail("sign: %v", err)
	}
	return sig, groupPub, hash
}

func btcCmd(args []string) {
	fs := flag.NewFlagSet("btc", flag.ExitOnError)
	sharesPath := fs.String("shares", "", "path to the shares JSON file from keygen")
	sighashHex := fs.String("sighash", "", "32-byte BIP-143 sighash, hex (64 chars)")
	quorum := fs.String("quorum", "", "comma-separated share indices to sign, e.g. 0,2")
	_ = fs.Parse(args)
	if *sharesPath == "" || *sighashHex == "" || *quorum == "" {
		fail("btc: -shares, -sighash and -quorum are all required")
	}

	sig, groupPub, sighash := loadAndSign(*sharesPath, *sighashHex, *quorum)

	addr, err := kobe.BtcP2WPKHAddress(groupPub)
	if err != nil {
		fail("btc: address: %v", err)
	}
	der, err := kobe.EncodeBtcDERSignature(sig)
	if err != nil {
		fail("btc: encode: %v", err)
	}
	// Independent verification with decred secp256k1 (not tss-lib): parse the DER
	// signature and verify it against the derived pubkey over the sighash.
	verified, err := kobe.VerifyBtcDERSignature(der, sighash, groupPub)
	if err != nil {
		fail("btc: verify: %v", err)
	}

	emit(map[string]any{
		"btc_address":     addr,
		"sighash":         hex.EncodeToString(sighash),
		"der_sighash_all": hex.EncodeToString(der),
		"verified":        verified,
	})
}

func tronCmd(args []string) {
	fs := flag.NewFlagSet("tron", flag.ExitOnError)
	sharesPath := fs.String("shares", "", "path to the shares JSON file from keygen")
	txidHex := fs.String("txid", "", "32-byte Tron tx id (sha256 of raw_data), hex (64 chars)")
	quorum := fs.String("quorum", "", "comma-separated share indices to sign, e.g. 0,2")
	_ = fs.Parse(args)
	if *sharesPath == "" || *txidHex == "" || *quorum == "" {
		fail("tron: -shares, -txid and -quorum are all required")
	}

	sig, groupPub, txid := loadAndSign(*sharesPath, *txidHex, *quorum)

	groupAddr := kobe.TronAddress(groupPub)
	recovered, err := kobe.RecoverTronAddress(txid, sig)
	if err != nil {
		fail("tron: recover: %v", err)
	}

	emit(map[string]any{
		"tron_address":           groupAddr,
		"txid":                   hex.EncodeToString(txid),
		"sig65":                  hex.EncodeToString(kobe.TronSignature(sig)),
		"recovered_tron_address": recovered,
		"match":                  recovered == groupAddr,
	})
}
