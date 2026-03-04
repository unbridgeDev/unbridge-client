// verify-sig is a standalone, independent verifier for a Distin GG20 signature.
//
//	verify-sig -hash <64hex> -sig65 <130hex> -expect 0x<addr>
//
// It runs go-ethereum's SigToPub (the exact ECRecover primitive an Ethereum node
// applies to a transaction signature) on the (r,s,v) bytes, derives the signer's
// address, and asserts it equals -expect. This process shares NOTHING with the
// operators that produced the signature — no tss-lib, no shares, no network — so
// a match here is independent proof that the over-the-wire threshold signature is
// a genuine, chain-valid Ethereum ECDSA signature for the group account.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	ethcommon "github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

func main() {
	hashHex := flag.String("hash", "", "32-byte message hash, hex")
	sigHex := flag.String("sig65", "", "65-byte signature r||s||v, hex")
	expect := flag.String("expect", "", "expected group ETH address (0x…)")
	flag.Parse()

	hash, err := hex.DecodeString(strings.TrimPrefix(*hashHex, "0x"))
	if err != nil || len(hash) != 32 {
		fmt.Fprintln(os.Stderr, "verify-sig: -hash must be 32 bytes hex")
		os.Exit(2)
	}
	sig, err := hex.DecodeString(strings.TrimPrefix(*sigHex, "0x"))
	if err != nil || len(sig) != 65 {
		fmt.Fprintln(os.Stderr, "verify-sig: -sig65 must be 65 bytes hex")
		os.Exit(2)
	}

	pub, err := ethcrypto.SigToPub(hash, sig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify-sig: ecrecover failed: %v\n", err)
		os.Exit(1)
	}
	recovered := ethcrypto.PubkeyToAddress(*pub)
	want := ethcommon.HexToAddress(*expect)

	fmt.Printf("independent go-ethereum ecrecover\n")
	fmt.Printf("  recovered : %s\n", recovered.Hex())
	fmt.Printf("  expected  : %s\n", want.Hex())
	if recovered == want {
		fmt.Println("  MATCH — signature is a chain-valid Ethereum signature for the group account")
		return
	}
	fmt.Println("  MISMATCH")
	os.Exit(1)
}
