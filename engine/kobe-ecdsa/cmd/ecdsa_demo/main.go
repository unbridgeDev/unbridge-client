// Runnable demo of Distin's 2-of-3 GG20 threshold-ECDSA signer for Ethereum.
//
//	go run ./cmd/ecdsa_demo
//
// Runs distributed key generation among 3 parties, threshold-signs a keccak256
// message hash with 2 of the 3 shares, and proves the result is a real
// Ethereum signature by recovering the signer address with go-ethereum's
// Ecrecover and asserting it equals the group public key's ETH address.
package main

import (
	"fmt"
	"os"

	kobe "github.com/distin/kobe-ecdsa"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

func hexs(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = h[c>>4]
		out[i*2+1] = h[c&0x0f]
	}
	return string(out)
}

func main() {
	fmt.Println("Distin / kobe-ecdsa — 2-of-3 GG20 threshold-ECDSA signer (Ethereum)")
	fmt.Println("library      : Binance tss-lib v2.0.2 (GG18/GG20), curve secp256k1")
	fmt.Println("scheme       : Gg20Secp256k1 (EVM / BTC / Tron branch)")
	fmt.Println("parties      : 3, threshold : 2")
	fmt.Println()

	fmt.Println("running distributed key generation (no dealer; safe-prime gen is slow)...")
	shares, groupPub, err := kobe.DistributedKeyGen(3, 1)
	if err != nil {
		fmt.Fprintln(os.Stderr, "DKG failed:", err)
		os.Exit(1)
	}
	groupAddr := kobe.GroupAddress(groupPub)
	fmt.Printf("group pubkey : 04%s\n", hexs(ethcrypto.FromECDSAPub(groupPub)[1:]))
	fmt.Printf("group ETH addr: %s\n", groupAddr.Hex())
	fmt.Println()

	// A real keccak256 message digest — what an ETH signer actually signs.
	msg := []byte("distin: one account, every chain")
	hash := ethcrypto.Keccak256(msg)
	fmt.Printf("message       : %q\n", msg)
	fmt.Printf("keccak256(32B): %s\n", hexs(hash))
	fmt.Println("signing quorum: shares {1, 3}  (party 2 stays offline)")
	fmt.Println()

	sig, err := kobe.ThresholdSign([]kobe.KeyShare{shares[0], shares[2]}, hash)
	if err != nil {
		fmt.Fprintln(os.Stderr, "threshold sign failed:", err)
		os.Exit(1)
	}
	fmt.Printf("signature r   : %s\n", hexs(sig.R[:]))
	fmt.Printf("signature s   : %s\n", hexs(sig.S[:]))
	fmt.Printf("recovery v    : %d\n", sig.V)
	fmt.Println()

	// Independent verification: go-ethereum's Ecrecover — the exact primitive an
	// ETH node runs on a tx signature.
	recovered, err := kobe.RecoverAddress(hash, sig)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ecrecover failed:", err)
		os.Exit(1)
	}
	fmt.Println("independent go-ethereum Ecrecover from (r, s, v):")
	fmt.Printf("recovered addr: %s\n", recovered.Hex())
	fmt.Println()

	if recovered != groupAddr {
		fmt.Fprintf(os.Stderr, "ADDRESS MISMATCH: group %s != recovered %s\n", groupAddr.Hex(), recovered.Hex())
		os.Exit(1)
	}
	fmt.Println("RECOVERED ADDRESS MATCHES — 2 of 3 shares produced a chain-valid")
	fmt.Println("Ethereum ECDSA signature for the group account, and the group")
	fmt.Println("private key was never reconstructed.")
}
