// btc-tx — prove the GG20 group can authorize a REAL Bitcoin spend.
//
//	go run ./cmd/btc-tx
//
// Mirrors cmd/eth-tx for Bitcoin: derive the group's native-segwit (P2WPKH,
// bc1...) address, build a real P2WPKH spend, compute its BIP-143 sighash (the
// exact 32-byte digest a Bitcoin node checks), threshold-sign it with 2 of 3
// shares, and recover the signer back to the group's Bitcoin address. Offline
// and fund-free: it proves the signature is chain-valid for the group key over a
// real transaction, without ever assembling the group private key.
package main

import (
	"fmt"
	"os"

	kobe "github.com/distin/kobe-ecdsa"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

func main() {
	fmt.Println("running fresh 2-of-3 GG20 DKG (safe-prime gen is slow)...")
	shares, groupPub, err := kobe.DistributedKeyGen(3, 1)
	if err != nil {
		die("DKG: %v", err)
	}
	btcAddr, err := kobe.BtcP2WPKHAddress(groupPub)
	if err != nil {
		die("btc address: %v", err)
	}
	fmt.Printf("group BTC address : %s\n", btcAddr)

	// A real P2WPKH input (the UTXO the group controls) and an output paying a
	// recipient. Sample outpoint/value; the signature commits to all of it.
	inputs := []kobe.BtcTxInput{{
		PrevTxID: sampleTxID(),
		Vout:     0,
		ValueSat: 100_000, // 0.001 BTC
		Sequence: 0xffffffff,
	}}
	// Pay 90_000 sat to a recipient P2WPKH scriptPubKey (0x0014 || 20-byte hash);
	// the 10_000 sat difference is the miner fee.
	recipient := make([]byte, 22)
	recipient[0] = 0x00
	recipient[1] = 0x14
	for i := 2; i < 22; i++ {
		recipient[i] = byte(i)
	}
	outputs := []kobe.BtcTxOutput{{ValueSat: 90_000, ScriptPubKey: recipient}}

	// BIP-143 sighash for input 0, SIGHASH_ALL.
	sighash, err := kobe.BtcSegwitSighash(2, inputs, outputs, 0, groupPub, 0)
	if err != nil {
		die("sighash: %v", err)
	}
	fmt.Printf("BIP-143 sighash   : %x\n", sighash)
	fmt.Printf("intent            : spend 100000 sat UTXO -> 90000 sat recipient (10000 fee)\n")

	fmt.Println("threshold-signing the BIP-143 sighash with shares {1,3}...")
	sig, err := kobe.ThresholdSign([]kobe.KeyShare{shares[0], shares[2]}, sighash[:])
	if err != nil {
		die("threshold sign: %v", err)
	}

	// Recover the signer's pubkey from (r,s,v) and re-derive its Bitcoin address:
	// the exact check a node makes when validating the witness signature.
	recPub, err := ethcrypto.SigToPub(sighash[:], sig.Bytes())
	if err != nil {
		die("recover pubkey: %v", err)
	}
	recAddr, err := kobe.BtcP2WPKHAddress(recPub)
	if err != nil {
		die("recovered address: %v", err)
	}
	if recAddr != btcAddr {
		die("ADDRESS MISMATCH: recovered %s != group %s", recAddr, btcAddr)
	}
	fmt.Println()
	fmt.Println("SIGNED, chain-valid Bitcoin input from a threshold signature:")
	fmt.Printf("  signature r     : %x\n", sig.R)
	fmt.Printf("  signature s     : %x\n", sig.S)
	fmt.Printf("  recovered addr  : %s  == group address ✓\n", recAddr)
	fmt.Println("  the group private key was never assembled in one place.")
	fmt.Println("  (witness stack: [DER(r,s)||0x01, compressed-pubkey] — ready for tx assembly)")
}

func sampleTxID() [32]byte {
	var t [32]byte
	for i := range t {
		t[i] = byte(0xa0 + (i % 16))
	}
	return t
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}
