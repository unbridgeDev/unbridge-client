// eth-tx — prove the GG20 group can authorize a REAL Ethereum transaction.
//
// The rest of the stack shows the operators produce a valid signature over a
// 32-byte hash. This closes the product gap: the hash here is the sighash of an
// actual EIP-1559 transaction, the threshold signature is assembled back into a
// broadcastable signed transaction, and go-ethereum recovers its sender to the
// group address — exactly what an Ethereum node checks before accepting it.
//
//	go run ./cmd/eth-tx -to 0xRecipient -value 0.001 -nonce 0
//
// The run proves construction + threshold-signing + sender-recovery offline (no
// funds, no RPC). It prints the signed raw transaction plus a ready curl for
// eth_sendRawTransaction — to actually land it on Sepolia, fund the group
// address from a faucet, set -nonce to the group account's current nonce, and
// POST the raw tx to any Sepolia RPC.
package main

import (
	"flag"
	"fmt"
	"math/big"
	"os"

	"crypto/ecdsa"

	kobe "github.com/distin/kobe-ecdsa"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// Sepolia. The group ETH address is chain-agnostic; only the chainId differs.
var sepoliaChainID = big.NewInt(11155111)

func main() {
	toFlag := flag.String("to", "0x000000000000000000000000000000000000dEaD", "recipient address")
	valEth := flag.Float64("value", 0.001, "value in ETH")
	nonceFlag := flag.Uint64("nonce", 0, "group account nonce (set to the real value before broadcasting)")
	sharesPath := flag.String("shares", "", "load an existing GG20 group from this shares file (default: fresh DKG)")
	flag.Parse()

	// 1. Group key: reuse an on-disk group if given, else a fresh 2-of-3 DKG.
	var shares []kobe.KeyShare
	var groupPub *ecdsa.PublicKey
	var err error
	if *sharesPath != "" {
		shares, groupPub, err = kobe.LoadShares(*sharesPath)
		if err != nil {
			die("load shares: %v", err)
		}
	} else {
		fmt.Println("running fresh 2-of-3 GG20 DKG (safe-prime gen is slow)...")
		shares, groupPub, err = kobe.DistributedKeyGen(3, 1)
		if err != nil {
			die("DKG: %v", err)
		}
	}
	groupAddr := kobe.GroupAddress(groupPub)
	fmt.Printf("group ETH address : %s\n", groupAddr.Hex())

	to := common.HexToAddress(*toFlag)
	value := ethToWei(*valEth)

	// 2. Build the EIP-1559 transaction and take its real sighash. Fees are
	// generous fixed caps (fine for Sepolia); nonce is caller-supplied.
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   sepoliaChainID,
		Nonce:     *nonceFlag,
		GasTipCap: big.NewInt(1_500_000_000),  // 1.5 gwei
		GasFeeCap: big.NewInt(30_000_000_000), // 30 gwei
		Gas:       21000,
		To:        &to,
		Value:     value,
	})
	signer := types.LatestSignerForChainID(sepoliaChainID)
	sighash := signer.Hash(tx)
	fmt.Printf("tx sighash (32B)  : %s\n", sighash.Hex())
	fmt.Printf("intent            : %s ETH -> %s (nonce %d)\n", weiToEthStr(value), to.Hex(), *nonceFlag)

	// 4. Threshold-sign the REAL sighash with 2 of 3 shares (party 2 offline).
	fmt.Println("threshold-signing the tx sighash with shares {1,3}...")
	sig, err := kobe.ThresholdSign([]kobe.KeyShare{shares[0], shares[2]}, sighash.Bytes())
	if err != nil {
		die("threshold sign: %v", err)
	}

	// 5. Assemble the signed transaction and recover its sender.
	signedTx, err := tx.WithSignature(signer, sig.Bytes())
	if err != nil {
		die("attach signature: %v", err)
	}
	sender, err := types.Sender(signer, signedTx)
	if err != nil {
		die("recover sender: %v", err)
	}
	if sender != groupAddr {
		die("SENDER MISMATCH: recovered %s != group %s", sender.Hex(), groupAddr.Hex())
	}
	raw, err := signedTx.MarshalBinary()
	if err != nil {
		die("encode: %v", err)
	}
	fmt.Println()
	fmt.Println("SIGNED, chain-valid transaction assembled from a threshold signature:")
	fmt.Printf("  tx hash         : %s\n", signedTx.Hash().Hex())
	fmt.Printf("  recovered sender: %s  == group address ✓\n", sender.Hex())
	fmt.Printf("  raw tx (0x)     : 0x%x\n", raw)
	fmt.Println("  the group private key was never assembled in one place.")

	// To land it: fund the group address on Sepolia, re-run with the real -nonce,
	// then POST the raw tx to any Sepolia RPC. No private key leaves the operators.
	fmt.Printf("\nTo broadcast (fund %s first, set the real -nonce):\n", groupAddr.Hex())
	fmt.Printf("  curl -s <SEPOLIA_RPC> -H 'content-type: application/json' \\\n")
	fmt.Printf("    -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_sendRawTransaction\",\"params\":[\"0x%x\"]}'\n", raw)
}

func ethToWei(eth float64) *big.Int {
	wei := new(big.Float).Mul(big.NewFloat(eth), big.NewFloat(1e18))
	out, _ := wei.Int(nil)
	return out
}

func weiToEthStr(wei *big.Int) string {
	f := new(big.Float).Quo(new(big.Float).SetInt(wei), big.NewFloat(1e18))
	return f.Text('f', 6)
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}
