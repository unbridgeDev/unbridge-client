package kobeecdsa

import (
	"crypto/ecdsa"
	"fmt"

	ethcommon "github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// GroupAddress derives the Ethereum address of the group public key, i.e.
// keccak256(uncompressed_pubkey[1:])[12:]. This is the account the threshold
// network controls: there is no single private key behind it.
func GroupAddress(pub *ecdsa.PublicKey) ethcommon.Address {
	return ethcrypto.PubkeyToAddress(*pub)
}

// RecoverAddress recovers the signer's Ethereum address from a threshold
// signature over a 32-byte hash, using go-ethereum's Ecrecover path — the exact
// primitive a real ETH node runs to validate a transaction signature. This is
// an INDEPENDENT verifier: it does not touch tss-lib, so a match proves the
// signature is a genuine, on-chain-valid ECDSA signature, not merely "valid
// under the library that produced it".
func RecoverAddress(hash32 []byte, sig *EthSignature) (ethcommon.Address, error) {
	if len(hash32) != 32 {
		return ethcommon.Address{}, fmt.Errorf("hash must be 32 bytes, got %d", len(hash32))
	}
	pub, err := ethcrypto.SigToPub(hash32, sig.Bytes())
	if err != nil {
		return ethcommon.Address{}, fmt.Errorf("ecrecover failed: %w", err)
	}
	return ethcrypto.PubkeyToAddress(*pub), nil
}
