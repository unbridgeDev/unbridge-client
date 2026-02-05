// Package kobeecdsa is Distin's off-chain GG20 threshold-ECDSA signer.
//
// This is the secp256k1 / threshold-ECDSA half of the off-chain MPC signer that
// the on-chain `distin` program stubs (the `Gg20Secp256k1` scheme in state.rs,
// used for the EVM / BTC / Tron branch). The Ed25519 (FROST) half lives in the
// sibling Rust crate engine/kobe/.
//
// It wraps Binance's audited, production-proven tss-lib (the reference GG18/GG20
// implementation) — no hand-rolled curve math or MPC rounds. The flow is:
//
//	DistributedKeyGen(n, threshold)  -> n key shares + one group public key
//	ThresholdSign(keys, signers, m)  -> one standard ECDSA (r, s, v) signature
//
// The signature it returns is a byte-exact standard secp256k1 ECDSA signature
// with an Ethereum recovery id, i.e. exactly what `Ecrecover` on a real ETH node
// accepts. The group private key is never reconstructed: each signer holds only
// a Shamir share and the signing protocol combines partials without ever forming
// the secret.
package kobeecdsa

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"runtime"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"
	keygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	signing "github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v2/tss"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

func init() {
	// Distin's EVM/BTC/Tron branch is secp256k1, not the tss-lib default (P-256).
	tss.SetCurve(ethcrypto.S256())
}

// KeyShare is one party's secret keygen output. It is never serialized off this
// process in this milestone; the share secret stays local to the party.
type KeyShare struct {
	ID   *tss.PartyID
	Save keygen.LocalPartySaveData
}

// GroupPublicKey is the shared secp256k1 public key. The corresponding private
// key is never materialised — it only ever exists split across the shares.
func (k KeyShare) groupPub() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: tss.EC(),
		X:     k.Save.ECDSAPub.X(),
		Y:     k.Save.ECDSAPub.Y(),
	}
}

// DistributedKeyGen runs the GG20 distributed key generation among n simulated
// parties (in-process, fully connected) and returns one KeyShare per party plus
// the shared group public key. `threshold` is the tss-lib t: any t+1 shares can
// later sign. For 2-of-3, pass n=3, threshold=1.
//
// No dealer holds the full key: each party derives its own Shamir share through
// the protocol, and the group key is reconstructed in the exponent only.
func DistributedKeyGen(n, threshold int) ([]KeyShare, *ecdsa.PublicKey, error) {
	if threshold < 1 || threshold >= n {
		return nil, nil, fmt.Errorf("need 1 <= threshold < n, got threshold=%d n=%d", threshold, n)
	}

	pIDs := tss.GenerateTestPartyIDs(n)
	ctx := tss.NewPeerContext(pIDs)

	outCh := make(chan tss.Message, n*n)
	endCh := make(chan *keygen.LocalPartySaveData, n)
	errCh := make(chan *tss.Error, n)

	parties := make([]*keygen.LocalParty, n)
	for i := 0; i < n; i++ {
		params := tss.NewParameters(tss.S256(), ctx, pIDs[i], n, threshold)
		// Pre-params (Paillier safe primes) are the expensive part of GG20
		// keygen. Generating them per party is what makes DKG slow.
		pre, err := keygen.GeneratePreParams(1 * time.Minute)
		if err != nil {
			return nil, nil, fmt.Errorf("pre-params for party %d: %w", i, err)
		}
		P := keygen.NewLocalParty(params, outCh, endCh, *pre).(*keygen.LocalParty)
		parties[i] = P
		go func(P *keygen.LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	saves := make([]keygen.LocalPartySaveData, n)
	done := 0
	for done < n {
		select {
		case err := <-errCh:
			return nil, nil, fmt.Errorf("keygen protocol error: %s", err.Error())
		case msg := <-outCh:
			route(parties, msg, errCh)
		case save := <-endCh:
			idx := indexOf(pIDs, save.ShareID)
			saves[idx] = *save
			done++
		}
	}

	shares := make([]KeyShare, n)
	for i := range parties {
		shares[i] = KeyShare{ID: pIDs[i], Save: saves[i]}
	}
	return shares, shares[0].groupPub(), nil
}

// EthSignature is a standard secp256k1 ECDSA signature in the exact form an
// Ethereum node consumes: 32-byte R, 32-byte S, and a single recovery byte V
// (0 or 1) that lets `Ecrecover` recover the signer's public key.
type EthSignature struct {
	R [32]byte
	S [32]byte
	V byte
}

// Bytes returns the 65-byte [R || S || V] form go-ethereum's SigToPub expects.
func (s EthSignature) Bytes() []byte {
	out := make([]byte, 65)
	copy(out[0:32], s.R[:])
	copy(out[32:64], s.S[:])
	out[64] = s.V
	return out
}

// ThresholdSign produces one standard ECDSA signature over the 32-byte message
// hash `hash32` using exactly the shares in `signers` (a subset of the keygen
// shares; len(signers) must be threshold+1). The other shares stay offline.
//
// The group private key is never assembled: the parties run the GG20 signing
// rounds and combine partial signatures into a single (r, s, v) that verifies
// against the group public key. The recovery byte is set so go-ethereum's
// Ecrecover / SigToPub recovers the group key from the signature.
func ThresholdSign(signers []KeyShare, hash32 []byte) (*EthSignature, error) {
	if len(hash32) != 32 {
		return nil, fmt.Errorf("message hash must be 32 bytes, got %d", len(hash32))
	}
	k := len(signers)
	if k < 2 {
		return nil, fmt.Errorf("need at least 2 signers for a threshold signature, got %d", k)
	}

	unsorted := make(tss.UnSortedPartyIDs, k)
	for i, s := range signers {
		unsorted[i] = s.ID
	}
	signPIDs := tss.SortPartyIDs(unsorted)
	ctx := tss.NewPeerContext(signPIDs)
	// threshold for the signing committee: t+1 = k, so t = k-1.
	threshold := k - 1

	msg := new(big.Int).SetBytes(hash32)

	outCh := make(chan tss.Message, k*k)
	endCh := make(chan *common.SignatureData, k)
	errCh := make(chan *tss.Error, k)

	// Map each sorted signing PID back to its KeyShare save data.
	saveByID := make(map[string]keygen.LocalPartySaveData, k)
	for _, s := range signers {
		saveByID[s.ID.Id] = s.Save
	}

	parties := make([]*signing.LocalParty, k)
	for i := 0; i < k; i++ {
		params := tss.NewParameters(tss.S256(), ctx, signPIDs[i], k, threshold)
		P := signing.NewLocalParty(msg, params, saveByID[signPIDs[i].Id], outCh, endCh).(*signing.LocalParty)
		parties[i] = P
		go func(P *signing.LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var sig *common.SignatureData
	done := 0
	for done < k {
		select {
		case err := <-errCh:
			return nil, fmt.Errorf("signing protocol error: %s", err.Error())
		case msg := <-outCh:
			routeSign(parties, msg, errCh)
		case s := <-endCh:
			if sig == nil {
				sig = s
			}
			done++
		}
	}
	runtime.GC()

	out := &EthSignature{V: sig.SignatureRecovery[0]}
	copy(out.R[:], leftPad32(sig.R))
	copy(out.S[:], leftPad32(sig.S))
	return out, nil
}

// --- message routing for the in-process party mesh ---

func route(parties []*keygen.LocalParty, msg tss.Message, errCh chan<- *tss.Error) {
	dest := msg.GetTo()
	if dest == nil { // broadcast
		for _, P := range parties {
			if P.PartyID().Index == msg.GetFrom().Index {
				continue
			}
			update(P, msg, errCh)
		}
		return
	}
	for _, to := range dest {
		update(parties[to.Index], msg, errCh)
	}
}

func routeSign(parties []*signing.LocalParty, msg tss.Message, errCh chan<- *tss.Error) {
	dest := msg.GetTo()
	if dest == nil {
		for _, P := range parties {
			if P.PartyID().Index == msg.GetFrom().Index {
				continue
			}
			update(P, msg, errCh)
		}
		return
	}
	for _, to := range dest {
		update(parties[to.Index], msg, errCh)
	}
}

func update(party tss.Party, msg tss.Message, errCh chan<- *tss.Error) {
	if party.PartyID() == msg.GetFrom() {
		return
	}
	bz, _, err := msg.WireBytes()
	if err != nil {
		errCh <- party.WrapError(err)
		return
	}
	pMsg, err := tss.ParseWireMessage(bz, msg.GetFrom(), msg.IsBroadcast())
	if err != nil {
		errCh <- party.WrapError(err)
		return
	}
	go func() {
		if _, err := party.Update(pMsg); err != nil {
			errCh <- err
		}
	}()
}

func indexOf(pIDs tss.SortedPartyIDs, shareID *big.Int) int {
	for i, p := range pIDs {
		if p.KeyInt().Cmp(shareID) == 0 {
			return i
		}
	}
	return -1
}

func leftPad32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}
