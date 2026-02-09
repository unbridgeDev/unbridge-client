package kobeecdsa

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	keygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// persistedShare is the on-disk form of one party's keygen output. tss-lib's
// own test fixtures serialize LocalPartySaveData with encoding/json, so we reuse
// that; the PartyID is not part of the save data, so we persist the three fields
// (id, moniker, key) needed to reconstruct it deterministically with NewPartyID.
type persistedShare struct {
	ID      string                    `json:"id"`
	Moniker string                    `json:"moniker"`
	Key     string                    `json:"key"` // decimal big.Int (the ShareID)
	Save    keygen.LocalPartySaveData `json:"save"`
}

// KeyShareFile is the JSON document written by `keygen` and read by `sign`. It
// holds all n shares plus the group public key so the loader can re-derive the
// group ETH address without re-running keygen. The share secrets live in this
// file; in production each share would stay on its own operator's host. Here the
// in-process simulation writes them together so a separate `sign` invocation can
// drive the quorum.
type KeyShareFile struct {
	Threshold int              `json:"threshold"` // tss-lib t (t+1 sign)
	GroupPubX string           `json:"group_pub_x"`
	GroupPubY string           `json:"group_pub_y"`
	Shares    []persistedShare `json:"shares"`
}

// SaveShares writes the keygen output to a JSON file.
func SaveShares(path string, shares []KeyShare, groupPub *ecdsa.PublicKey, threshold int) error {
	doc := KeyShareFile{
		Threshold: threshold,
		GroupPubX: groupPub.X.String(),
		GroupPubY: groupPub.Y.String(),
		Shares:    make([]persistedShare, len(shares)),
	}
	for i, s := range shares {
		doc.Shares[i] = persistedShare{
			ID:      s.ID.Id,
			Moniker: s.ID.Moniker,
			Key:     s.ID.KeyInt().String(),
			Save:    s.Save,
		}
	}
	bz, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal shares: %w", err)
	}
	if err := os.WriteFile(path, bz, 0o600); err != nil {
		return fmt.Errorf("write shares: %w", err)
	}
	return nil
}

// LoadShares reads the keygen output back from a JSON file, reconstructing the
// PartyID of each share. The returned shares are in the same order written, so a
// caller selects a quorum by index just like in-process keygen.
func LoadShares(path string) ([]KeyShare, *ecdsa.PublicKey, error) {
	bz, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read shares: %w", err)
	}
	var doc KeyShareFile
	if err := json.Unmarshal(bz, &doc); err != nil {
		return nil, nil, fmt.Errorf("unmarshal shares: %w", err)
	}
	shares := make([]KeyShare, len(doc.Shares))
	for i, ps := range doc.Shares {
		key, ok := new(big.Int).SetString(ps.Key, 10)
		if !ok {
			return nil, nil, fmt.Errorf("share %d: bad key %q", i, ps.Key)
		}
		shares[i] = KeyShare{
			ID:   tss.NewPartyID(ps.ID, ps.Moniker, key),
			Save: ps.Save,
		}
	}
	x, ok1 := new(big.Int).SetString(doc.GroupPubX, 10)
	y, ok2 := new(big.Int).SetString(doc.GroupPubY, 10)
	if !ok1 || !ok2 {
		return nil, nil, fmt.Errorf("bad group pubkey coords")
	}
	groupPub := &ecdsa.PublicKey{Curve: ethcrypto.S256(), X: x, Y: y}
	return shares, groupPub, nil
}
