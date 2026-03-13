package kobenet

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/bnb-chain/tss-lib/v2/tss"
)

// OperatorConfig is the on-disk identity + topology for one operator process.
// Each operator gets its OWN config file (distinct index, distinct identity key,
// distinct listen port, distinct share path) — that is what makes the three
// processes genuinely separate operators rather than three views of one secret.
//
// The identity private key authenticates this operator on the wire; the peer
// directory pins every other operator's identity PUBLIC key so an impostor that
// doesn't hold the matching private key is rejected at the handshake.
type OperatorConfig struct {
	Index       int    `json:"index"`
	Moniker     string `json:"moniker"`
	Listen      string `json:"listen"`       // host:port this operator listens on
	IdentityHex string `json:"identity_key"` // hex ed25519 private key (64 bytes)
	SharePath   string `json:"share_path"`   // path to THIS operator's single key share
	Peers       []Peer `json:"peers"`        // every operator incl. self (pubkeys only)
	// M8 mutual-TLS material. When all three are set the operator runs the
	// hardened mTLS transport; when absent it falls back to the legacy
	// Ed25519-handshake raw-socket path. CAPath is the operator-set CA cert
	// (shared); LeafPath is THIS operator's leaf cert; the peer directory's
	// per-operator cert files are named <dir>/op<i>.cert.pem alongside the CA.
	CAPath    string `json:"ca_cert,omitempty"`
	LeafPath  string `json:"leaf_cert,omitempty"`
	CertDir   string `json:"cert_dir,omitempty"` // dir holding op<i>.cert.pem for every peer
	TLSEnable bool   `json:"tls,omitempty"`
}

// LoadOperatorConfig reads and validates an operator config, decoding the
// identity private key and every peer's pinned public key from hex.
func LoadOperatorConfig(path string) (*OperatorConfig, ed25519.PrivateKey, []Peer, error) {
	bz, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read config: %w", err)
	}
	var c OperatorConfig
	if err := json.Unmarshal(bz, &c); err != nil {
		return nil, nil, nil, fmt.Errorf("parse config: %w", err)
	}
	privBz, err := hex.DecodeString(c.IdentityHex)
	if err != nil || len(privBz) != ed25519.PrivateKeySize {
		return nil, nil, nil, fmt.Errorf("bad identity key (want %d hex bytes)", ed25519.PrivateKeySize)
	}
	priv := ed25519.PrivateKey(privBz)
	peers := make([]Peer, len(c.Peers))
	for i, p := range c.Peers {
		pub, err := hex.DecodeString(p.PubHex)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, nil, nil, fmt.Errorf("peer %d: bad pubkey", p.Index)
		}
		p.PubKey = ed25519.PublicKey(pub)
		peers[i] = p
	}
	// When mutual TLS is enabled, attach each peer's pinned leaf cert (DER) now,
	// keyed by index, so it travels with the peer through any later quorum
	// re-indexing.
	if c.TLSEnable {
		for i := range peers {
			path := filepath.Join(c.CertDir, fmt.Sprintf("op%d.cert.pem", peers[i].Index))
			pemBz, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil, nil, nil, fmt.Errorf("peer %d: read leaf cert %s: %w", peers[i].Index, path, rerr)
			}
			der, derr := DecodeCertPEM(pemBz)
			if derr != nil {
				return nil, nil, nil, fmt.Errorf("peer %d: decode leaf cert: %w", peers[i].Index, derr)
			}
			peers[i].CertDER = der
		}
	}
	return &c, priv, peers, nil
}

// LoadCertPair reads the operator-set CA cert and this operator's own leaf cert
// (both PEM on disk) as DER, for building mutual-TLS material. Peer leaf certs
// are loaded separately and attached to the peer directory in LoadOperatorConfig.
func LoadCertPair(caPath, leafPath string) (caDER, ownLeafDER []byte, err error) {
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read CA cert: %w", err)
	}
	if caDER, err = DecodeCertPEM(caPEM); err != nil {
		return nil, nil, fmt.Errorf("decode CA cert: %w", err)
	}
	leafPEM, err := os.ReadFile(leafPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read own leaf cert: %w", err)
	}
	if ownLeafDER, err = DecodeCertPEM(leafPEM); err != nil {
		return nil, nil, fmt.Errorf("decode own leaf cert: %w", err)
	}
	return caDER, ownLeafDER, nil
}

// PartyIDFor builds the tss.PartyID for a peer index using a deterministic share
// key derived from the moniker order. For keygen the key just needs to be unique
// and stable; tss-lib sorts by it. We use (index+1) as the big-int key so the
// sort order matches the configured index order across all processes.
func PartyIDFor(p Peer) *tss.PartyID {
	return tss.NewPartyID(fmt.Sprintf("op-%d", p.Index), p.Moniker, big.NewInt(int64(p.Index+1)))
}

// AllPartyIDs builds the full sorted party ordering from the peer directory.
// Every operator process builds the identical ordering (same inputs), so the
// indices line up across processes.
func AllPartyIDs(peers []Peer) tss.SortedPartyIDs {
	unsorted := make(tss.UnSortedPartyIDs, len(peers))
	for i, p := range peers {
		unsorted[i] = PartyIDFor(p)
	}
	return tss.SortPartyIDs(unsorted)
}
