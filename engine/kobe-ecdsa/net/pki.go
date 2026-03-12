package kobenet

// PKI for the operator set (Milestone 8).
//
// A real operator network needs a real trust root, not a flat directory of
// pinned keys with no notion of issuance. This file builds the smallest honest
// PKI that earns the name:
//
//   - ONE operator-set CA (a self-signed Ed25519 root). Its private key signs
//     every operator's leaf certificate; its public cert is the single trust
//     anchor every operator validates peers against.
//   - ONE leaf certificate per operator, signed by the CA, whose subject public
//     key IS that operator's Ed25519 identity key. So an operator's TLS identity
//     and its Envelope-signing identity are the same key — there is exactly one
//     secret per operator, and possessing it is what membership means.
//
// This is a static enrolment model: the CA mints N leaves up front (see
// cmd/gen-pki) and is then offline. There is no online enrolment, no
// revocation list, no intermediate hierarchy — those are deliberate omissions
// for a fixed operator set and are called out in the M8 report as the next
// production steps. What IS real: certificate issuance under a single
// controlled root, mutual TLS, and per-operator pinning.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// certServerName is the CN/SAN baked into every operator leaf and used as the
// dialer's ServerName. Hostname verification is satisfied by this fixed name;
// the real peer-identity check is the public-key pin, not the hostname.
const certServerName = "distin-operator"

// caName is the operator-set CA's common name.
const caName = "distin-operator-set-ca"

// CA holds the operator-set certificate authority: its signed cert (the trust
// anchor distributed to every operator) and its private key (used only at
// enrolment time to mint leaves, then kept offline).
type CA struct {
	CertDER []byte
	priv    ed25519.PrivateKey
	cert    *x509.Certificate
}

// NewCA mints a fresh self-signed Ed25519 operator-set CA.
func NewCA(validity time.Duration) (*CA, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: caName},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true, // leaves only; no intermediates
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{CertDER: der, priv: priv, cert: cert}, nil
}

// IssueLeaf signs an operator leaf certificate whose subject public key is the
// operator's Ed25519 identity key. The CA never sees the operator's private key;
// it certifies the PUBLIC key, which is what binds "this identity key belongs to
// operator N of the set". moniker goes in the CN for human-readable transcripts.
func (ca *CA) IssueLeaf(operatorPub ed25519.PublicKey, moniker string, validity time.Duration) ([]byte, error) {
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: certServerName, OrganizationalUnit: []string{moniker}},
		DNSNames:     []string{certServerName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	return x509.CreateCertificate(rand.Reader, tmpl, ca.cert, operatorPub, ca.priv)
}

// serial returns a random 128-bit certificate serial number.
func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if n.Sign() == 0 {
		n = big.NewInt(1)
	}
	return n
}

// --- PEM helpers (cert material is stored PEM-encoded on disk) ---

// EncodeCertPEM wraps a DER certificate as PEM.
func EncodeCertPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// DecodeCertPEM unwraps a single PEM certificate block to DER.
func DecodeCertPEM(p []byte) ([]byte, error) {
	blk, _ := pem.Decode(p)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("not a CERTIFICATE PEM block")
	}
	return blk.Bytes, nil
}

// buildTLSMaterial assembles this operator's TLS state from its identity key,
// its own leaf cert (DER), the CA cert (DER), and the peer directory (each peer
// carries the DER of its pinned leaf cert). The leaf private key is the
// operator's Ed25519 identity key — the same key that signs Envelopes.
func buildTLSMaterial(self int, identity ed25519.PrivateKey, ownLeafDER, caDER []byte, peers []Peer) (*tlsMaterial, error) {
	caPool := x509.NewCertPool()
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}
	caPool.AddCert(caCert)

	leaf := tls.Certificate{
		Certificate: [][]byte{ownLeafDER},
		PrivateKey:  identity,
	}

	pinned := make(map[int][]byte, len(peers))
	for _, p := range peers {
		if len(p.CertDER) == 0 {
			return nil, fmt.Errorf("peer %d has no certificate in directory", p.Index)
		}
		c, err := x509.ParseCertificate(p.CertDER)
		if err != nil {
			return nil, fmt.Errorf("peer %d: parse leaf cert: %w", p.Index, err)
		}
		// Sanity: the pinned leaf's key must equal the pinned ed25519 identity
		// key, so the cert and the Envelope-verification key cannot diverge.
		certPub, ok := c.PublicKey.(ed25519.PublicKey)
		if !ok || !pubEqual(certPub, p.PubKey) {
			return nil, fmt.Errorf("peer %d: leaf cert key does not match pinned identity key", p.Index)
		}
		pinned[p.Index] = c.RawSubjectPublicKeyInfo
	}

	// Pin our own SPKI too, so peerIndexForSPKI can resolve our own cert if
	// needed and the set is complete.
	ownCert, err := x509.ParseCertificate(ownLeafDER)
	if err != nil {
		return nil, fmt.Errorf("parse own leaf: %w", err)
	}
	pinned[self] = ownCert.RawSubjectPublicKeyInfo

	return &tlsMaterial{
		self:       self,
		leafCert:   leaf,
		caPool:     caPool,
		pinnedSPKI: pinned,
	}, nil
}
