package kobenet

// Milestone 8 — operator transport hardening.
//
// The Milestone-6 transport authenticated every frame with an application-layer
// Ed25519 signature over a hand-rolled challenge-response handshake. That proved
// a peer can't be impersonated on the wire, but it left the BYTES in cleartext:
// a network observer saw every tss-lib protocol message, and the only thing
// standing between an attacker and the mesh was our own handshake code.
//
// M8 puts the connection inside mutual TLS (Go's crypto/tls — the audited
// stdlib stack, never our own record layer). Every operator presents an X.509
// client+server certificate; BOTH ends require and verify the other's
// certificate (tls.RequireAndVerifyClientCert on the listener, a verifying
// client config on the dialer). On top of TLS's own chain validation we PIN the
// peer: the certificate a peer presents must chain to the operator-set CA AND
// its leaf public key must equal the key we pinned for the operator index it
// claims. That binds the TLS identity to the same per-operator identity the rest
// of the system already keys on, so a valid-but-wrong operator's cert is
// rejected exactly like a forged one.
//
// What TLS gives us that the M6 handshake did not:
//   - Confidentiality: the tss-lib wire bytes are encrypted in transit.
//   - Integrity + replay protection at the record layer (AEAD, sequence
//     numbers) — for the whole stream, not just per-Envelope.
//   - A vetted handshake (TLS 1.3 only here) instead of our own nonce dance.
//
// The Envelope's Ed25519 signature is KEPT on top of TLS, not removed: TLS
// authenticates the CHANNEL (this socket is operator j), while the Envelope
// signature authenticates the MESSAGE end-to-end and binds it to (session,
// from, to, payload). Defence in depth, and the Envelope signature is what a
// future store-and-forward relay would still need.

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

// tlsMaterial is one operator's TLS key material plus the pinned trust state for
// the whole operator set. leafCert is THIS operator's certificate (presented to
// peers); caPool is the operator-set CA used to validate any peer's cert chain;
// pinnedSPKI maps an operator index to the DER SPKI (SubjectPublicKeyInfo) of
// that operator's pinned leaf key, so a chain-valid cert that isn't the one we
// pinned for that index is still rejected.
type tlsMaterial struct {
	self       int
	leafCert   tls.Certificate
	caPool     *x509.CertPool
	pinnedSPKI map[int][]byte
}

// minTLS is the floor: TLS 1.3 only. No downgrade, no legacy ciphers — 1.3's
// suites are all AEAD with forward secrecy, so there is nothing to negotiate
// down to.
const minTLS = tls.VersionTLS13

// serverConfig is the *tls.Config this operator uses for connections peers DIAL
// in to. It presents our leaf cert and requires + verifies the dialer's cert.
func (m *tlsMaterial) serverConfig() *tls.Config {
	return &tls.Config{
		Certificates:          []tls.Certificate{m.leafCert},
		ClientAuth:            tls.RequireAndVerifyClientCert,
		ClientCAs:             m.caPool,
		MinVersion:            minTLS,
		VerifyPeerCertificate: m.verifyPinned,
	}
}

// clientConfig is the *tls.Config this operator uses when it DIALS a peer. It
// presents our leaf cert and verifies the listener's cert against the CA + pin.
//
// ServerName is set to the operator-set CA's name purely to satisfy TLS's SNI /
// hostname-verification machinery; the real identity check is the pin in
// verifyPinned, not the hostname. We do NOT set InsecureSkipVerify — the chain
// is fully validated against caPool; we only override the leaf-identity check
// with a stricter, pin-based one.
func (m *tlsMaterial) clientConfig() *tls.Config {
	return &tls.Config{
		Certificates:          []tls.Certificate{m.leafCert},
		RootCAs:               m.caPool,
		MinVersion:            minTLS,
		ServerName:            certServerName,
		VerifyPeerCertificate: m.verifyPinned,
	}
}

// verifyPinned runs AFTER crypto/tls has already validated the peer's
// certificate chain against the operator-set CA (ClientCAs / RootCAs). It adds
// the operator-set-specific check the generic TLS stack cannot do: the peer's
// leaf public key must be one we pinned for SOME operator in the set. Pinning to
// the SPECIFIC claimed index happens at the application layer in the handshake
// (verifyConnIdentity), once we have read the peer's claimed index; here we only
// need to guarantee the cert belongs to a member of the set.
//
// verifiedChains is non-empty because both configs require verification (no
// InsecureSkipVerify), so we can trust rawCerts[0] is the validated leaf.
func (m *tlsMaterial) verifyPinned(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("tls: peer presented no certificate")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("tls: parse peer leaf: %w", err)
	}
	spki := leaf.RawSubjectPublicKeyInfo
	for _, pinned := range m.pinnedSPKI {
		if bytesEqual(spki, pinned) {
			return nil
		}
	}
	return fmt.Errorf("tls: peer leaf key is not pinned for any operator in the set (untrusted cert rejected)")
}

// peerIndexForSPKI returns the operator index whose pinned leaf key matches the
// given SPKI, or -1. Used by the handshake to confirm the TLS-authenticated cert
// belongs to the SAME operator index the peer claims on the wire.
func (m *tlsMaterial) peerIndexForSPKI(spki []byte) int {
	for idx, pinned := range m.pinnedSPKI {
		if bytesEqual(spki, pinned) {
			return idx
		}
	}
	return -1
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// pubFromCertDER extracts the Ed25519 identity public key embedded as the leaf
// certificate's subject public key. Operator leaf certs use the operator's
// Ed25519 identity key as the cert key, so the TLS identity and the
// Envelope-signing identity are literally the same key.
func pubFromCertDER(der []byte) (ed25519.PublicKey, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("cert public key is not ed25519")
	}
	return pub, nil
}
