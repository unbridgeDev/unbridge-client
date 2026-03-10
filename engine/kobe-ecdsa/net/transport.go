// Package kobenet is Distin's real wire transport for the GG20 operator network.
//
// Milestone 6 turns the in-process party mesh (engine/kobe-ecdsa/tss.go, where N
// parties are goroutines sharing in-memory channels) into N genuinely separate
// operator PROCESSES that talk over real TCP sockets. Each operator holds only
// its own key share and exchanges tss-lib's wire messages (the bytes from
// tss.Message.WireBytes()) with its peers over the network, with every message
// authenticated by the sender's Ed25519 identity key.
//
// The transport is deliberately the smallest thing that is genuinely a network:
//
//   - TCP (Go stdlib net), one connection per peer pair, length-prefixed frames.
//     tss-lib already hands us a transport-ready []byte + routing flags, so a
//     byte stream is the natural fit; no gRPC/proto/ws layer earns its keep on
//     localhost.
//   - Full mesh: operator i dials operator j when i < j; the higher index
//     accepts. Exactly one connection per pair, used in both directions.
//   - Authentication: each operator has an Ed25519 identity key. Every envelope
//     is signed over (session, from, to, round-bytes); the receiver verifies
//     against the sender's pinned identity public key. A spoofed or tampered
//     frame fails verification and the operator aborts cleanly.
//
// This is a localhost proof of real networking, not a hardened production
// network: there is no TLS, no PKI, no peer discovery, no reconnection. The
// identity-key signing proves a peer can't be impersonated on the wire; that is
// the property the milestone is about.
package kobenet

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
)

// Peer is the static directory entry for one operator: its index in the party
// ordering, the host:port it listens on, and its Ed25519 identity public key.
// Every operator is configured with the full peer list up front (no discovery).
type Peer struct {
	Index   int               `json:"index"`
	Addr    string            `json:"addr"`
	PubKey  ed25519.PublicKey `json:"-"`
	PubHex  string            `json:"pubkey"` // hex of PubKey, for the JSON config
	Moniker string            `json:"moniker"`
	// CertDER is the operator's M8 leaf certificate (DER), pinned for mutual
	// TLS. Populated from the peer's PEM cert file; empty in the legacy
	// pre-TLS path (the in-process tests still use raw sockets).
	CertDER []byte `json:"-"`
}

// Envelope is one authenticated wire message. Payload is a tss-lib WireBytes()
// blob; the routing flags mirror tss.Message (IsBroadcast / GetTo). Sig is an
// Ed25519 signature by the sender's identity key over signingBytes(e).
type Envelope struct {
	Session     string `json:"session"`
	From        int    `json:"from"`
	To          int    `json:"to"` // -1 = broadcast
	IsBroadcast bool   `json:"is_broadcast"`
	Fin         bool   `json:"fin"` // control frame: sender finished, draining
	Payload     []byte `json:"payload"`
	Sig         []byte `json:"sig"`
}

// signingBytes is the canonical byte string an Envelope's identity signature
// covers: session || from || to || is_broadcast || payload. Including from/to and
// the session id binds the signature to the routing and the run, so a captured
// frame can't be replayed into a different session or re-addressed.
func signingBytes(e *Envelope) []byte {
	b := make([]byte, 0, len(e.Session)+len(e.Payload)+16)
	b = append(b, e.Session...)
	var n [8]byte
	binary.BigEndian.PutUint32(n[:4], uint32(e.From))
	b = append(b, n[:4]...)
	binary.BigEndian.PutUint32(n[:4], uint32(e.To))
	b = append(b, n[:4]...)
	if e.IsBroadcast {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	if e.Fin {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	b = append(b, e.Payload...)
	return b
}

// Sign fills e.Sig with the sender's Ed25519 signature over signingBytes(e).
func (e *Envelope) Sign(priv ed25519.PrivateKey) {
	e.Sig = ed25519.Sign(priv, signingBytes(e))
}

// Verify checks e.Sig against the claimed sender's pinned identity public key.
// A false return means the frame was spoofed or tampered in flight.
func (e *Envelope) Verify(senderPub ed25519.PublicKey) bool {
	return ed25519.Verify(senderPub, signingBytes(e), e.Sig)
}

// writeFrame writes a 4-byte big-endian length prefix followed by the JSON of e.
// A length prefix is what makes the TCP byte stream message-framed.
func writeFrame(w io.Writer, e *Envelope) error {
	bz, err := json.Marshal(e)
	if err != nil {
		return err
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(bz)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(bz)
	return err
}

// readFrame reads one length-prefixed Envelope. A frame larger than maxFrame is
// rejected (defends against a peer claiming an absurd length).
const maxFrame = 16 << 20 // 16 MiB; tss-lib keygen messages are well under this

func readFrame(r io.Reader) (*Envelope, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > maxFrame {
		return nil, fmt.Errorf("bad frame length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	var e Envelope
	if err := json.Unmarshal(buf, &e); err != nil {
		return nil, fmt.Errorf("malformed frame: %w", err)
	}
	return &e, nil
}

// conn wraps a net.Conn with a write mutex (multiple goroutines may send on the
// same peer connection) and the peer's verified index.
type conn struct {
	peer int
	nc   net.Conn
	wmu  sync.Mutex
}

func (c *conn) send(e *Envelope) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return writeFrame(c.nc, e)
}
