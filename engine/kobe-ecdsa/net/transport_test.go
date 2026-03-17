package kobenet

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
)

// TestEnvelopeAuthRejectsTamperAndSpoof proves the wire authentication: a frame
// signed by an operator's identity key verifies under that key, but fails if the
// payload is tampered, the routing is rewritten, or it is checked against a
// different (impostor) key. This is the property that stops a peer being spoofed
// or a message being forged on the wire.
func TestEnvelopeAuthRejectsTamperAndSpoof(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	impostorPub, _, _ := ed25519.GenerateKey(rand.Reader)

	e := &Envelope{Session: "distin-sign", From: 0, To: 2, IsBroadcast: false, Payload: []byte("round-2 payload")}
	e.Sign(priv)

	if !e.Verify(pub) {
		t.Fatal("genuine frame failed verification under its own identity key")
	}

	// Tamper the payload.
	bad := *e
	bad.Payload = append([]byte{}, e.Payload...)
	bad.Payload[0] ^= 0xff
	if bad.Verify(pub) {
		t.Fatal("tampered payload still verified (forgery not detected)")
	}

	// Rewrite the routing (re-address the frame).
	readdr := *e
	readdr.To = 1
	if readdr.Verify(pub) {
		t.Fatal("re-addressed frame still verified (routing not bound to signature)")
	}

	// Replay into a different session.
	crossSession := *e
	crossSession.Session = "distin-keygen"
	if crossSession.Verify(pub) {
		t.Fatal("cross-session frame still verified (session not bound)")
	}

	// Spoof: verify under an impostor key.
	if e.Verify(impostorPub) {
		t.Fatal("frame verified under the wrong identity key (impersonation possible)")
	}

	// FIN frames are signed too: a forged FIN must not pass.
	fin := &Envelope{Session: "distin-sign", From: 0, To: -1, IsBroadcast: true, Fin: true}
	fin.Sign(priv)
	if !fin.Verify(pub) {
		t.Fatal("genuine FIN failed verification")
	}
	forgedFin := *fin
	forgedFin.Fin = false // flip a signed control bit
	if forgedFin.Verify(pub) {
		t.Fatal("FIN control bit not bound to the signature")
	}
}

// TestFrameRoundTrip checks the length-prefixed framing survives a write/read.
func TestFrameRoundTrip(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	e := &Envelope{Session: "s", From: 1, To: -1, IsBroadcast: true, Payload: make([]byte, 5000)}
	e.Sign(priv)

	a, b := net.Pipe()
	go func() {
		if err := writeFrame(a, e); err != nil {
			t.Errorf("writeFrame: %v", err)
		}
	}()
	got, err := readFrame(b)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if got.From != e.From || got.IsBroadcast != e.IsBroadcast || len(got.Payload) != len(e.Payload) {
		t.Fatal("round-tripped frame differs from original")
	}
}
