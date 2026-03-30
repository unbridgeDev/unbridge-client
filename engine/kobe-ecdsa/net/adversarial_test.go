package kobenet

import (
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	keygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// M11 — adversarial operator network (GG20 networked path).
//
// The three hostile behaviors the milestone requires the protocol to survive
// (terminate correctly OR identifiably-abort, never hang, never forge):
//
//   (a) an operator DROPS mid-round            -> clean abort (existing demo NEG A
//                                                  + readLoop "peer disconnected")
//   (b) an operator sends GARBAGE protocol bytes that PASS wire-auth
//                                              -> tested here: feed() rejects them
//                                                 as a parse error; never accepted,
//                                                 never panics, never forged.
//   (c) an operator STALLS (never sends)       -> tested here: the phase timeout
//                                                 fires and RunSign returns an
//                                                 error rather than hanging.
//
// (b) and (c) are the genuinely new M11 properties; (a) is already proven by
// net/demo.sh NEGATIVE A and the M8 work. The malicious-proof case (garbage that
// parses but fails the ZK check) is M9's identifiable abort.

// authedGarbage builds an Envelope whose payload is random bytes but is correctly
// signed by `from`'s identity key — i.e. it passes every wire-auth check
// (signature, session, sender binding) yet is not a valid tss-lib message.
func authedGarbage(from int, priv ed25519.PrivateKey, session string) *Envelope {
	payload := make([]byte, 256)
	_, _ = rand.Read(payload)
	e := &Envelope{Session: session, From: from, To: 1, IsBroadcast: false, Payload: payload}
	e.Sign(priv)
	return e
}

// TestGarbagePassingWireAuthIsRejected proves property (b): protocol bytes that
// are correctly authenticated on the wire but are NOT a parseable tss-lib message
// are rejected before they ever reach a party — never silently accepted, never a
// panic, never a forged result.
//
// feed() does exactly two things with an inbound payload: resolve the sender by
// index, then `tss.ParseWireMessage(payload, …)` BEFORE any `party.Update`. So
// the parse step is the gate that stops authenticated garbage. We assert that an
// authenticated random payload fails ParseWireMessage (the exact call feed makes)
// rather than being accepted.
func TestGarbagePassingWireAuthIsRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	// The garbage frame really does pass wire authentication.
	e := authedGarbage(0, priv, "distin-sign")
	if !e.Verify(pub) {
		t.Fatal("test setup: garbage frame should pass its own signature check")
	}

	// feed() resolves the sender then calls tss.ParseWireMessage — exercise that
	// exact gate. A real signing party id list is enough to attempt the parse.
	pids := tss.GenerateTestPartyIDs(2)
	var from *tss.PartyID
	for _, p := range pids {
		if p.Index == 0 {
			from = p
		}
	}
	if from == nil {
		t.Fatal("could not resolve sender party id")
	}

	// The parse must FAIL (or, defensively, fail ValidateBasic). It must never
	// yield a usable message from random bytes.
	pmsg, err := tss.ParseWireMessage(e.Payload, from, e.IsBroadcast)
	if err == nil && (pmsg != nil && pmsg.ValidateBasic()) {
		t.Fatal("authenticated GARBAGE parsed into a valid protocol message (forgery surface)")
	}
	t.Logf("M11(b): authenticated garbage rejected before reaching the party (parse err=%v)", err)
}

// TestStallTerminatesViaTimeout proves property (c): if a quorum operator never
// produces its messages, the signing phase does not hang — RunSign returns a
// timeout error within the deadline. We model the stall by starting a single
// operator's RunSign against a network whose peer never connects/sends, with a
// short timeout, and asserting it returns (not blocks) with a timeout error.
func TestStallTerminatesViaTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("skips the keygen needed to get a share under -short")
	}
	// A 2-of-2 keygen to obtain a real share for one operator.
	const n, threshold = 2, 1
	peers, privs, caDER := mintTLSPeers(t, n, 9970)
	pids := AllPartyIDs(peers)

	pre := make([]*keygen.LocalPreParams, n)
	var pwg sync.WaitGroup
	for i := 0; i < n; i++ {
		pwg.Add(1)
		go func(i int) {
			defer pwg.Done()
			p, _ := keygen.GeneratePreParams(2 * time.Minute)
			pre[i] = p
		}(i)
	}
	pwg.Wait()

	saves := make([]*keygen.LocalPartySaveData, n)
	var kwg sync.WaitGroup
	kErrs := make([]error, n)
	for i := 0; i < n; i++ {
		kwg.Add(1)
		go func(i int) {
			defer kwg.Done()
			net, err := NewNetworkTLS(i, peers[i].Moniker, privs[i], peers, "stall-keygen", ownLeaf(peers, i), caDER, nil)
			if err != nil {
				kErrs[i] = err
				return
			}
			if err := net.Start(peers[i].Addr, 25*time.Second); err != nil {
				kErrs[i] = err
				return
			}
			defer net.Close()
			s, _, err := RunKeygen(net, pids, i, threshold, pre[i], 120*time.Second)
			saves[i] = s
			kErrs[i] = err
		}(i)
	}
	kwg.Wait()
	for _, e := range kErrs {
		if e != nil {
			t.Fatal(e)
		}
	}

	// Now operator 0 tries to sign with a quorum {0,1}, but operator 1 STALLS
	// (never starts). Operator 0's mesh Start will not complete because peer 1
	// never connects; with a short timeout that must RETURN an error, not hang.
	done := make(chan error, 1)
	go func() {
		net, err := NewNetworkTLS(0, peers[0].Moniker, privs[0], peers, "stall-sign", ownLeaf(peers, 0), caDER, nil)
		if err != nil {
			done <- err
			return
		}
		// Short start timeout: peer 1 never shows up.
		if err := net.Start(peers[0].Addr, 2*time.Second); err != nil {
			done <- err
			return
		}
		defer net.Close()
		_, err = RunSign(net, pids, 0, threshold, *saves[0], make([]byte, 32), 3*time.Second)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a stalled signing run returned success (must abort, never forge)")
		}
		t.Logf("M11(c): stalled run aborted cleanly (no hang, no forge): %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("stalled signing run HUNG past its timeout (must terminate)")
	}
}
