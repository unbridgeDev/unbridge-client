package kobenet

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"
	"time"
)

// subset returns the peer directory restricted to the given global indices (the
// signing quorum). FROST keeps each operator's GLOBAL identifier (index+1) across
// keygen and signing — the share was dealt to that identifier — so unlike the
// GG20 path we do NOT re-index the quorum to dense local indices. The transport
// addresses by peer index and handles a sparse index set fine (it dials i<j).
func subset(peers []Peer, quorum []int, basePort int) []Peer {
	out := make([]Peer, 0, len(quorum))
	for _, gi := range quorum {
		p := peers[gi]
		p.Addr = fmt.Sprintf("127.0.0.1:%d", basePort+gi)
		out = append(out, p)
	}
	return out
}

// runFrostDKG runs a real FROST DKG across n separate operator Networks over
// mutual TLS, returning each operator's key share, the shared public package,
// and the 32-byte group key. Each operator is its own goroutine + Network +
// port, exactly like the multi-process demo but in one test binary.
func runFrostDKG(t *testing.T, peers []Peer, privs []ed25519.PrivateKey, caDER []byte, basePort int) (shares, pubPkgs [][]byte, groupKey []byte) {
	t.Helper()
	n := len(peers)
	dkgPeers := subset(peers, seq(n), basePort)
	shares = make([][]byte, n)
	pubPkgs = make([][]byte, n)
	groupKeys := make([][]byte, n)
	errs := make([]error, n)

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			net, err := NewNetworkTLS(i, dkgPeers[i].Moniker, privs[i], dkgPeers, "frost-keygen", dkgPeers[i].CertDER, caDER, nil)
			if err != nil {
				errs[i] = fmt.Errorf("op%d tls material: %w", i, err)
				return
			}
			if err := net.Start(dkgPeers[i].Addr, 20*time.Second); err != nil {
				errs[i] = fmt.Errorf("op%d mesh: %w", i, err)
				return
			}
			defer net.Close()
			peerIdxs := others(n, i)
			res, err := RunFrostKeygen(net, i, peerIdxs, n, frostThreshold(n), 60*time.Second)
			if err != nil {
				errs[i] = fmt.Errorf("op%d keygen: %w", i, err)
				return
			}
			shares[i] = res.KeyShare
			pubPkgs[i] = res.PubPkg
			groupKeys[i] = res.GroupKey
		}(i)
	}
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	for i := 1; i < n; i++ {
		if string(groupKeys[i]) != string(groupKeys[0]) {
			t.Fatalf("operators disagree on the FROST group key")
		}
	}
	return shares, pubPkgs, groupKeys[0]
}

// TestFrostMutualTLSDKGAndSignVerifies is the M11-Part-2 verified artifact for
// the FROST path, mirroring TestMutualTLSDKGAndSignVerifies (GG20): n operators
// run a REAL FROST DKG and a 2-of-3 threshold sign over MUTUAL TLS (every
// connection RequireAndVerifyClientCert + per-operator pin), and the aggregate
// is verified by Go's INDEPENDENT standard crypto/ed25519 — the same RFC 8032
// primitive Solana checks. The crypto is the audited ZF frost-ed25519 crate over
// the C ABI; the transport is the same hardened mTLS stack the GG20 path uses.
func TestFrostMutualTLSDKGAndSignVerifies(t *testing.T) {
	const n = 3
	peers, privs, caDER := mintTLSPeers(t, n, 9800)

	shares, pubPkgs, groupKey := runFrostDKG(t, peers, privs, caDER, 9800)
	if len(groupKey) != 32 {
		t.Fatalf("group key is %d bytes, want 32", len(groupKey))
	}

	// --- 2-of-3 sign over mutual TLS, quorum {0,2} (op1 offline) ---
	quorum := []int{0, 2}
	aggregator := 0
	msg := make([]byte, 32)
	_, _ = rand.Read(msg)
	signPeers := subset(peers, quorum, 9900)

	sigs := make([][]byte, len(quorum))
	sErrs := make([]error, len(quorum))
	var swg sync.WaitGroup
	for qi, gi := range quorum {
		swg.Add(1)
		go func(qi, gi int) {
			defer swg.Done()
			net, err := NewNetworkTLS(gi, peers[gi].Moniker, privs[gi], signPeers, "frost-sign", peers[gi].CertDER, caDER, nil)
			if err != nil {
				sErrs[qi] = fmt.Errorf("op%d tls material: %w", gi, err)
				return
			}
			if err := net.Start(fmt.Sprintf("127.0.0.1:%d", 9900+gi), 20*time.Second); err != nil {
				sErrs[qi] = fmt.Errorf("op%d mesh: %w", gi, err)
				return
			}
			defer net.Close()
			res, err := RunFrostSign(net, gi, quorum, aggregator, shares[gi], pubPkgs[gi], msg, 60*time.Second)
			if err != nil {
				sErrs[qi] = fmt.Errorf("op%d sign: %w", gi, err)
				return
			}
			sigs[qi] = res.Signature
		}(qi, gi)
	}
	swg.Wait()
	for _, e := range sErrs {
		if e != nil {
			t.Fatal(e)
		}
	}

	// The aggregator (op0, quorum index 0) holds the signature.
	sig := sigs[0]
	if len(sig) != 64 {
		t.Fatalf("aggregate signature is %d bytes, want 64", len(sig))
	}

	// INDEPENDENT standard Ed25519 verification — exactly what Solana runs.
	if !ed25519.Verify(ed25519.PublicKey(groupKey), msg, sig) {
		t.Fatal("crypto/ed25519 REJECTED the networked FROST aggregate over the group key")
	}
	// Negative: a different message must fail.
	bad := append([]byte(nil), msg...)
	bad[0] ^= 0xff
	if ed25519.Verify(ed25519.PublicKey(groupKey), bad, sig) {
		t.Fatal("verifier accepted the signature over a DIFFERENT message")
	}
	t.Logf("networked 2-of-3 FROST aggregate verifies under crypto/ed25519 against group key %x", groupKey)
}

// TestFrostIdentifiableAbort proves FROST's abort story AND its on-chain-slashable
// attestation path: when a quorum member contributes an INVALID signature share,
// EVERY honest quorum member (not just the aggregator) runs frost::aggregate's
// per-share verification over the broadcast shares, independently names that
// signer (Error::InvalidSignatureShare), and surfaces a *FrostCulpritError naming
// the exact operator — never a forged signature, never a hang. Each honest
// operator then signs the SAME canonical FaultReport (the M9 path GG20 uses), and
// the honest quorum assembles a slashable bundle while a minority cannot. This is
// what makes a misbehaving FROST operator economically punishable on-chain,
// matching GG20.
func TestFrostIdentifiableAbort(t *testing.T) {
	const n = 3
	peers, privs, caDER := mintTLSPeers(t, n, 9820)
	shares, pubPkgs, _ := runFrostDKG(t, peers, privs, caDER, 9820)

	quorum := []int{0, 1, 2}
	aggregator := 0
	culprit := 2
	msg := make([]byte, 32)
	_, _ = rand.Read(msg)
	signPeers := subset(peers, quorum, 9920)

	errs := make([]error, n)
	var swg sync.WaitGroup
	for _, gi := range quorum {
		swg.Add(1)
		go func(gi int) {
			defer swg.Done()
			net, err := NewNetworkTLS(gi, peers[gi].Moniker, privs[gi], signPeers, "frost-sign-bad", peers[gi].CertDER, caDER, nil)
			if err != nil {
				errs[gi] = err
				return
			}
			if err := net.Start(fmt.Sprintf("127.0.0.1:%d", 9920+gi), 20*time.Second); err != nil {
				errs[gi] = err
				return
			}
			defer net.Close()
			if gi == culprit {
				errs[gi] = RunFrostSignCorrupt(net, gi, quorum, shares[gi], msg)
			} else {
				_, errs[gi] = RunFrostSign(net, gi, quorum, aggregator, shares[gi], pubPkgs[gi], msg, 60*time.Second)
			}
		}(gi)
	}
	swg.Wait()

	// EVERY honest operator (aggregator op0 AND non-aggregator op1) must have
	// independently surfaced a culprit-naming error pointing at op2, and each turns
	// it into a signed fault attestation.
	var atts []Attestation
	for _, gi := range quorum {
		if gi == culprit {
			continue // the culprit does not attest against itself
		}
		var ce *FrostCulpritError
		if !asFrostCulprit(errs[gi], &ce) {
			t.Fatalf("honest operator %d did not surface an identifiable-abort error, got: %v", gi, errs[gi])
		}
		if ce.Operator != culprit {
			t.Fatalf("operator %d named culprit %d, expected %d", gi, ce.Operator, culprit)
		}
		report := FrostFaultReport(msg, ce.Operator, peers[ce.Operator].PubKey)
		att := SignFaultReport(report, gi, privs[gi])
		if !VerifyAttestation(att) {
			t.Fatalf("operator %d produced an invalid attestation signature", gi)
		}
		t.Logf("honest operator %d independently named cheating operator %d; signed FROST fault attestation", gi, ce.Operator)
		atts = append(atts, att)
	}

	// A MINORITY (one attester) must NOT reach the 2-of-3 slash quorum.
	if _, err := CollectFault(atts[:1], 2); err == nil {
		t.Fatal("a single FROST attester reached the 2-of-3 slash quorum (minority must not slash)")
	}
	// The full honest quorum DOES, and names the same culprit.
	bundle, err := CollectFault(atts, 2)
	if err != nil {
		t.Fatalf("honest quorum failed to assemble a slashable FROST fault bundle: %v", err)
	}
	for _, a := range bundle {
		if a.Report.CulpritGlobal != culprit {
			t.Fatalf("bundle names operator %d, expected %d", a.Report.CulpritGlobal, culprit)
		}
		if a.Report.Session != SessionFrostSign || a.Report.Round != FaultRoundFrostShare {
			t.Fatalf("FROST report carries wrong session/round tag: %q/%d", a.Report.Session, a.Report.Round)
		}
	}
	t.Logf("FROST M9: %d honest attestations agree culprit = operator %d → on-chain-slashable bundle assembled", len(bundle), culprit)
}

func asFrostCulprit(err error, out **FrostCulpritError) bool {
	if ce, ok := err.(*FrostCulpritError); ok {
		*out = ce
		return true
	}
	return false
}

// --- small helpers ---

func seq(n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = i
	}
	return out
}

func others(n, self int) []int {
	out := make([]int, 0, n-1)
	for i := 0; i < n; i++ {
		if i != self {
			out = append(out, i)
		}
	}
	return out
}

// frostThreshold maps n operators to FROST min_signers. We use the same 2-of-3
// shape the GG20 path uses for n=3; generally ceil((n+1)/2) for an honest
// majority, but the tests fix n=3 -> 2.
func frostThreshold(n int) int {
	if n == 3 {
		return 2
	}
	return (n + 2) / 2
}
