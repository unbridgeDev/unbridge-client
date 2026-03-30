package kobenet

import (
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	keygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
)

// TestIdentifiableAbortAttestsCulprit is the M9 verified artifact (off-chain
// half): a REAL GG20 3-of-3 signing round in which one operator misbehaves
// (corrupts its round-2 MtA proof). tss-lib's own cryptography blames that exact
// operator at the honest parties; each honest operator turns that attribution
// into a signed FaultReport; the quorum of honest attestations is collected and
// verified, naming the SAME culprit. A minority (one honest attester) does NOT
// reach the slash quorum, and an honest operator is never named as culprit.
func TestIdentifiableAbortAttestsCulprit(t *testing.T) {
	if testing.Short() {
		t.Skip("skips the slow GG20 DKG under -short")
	}
	const n, threshold = 3, 2 // 3-of-3 quorum: 1 culprit + 2 honest attesters
	peers, privs, caDER := mintTLSPeers(t, n, 9800)
	pids := AllPartyIDs(peers)

	// --- DKG (mutual TLS), honest ---
	pre := make([]*keygen.LocalPreParams, n)
	var pwg sync.WaitGroup
	for i := 0; i < n; i++ {
		pwg.Add(1)
		go func(i int) {
			defer pwg.Done()
			p, err := keygen.GeneratePreParams(2 * time.Minute)
			if err != nil {
				t.Errorf("pre-params %d: %v", i, err)
				return
			}
			pre[i] = p
		}(i)
	}
	pwg.Wait()

	saves := make([]*keygen.LocalPartySaveData, n)
	kErrs := make([]error, n)
	var kwg sync.WaitGroup
	for i := 0; i < n; i++ {
		kwg.Add(1)
		go func(i int) {
			defer kwg.Done()
			net, err := NewNetworkTLS(i, peers[i].Moniker, privs[i], peers, "fault-keygen", ownLeaf(peers, i), caDER, nil)
			if err != nil {
				kErrs[i] = err
				return
			}
			if err := net.Start(peers[i].Addr, 25*time.Second); err != nil {
				kErrs[i] = fmt.Errorf("op%d mesh: %w", i, err)
				return
			}
			defer net.Close()
			save, _, err := RunKeygen(net, pids, i, threshold, pre[i], 120*time.Second)
			if err != nil {
				kErrs[i] = fmt.Errorf("op%d keygen: %w", i, err)
				return
			}
			saves[i] = save
		}(i)
	}
	kwg.Wait()
	for _, e := range kErrs {
		if e != nil {
			t.Fatal(e)
		}
	}

	// --- 3-of-3 sign with op2 (a global index) MISBEHAVING ---
	// quorum = {0,1,2}; the global culprit is operator 2. Each operator maps the
	// quorum-local culprit index tss-lib reports back to the global operator.
	quorum := []int{0, 1, 2}
	const culpritGlobal = 2
	signPIDs, globalForLocal := QuorumPartyIDs(peers, quorum)
	localForGlobal := map[int]int{}
	for li, gi := range globalForLocal {
		localForGlobal[gi] = li
	}
	hash := make([]byte, 32)
	_, _ = rand.Read(hash)

	faults := make([]*FaultError, len(quorum))
	signErrs := make([]error, len(quorum))
	var swg sync.WaitGroup
	for li := range signPIDs {
		swg.Add(1)
		go func(li int) {
			defer swg.Done()
			gi := globalForLocal[li]
			localPeers := make([]Peer, len(signPIDs))
			for lj := range signPIDs {
				p := peers[globalForLocal[lj]]
				p.Index = lj
				p.Addr = fmt.Sprintf("127.0.0.1:%d", 9850+lj)
				localPeers[lj] = p
			}
			net, err := NewNetworkTLS(li, peers[gi].Moniker, privs[gi], localPeers, "distin-sign", ownLeaf(peers, gi), caDER, nil)
			if err != nil {
				signErrs[li] = err
				return
			}
			if err := net.Start(localPeers[li].Addr, 25*time.Second); err != nil {
				signErrs[li] = fmt.Errorf("op%d mesh: %w", gi, err)
				return
			}
			defer net.Close()

			var sErr error
			if gi == culpritGlobal {
				_, sErr = RunSignMisbehaving(net, signPIDs, li, threshold, *saves[gi], hash, 60*time.Second)
			} else {
				_, sErr = RunSign(net, signPIDs, li, threshold, *saves[gi], hash, 60*time.Second)
			}
			var fe *FaultError
			if errors.As(sErr, &fe) {
				faults[li] = fe
			} else {
				signErrs[li] = sErr // any non-fault error (incl. nil-as-no-error) recorded
			}
		}(li)
	}
	swg.Wait()

	// Each HONEST operator must have identified the culprit. The culprit operator
	// itself may abort with a plain error (it is not asked to accuse itself).
	var attestations []Attestation
	for li := range signPIDs {
		gi := globalForLocal[li]
		if gi == culpritGlobal {
			continue
		}
		fe := faults[li]
		if fe == nil {
			t.Fatalf("honest operator %d did not identify a culprit (signErr=%v)", gi, signErrs[li])
		}
		// Map the quorum-local culprit index tss-lib reported to the global op.
		if len(fe.CulpritLocal) != 1 {
			t.Fatalf("operator %d: expected exactly one culprit, got locals %v", gi, fe.CulpritLocal)
		}
		gotGlobal := globalForLocal[fe.CulpritLocal[0]]
		if gotGlobal != culpritGlobal {
			t.Fatalf("operator %d blamed global operator %d, expected %d", gi, gotGlobal, culpritGlobal)
		}
		report := FaultReport{
			Session:       "distin-sign",
			MessageHash:   hash,
			Round:         fe.Round,
			CulpritGlobal: gotGlobal,
			CulpritPubKey: peers[gotGlobal].PubKey,
		}
		att := SignFaultReport(report, gi, privs[gi])
		if !VerifyAttestation(att) {
			t.Fatalf("operator %d produced an invalid attestation signature", gi)
		}
		t.Logf("operator %d cryptographically identified culprit = global operator %d (round %d); signed attestation",
			gi, gotGlobal, fe.Round)
		attestations = append(attestations, att)
	}

	// A MINORITY (one attester) must NOT reach the slash quorum of 2.
	if _, err := CollectFault(attestations[:1], 2); err == nil {
		t.Fatal("a single attester reached the 2-of-3 slash quorum (minority must not be able to slash)")
	}

	// The full honest quorum DOES reach it, and names the culprit.
	bundle, err := CollectFault(attestations, 2)
	if err != nil {
		t.Fatalf("honest quorum failed to assemble a slashable fault bundle: %v", err)
	}
	if len(bundle) < 2 {
		t.Fatalf("slash bundle has %d attestations, want >= 2", len(bundle))
	}
	for _, a := range bundle {
		if a.Report.CulpritGlobal != culpritGlobal {
			t.Fatalf("bundle names global operator %d, expected %d", a.Report.CulpritGlobal, culpritGlobal)
		}
	}
	t.Logf("M9: %d-of-%d honest attestations agree the culprit is global operator %d → slashable bundle assembled",
		len(bundle), n, culpritGlobal)

	// An honest operator must NOT be slashable: forge attestations naming op0
	// (honest) but only a single signer can be mustered against it under the
	// threat model (a minority), so it must not reach quorum.
	honestVictim := 0
	var frame []Attestation
	for _, gi := range quorum {
		if gi == honestVictim || gi == culpritGlobal {
			continue
		}
		r := FaultReport{Session: "distin-sign", MessageHash: hash, Round: 7, CulpritGlobal: honestVictim, CulpritPubKey: peers[honestVictim].PubKey}
		frame = append(frame, SignFaultReport(r, gi, privs[gi]))
	}
	if _, err := CollectFault(frame, 2); err == nil {
		t.Fatal("a minority assembled a slashable bundle against an honest operator")
	}
	t.Logf("M9: a minority CANNOT assemble a slashable bundle against honest operator %d (need 2, have 1)", honestVictim)
}
