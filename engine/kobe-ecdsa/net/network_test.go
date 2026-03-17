package kobenet

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"
	"time"

	keygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// makePeers mints n operator identities on loopback ports starting at basePort.
func makePeers(n, basePort int) ([]Peer, []ed25519.PrivateKey) {
	peers := make([]Peer, n)
	privs := make([]ed25519.PrivateKey, n)
	for i := 0; i < n; i++ {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		privs[i] = priv
		peers[i] = Peer{
			Index:   i,
			Addr:    fmt.Sprintf("127.0.0.1:%d", basePort+i),
			PubKey:  pub,
			Moniker: fmt.Sprintf("op%d", i),
		}
	}
	return peers, privs
}

// TestNetworkedDKGAndSignVerifies runs the full Milestone-6 flow over REAL TCP
// loopback sockets: 3 operators each run their own keygen party connected by
// actual net.Conn sockets (not in-memory channels), then a 2-of-3 quorum signs a
// message over the network, and the result is independently verified with
// go-ethereum ecrecover. This exercises the same transport the separate operator
// processes use; the only difference is the parties live in one test process.
//
// It is slow (GG20 safe-prime DKG) — run with -timeout 300s.
func TestNetworkedDKGAndSignVerifies(t *testing.T) {
	if testing.Short() {
		t.Skip("skips the slow GG20 DKG under -short")
	}
	const n, threshold = 3, 1
	peers, privs := makePeers(n, 9300)
	pids := AllPartyIDs(peers)

	// Pre-generate each operator's pre-params (the slow part) in parallel.
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

	// --- networked DKG ---
	saves := make([]*keygen.LocalPartySaveData, n)
	groupAddrs := make([]string, n)
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			net := NewNetwork(i, peers[i].Moniker, privs[i], peers, "test-keygen", nil)
			if err := net.Start(peers[i].Addr, 20*time.Second); err != nil {
				errs[i] = fmt.Errorf("op%d mesh: %w", i, err)
				return
			}
			defer net.Close()
			save, groupPub, err := RunKeygen(net, pids, i, threshold, pre[i], 120*time.Second)
			if err != nil {
				errs[i] = fmt.Errorf("op%d keygen: %w", i, err)
				return
			}
			saves[i] = save
			groupAddrs[i] = ethcrypto.PubkeyToAddress(*groupPub).Hex()
		}(i)
	}
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	// All operators must agree on the group address.
	for i := 1; i < n; i++ {
		if groupAddrs[i] != groupAddrs[0] {
			t.Fatalf("operators disagree on group address: %s vs %s", groupAddrs[i], groupAddrs[0])
		}
	}
	groupAddr := groupAddrs[0]

	// --- networked 2-of-3 sign with quorum {0,2}; op1 stays offline ---
	quorum := []int{0, 2}
	signPIDs, globalForLocal := QuorumPartyIDs(peers, quorum)
	hash := make([]byte, 32)
	_, _ = rand.Read(hash)

	type sigOut struct {
		r, s [32]byte
		v    byte
	}
	results := make([]*sigOut, len(quorum))
	sErrs := make([]error, len(quorum))
	var swg sync.WaitGroup
	for li := range signPIDs {
		swg.Add(1)
		go func(li int) {
			defer swg.Done()
			gi := globalForLocal[li]
			// Build the quorum-local peer view.
			localPeers := make([]Peer, len(signPIDs))
			for lj := range signPIDs {
				p := peers[globalForLocal[lj]]
				p.Index = lj
				p.Addr = fmt.Sprintf("127.0.0.1:%d", 9400+lj)
				localPeers[lj] = p
			}
			net := NewNetwork(li, peers[gi].Moniker, privs[gi], localPeers, "test-sign", nil)
			if err := net.Start(localPeers[li].Addr, 20*time.Second); err != nil {
				sErrs[li] = fmt.Errorf("op%d(local %d) mesh: %w", gi, li, err)
				return
			}
			defer net.Close()
			sd, err := RunSign(net, signPIDs, li, len(quorum)-1, *saves[gi], hash, 60*time.Second)
			if err != nil {
				sErrs[li] = fmt.Errorf("op%d sign: %w", gi, err)
				return
			}
			out := &sigOut{v: sd.SignatureRecovery[0]}
			copy(out.r[:], leftPad(sd.R))
			copy(out.s[:], leftPad(sd.S))
			results[li] = out
		}(li)
	}
	swg.Wait()
	for _, e := range sErrs {
		if e != nil {
			t.Fatal(e)
		}
	}

	// Independent verification: ecrecover the group address from (r,s,v).
	out := results[0]
	sig := make([]byte, 65)
	copy(sig[0:32], out.r[:])
	copy(sig[32:64], out.s[:])
	sig[64] = out.v
	pub, err := ethcrypto.SigToPub(hash, sig)
	if err != nil {
		t.Fatalf("ecrecover: %v", err)
	}
	recovered := ethcrypto.PubkeyToAddress(*pub).Hex()
	if recovered != groupAddr {
		t.Fatalf("networked threshold sig does not recover the group address: got %s want %s", recovered, groupAddr)
	}

	// Both quorum members must have produced the identical signature.
	if results[1] == nil || results[0].r != results[1].r || results[0].s != results[1].s {
		t.Fatal("quorum members produced different signatures")
	}
}

func leftPad(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}
