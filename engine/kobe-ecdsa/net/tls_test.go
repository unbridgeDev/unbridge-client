package kobenet

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	keygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// mintTLSPeers builds n operators that each hold a CA-issued leaf certificate
// (subject key = the operator's Ed25519 identity key), returning the peer
// directory (with pinned CertDER), the identity privkeys, and the CA cert DER.
func mintTLSPeers(t *testing.T, n, basePort int) ([]Peer, []ed25519.PrivateKey, []byte) {
	t.Helper()
	ca, err := NewCA(time.Hour)
	if err != nil {
		t.Fatalf("mint CA: %v", err)
	}
	peers := make([]Peer, n)
	privs := make([]ed25519.PrivateKey, n)
	for i := 0; i < n; i++ {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		privs[i] = priv
		leafDER, err := ca.IssueLeaf(pub, fmt.Sprintf("op%d", i), time.Hour)
		if err != nil {
			t.Fatalf("issue leaf %d: %v", i, err)
		}
		peers[i] = Peer{
			Index:   i,
			Addr:    fmt.Sprintf("127.0.0.1:%d", basePort+i),
			PubKey:  pub,
			CertDER: leafDER,
			Moniker: fmt.Sprintf("op%d", i),
		}
	}
	return peers, privs, ca.CertDER
}

func ownLeaf(peers []Peer, i int) []byte { return peers[i].CertDER }

// TestMutualTLSDKGAndSignVerifies is the Milestone-8 verified artifact: 3
// operators run a GG20 DKG and a 2-of-3 threshold sign over MUTUAL TLS (every
// connection is tls.RequireAndVerifyClientCert + per-operator pin), and the
// resulting signature is independently ecrecover-verified to the group address.
// Same proof the M6 test gives, but now the wire is encrypted + mutually
// authenticated by CA-issued certificates.
func TestMutualTLSDKGAndSignVerifies(t *testing.T) {
	if testing.Short() {
		t.Skip("skips the slow GG20 DKG under -short")
	}
	const n, threshold = 3, 1
	peers, privs, caDER := mintTLSPeers(t, n, 9500)
	pids := AllPartyIDs(peers)

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

	// --- mutual-TLS DKG ---
	saves := make([]*keygen.LocalPartySaveData, n)
	groupAddrs := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			net, err := NewNetworkTLS(i, peers[i].Moniker, privs[i], peers, "tls-keygen", ownLeaf(peers, i), caDER, nil)
			if err != nil {
				errs[i] = fmt.Errorf("op%d tls material: %w", i, err)
				return
			}
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
	for i := 1; i < n; i++ {
		if groupAddrs[i] != groupAddrs[0] {
			t.Fatalf("operators disagree on group address: %s vs %s", groupAddrs[i], groupAddrs[0])
		}
	}
	groupAddr := groupAddrs[0]

	// --- mutual-TLS 2-of-3 sign, quorum {0,2} ---
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
			localPeers := make([]Peer, len(signPIDs))
			for lj := range signPIDs {
				p := peers[globalForLocal[lj]]
				p.Index = lj
				p.Addr = fmt.Sprintf("127.0.0.1:%d", 9600+lj)
				localPeers[lj] = p
			}
			net, err := NewNetworkTLS(li, peers[gi].Moniker, privs[gi], localPeers, "tls-sign", ownLeaf(peers, gi), caDER, nil)
			if err != nil {
				sErrs[li] = fmt.Errorf("op%d tls material: %w", gi, err)
				return
			}
			if err := net.Start(localPeers[li].Addr, 20*time.Second); err != nil {
				sErrs[li] = fmt.Errorf("op%d mesh: %w", gi, err)
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
		t.Fatalf("mutual-TLS threshold sig does not recover the group address: got %s want %s", recovered, groupAddr)
	}
	if results[1] == nil || results[0].r != results[1].r || results[0].s != results[1].s {
		t.Fatal("quorum members produced different signatures")
	}
	t.Logf("mutual-TLS 2-of-3 GG20 signature recovers to group address %s", recovered)
}

// TestUntrustedCertRejected is the Milestone-8 negative artifact: an operator
// whose leaf certificate is signed by a DIFFERENT (rogue) CA — not the
// operator-set CA the honest operators pin — is rejected at the mutual-TLS
// handshake before any protocol byte flows. This proves membership is gated by
// the PKI, not merely by knowing a port.
func TestUntrustedCertRejected(t *testing.T) {
	// Honest operator 1 (the listener) trusts only the real operator-set CA.
	peers, privs, caDER := mintTLSPeers(t, 2, 9700)
	listenerTLS, err := buildTLSMaterial(1, privs[1], peers[1].CertDER, caDER, []Peer{peers[0]})
	if err != nil {
		t.Fatalf("listener tls material: %v", err)
	}

	// Attacker: a leaf signed by a rogue CA, presenting honest op0's identity key
	// so even the pin check would pass — but the CHAIN does not validate against
	// the operator-set CA, so TLS rejects it outright.
	rogueCA, err := NewCA(time.Hour)
	if err != nil {
		t.Fatalf("rogue CA: %v", err)
	}
	attackerPub := privs[0].Public().(ed25519.PublicKey)
	rogueLeaf, err := rogueCA.IssueLeaf(attackerPub, "op0", time.Hour)
	if err != nil {
		t.Fatalf("rogue leaf: %v", err)
	}
	attackerTLS := &tlsMaterial{
		self:     0,
		leafCert: tls.Certificate{Certificate: [][]byte{rogueLeaf}, PrivateKey: privs[0]},
		caPool:   listenerTLS.caPool, // attacker happens to trust the real CA; irrelevant
		pinnedSPKI: map[int][]byte{
			1: mustSPKI(t, peers[1].CertDER),
		},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:9710")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	srvErr := make(chan error, 1)
	go func() {
		nc, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		tc := tls.Server(nc, listenerTLS.serverConfig())
		_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
		srvErr <- tc.Handshake() // expect a verification error
	}()

	nc, err := net.DialTimeout("tcp", "127.0.0.1:9710", 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	tc := tls.Client(nc, attackerTLS.clientConfig())
	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	clientHandshakeErr := tc.Handshake()

	serverHandshakeErr := <-srvErr

	// The honest listener MUST reject the rogue-CA cert.
	if serverHandshakeErr == nil {
		t.Fatal("listener accepted a cert NOT signed by the operator-set CA (untrusted operator admitted)")
	}
	t.Logf("rogue-CA operator rejected at mutual-TLS handshake: server=%v client=%v", serverHandshakeErr, clientHandshakeErr)
}

func mustSPKI(t *testing.T, certDER []byte) []byte {
	t.Helper()
	c, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse cert for SPKI: %v", err)
	}
	return c.RawSubjectPublicKeyInfo
}
