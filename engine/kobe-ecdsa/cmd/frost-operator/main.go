// frost-operator is one Distin FROST-Ed25519 signing operator, run as its OWN OS
// process (M11-Part-2 / fork F1). It is the FROST counterpart to cmd/operator
// (GG20): launched N times — distinct PIDs, ports, identity keys, and (after
// keygen) distinct encrypted share files — the operators run a REAL FROST DKG
// and a t-of-n threshold sign over the SAME hardened mutual-TLS transport the
// GG20 path uses. The cryptography is the audited ZF frost-ed25519 crate, reached
// over the C ABI in net/frost_ffi.go; no FROST math runs in Go.
//
// Two phases (same config format as the GG20 operator):
//
//	frost-operator -config op0.json -phase keygen
//	    Joins the mesh, runs FROST DKG, writes ONLY this operator's KeyPackage
//	    (encrypted at rest when DISTIN_SHARE_PASSPHRASE is set) plus a public
//	    sidecar (group key + PublicKeyPackage). Prints {index, group_pubkey}.
//
//	frost-operator -config op0.json -phase sign -quorum 0,2 -msg <64hex> [-aggregator 0]
//	    If in -quorum, loads its share, runs FROST round1/round2 over the network.
//	    The aggregator additionally combines the shares (re-verified under
//	    ed25519-dalek inside the crate) and prints {signature, group_pubkey,
//	    ed25519_verify}. Operators not in the quorum exit 0 idle.
//
// The misbehaving harness (-misbehave) broadcasts a tampered signature share so
// the aggregator's identifiable abort names this operator.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	kobenet "github.com/distin/kobe-ecdsa/net"
)

func main() {
	configPath := flag.String("config", "", "operator config JSON (identity + peer directory)")
	phase := flag.String("phase", "", "keygen | sign")
	quorum := flag.String("quorum", "", "sign: comma-separated GLOBAL operator indices, e.g. 0,2")
	msgHex := flag.String("msg", "", "sign: 32-byte message, hex")
	aggregator := flag.Int("aggregator", -1, "sign: global index of the aggregating operator (default: lowest in quorum)")
	misbehave := flag.Bool("misbehave", false, "sign: broadcast a tampered signature share so the aggregator identifiably aborts naming THIS operator")
	timeout := flag.Duration("timeout", 2*time.Minute, "overall phase timeout")
	flag.Parse()

	if *configPath == "" || *phase == "" {
		log.Fatal("frost-operator: -config and -phase are required")
	}
	cfg, priv, peers, err := kobenet.LoadOperatorConfig(*configPath)
	if err != nil {
		log.Fatalf("frost-operator: load config: %v", err)
	}
	logf := func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, "[frost-op%d pid=%d port=%s] "+format+"\n",
			append([]any{cfg.Index, os.Getpid(), portOf(cfg.Listen)}, a...)...)
	}
	logf("starting, phase=%s, scheme=FrostEd25519", *phase)

	switch *phase {
	case "keygen":
		runKeygen(cfg, priv, peers, *timeout, logf)
	case "sign":
		runSign(cfg, priv, peers, *quorum, *msgHex, *aggregator, *misbehave, *timeout, logf)
	default:
		log.Fatalf("frost-operator: unknown phase %q", *phase)
	}
}

// frostPublic is the cleartext sidecar written next to the encrypted share: the
// group key and PublicKeyPackage are PUBLIC (the aggregator needs the pubpkg).
type frostPublic struct {
	Index    int    `json:"index"`
	GroupKey string `json:"group_pubkey"`
	PubPkg   string `json:"pubpkg"`
}

func publicSidecar(sharePath string) string { return sharePath + ".public.json" }

func runKeygen(cfg *kobenet.OperatorConfig, priv ed25519.PrivateKey, peers []kobenet.Peer, timeout time.Duration, logf func(string, ...any)) {
	n := len(peers)
	net, err := buildNetwork(cfg, priv, peers, cfg.Index, "frost-keygen", logf)
	if err != nil {
		log.Fatalf("operator %d: build network: %v", cfg.Index, err)
	}
	logf("dialing/accepting the %d-operator mesh…", n)
	if err := net.Start(cfg.Listen, timeout); err != nil {
		log.Fatalf("operator %d: mesh start: %v", cfg.Index, err)
	}
	defer net.Close()
	logf("mesh up; running FROST distributed key generation over TCP…")

	peerIdxs := others(n, cfg.Index)
	res, err := kobenet.RunFrostKeygen(net, cfg.Index, peerIdxs, n, frostThreshold(n), timeout)
	if err != nil {
		log.Fatalf("operator %d: FROST keygen: %v", cfg.Index, err)
	}

	// Encrypt the key share at rest when a passphrase is set (M10 envelope).
	if pass := sharePassphrase(); len(pass) > 0 {
		if err := kobenet.SaveFrostShareEncrypted(cfg.SharePath, res.KeyShare, pass); err != nil {
			log.Fatalf("operator %d: save encrypted FROST share: %v", cfg.Index, err)
		}
		logf("DKG complete; wrote OUR FROST share ENCRYPTED (AES-256-GCM, argon2id) to %s", cfg.SharePath)
	} else {
		if err := os.WriteFile(cfg.SharePath, res.KeyShare, 0o600); err != nil {
			log.Fatalf("operator %d: save FROST share: %v", cfg.Index, err)
		}
		logf("DKG complete; wrote OUR FROST share PLAINTEXT to %s (set DISTIN_SHARE_PASSPHRASE to encrypt)", cfg.SharePath)
	}
	side := frostPublic{Index: cfg.Index, GroupKey: hex.EncodeToString(res.GroupKey), PubPkg: hex.EncodeToString(res.PubPkg)}
	sb, _ := json.MarshalIndent(side, "", "  ")
	if err := os.WriteFile(publicSidecar(cfg.SharePath), sb, 0o644); err != nil {
		log.Fatalf("operator %d: save public sidecar: %v", cfg.Index, err)
	}

	emit(map[string]any{"index": cfg.Index, "phase": "keygen", "group_pubkey": hex.EncodeToString(res.GroupKey)})
}

func runSign(cfg *kobenet.OperatorConfig, priv ed25519.PrivateKey, peers []kobenet.Peer, quorumStr, msgHex string, aggregator int, misbehave bool, timeout time.Duration, logf func(string, ...any)) {
	quorum := parseQuorum(quorumStr, len(peers))
	if aggregator < 0 {
		aggregator = quorum[0]
	}
	if indexInQuorum(quorum, cfg.Index) < 0 {
		logf("not in quorum %v; staying offline", quorum)
		emit(map[string]any{"index": cfg.Index, "phase": "sign", "participated": false})
		return
	}
	msg, err := hex.DecodeString(strings.TrimPrefix(msgHex, "0x"))
	if err != nil || len(msg) != 32 {
		log.Fatalf("operator %d: -msg must be 32 bytes hex", cfg.Index)
	}

	// Load OUR share (encrypted-at-rest aware) + the public sidecar.
	var keyShare []byte
	if isEncryptedEnvelope(cfg.SharePath) {
		pass := sharePassphrase()
		if len(pass) == 0 {
			log.Fatalf("operator %d: share is encrypted; set DISTIN_SHARE_PASSPHRASE", cfg.Index)
		}
		keyShare, err = kobenet.LoadFrostShareEncrypted(cfg.SharePath, pass)
	} else {
		keyShare, err = os.ReadFile(cfg.SharePath)
	}
	if err != nil {
		log.Fatalf("operator %d: load FROST share: %v", cfg.Index, err)
	}
	side, err := loadPublic(publicSidecar(cfg.SharePath))
	if err != nil {
		log.Fatalf("operator %d: load public sidecar: %v", cfg.Index, err)
	}
	pubPkg, _ := hex.DecodeString(side.PubPkg)
	groupKey, _ := hex.DecodeString(side.GroupKey)

	// The signing mesh contains only the quorum, keyed by GLOBAL index (FROST
	// identifiers are stable across keygen/sign), so we restrict the peer view.
	signPeers := make([]kobenet.Peer, 0, len(quorum))
	for _, gi := range quorum {
		signPeers = append(signPeers, peers[gi])
	}
	net, err := buildNetwork(cfg, priv, signPeers, cfg.Index, "frost-sign", logf)
	if err != nil {
		log.Fatalf("operator %d: build quorum network: %v", cfg.Index, err)
	}
	logf("dialing/accepting the quorum mesh %v (aggregator=op%d)…", quorum, aggregator)
	if err := net.Start(cfg.Listen, timeout); err != nil {
		log.Fatalf("operator %d: quorum mesh start: %v", cfg.Index, err)
	}
	defer net.Close()
	logf("quorum mesh up; running FROST threshold signing over TCP…")

	if misbehave {
		logf("MISBEHAVING: will broadcast a tampered signature share to induce identifiable abort")
		if err := kobenet.RunFrostSignCorrupt(net, cfg.Index, quorum, keyShare, msg); err != nil {
			logf("misbehaving operator aborted: %v", err)
		}
		emit(map[string]any{"index": cfg.Index, "phase": "sign", "participated": true, "misbehaved": true})
		return
	}

	res, err := kobenet.RunFrostSign(net, cfg.Index, quorum, aggregator, keyShare, pubPkg, msg, timeout)
	if err != nil {
		if ce, ok := err.(*kobenet.FrostCulpritError); ok {
			// This honest operator independently verified the broadcast shares and
			// named the culprit. Turn that attribution into a signed, on-chain
			// consumable fault attestation — the SAME M9 path GG20 uses. The culprit
			// must not attest against itself (its own RunFrostSign does not surface a
			// culprit naming itself; if it somehow did, we drop it here).
			if ce.Operator == cfg.Index {
				logf("identifiable abort named self; not self-attesting")
				emit(map[string]any{"index": cfg.Index, "phase": "sign", "participated": true, "fault": true, "culprit": ce.Operator})
				return
			}
			report := kobenet.FrostFaultReport(msg, ce.Operator, peers[ce.Operator].PubKey)
			att := kobenet.SignFaultReport(report, cfg.Index, priv)
			logf("identifiable abort: cheating operator %d named; signed FROST fault attestation", ce.Operator)
			emit(map[string]any{
				"index":          cfg.Index,
				"phase":          "sign",
				"participated":   true,
				"fault":          true,
				"culprit_global": ce.Operator,
				"round":          report.Round,
				"attestation":    att,
			})
			return
		}
		log.Fatalf("operator %d: FROST sign: %v", cfg.Index, err)
	}

	out := map[string]any{"index": cfg.Index, "phase": "sign", "participated": true, "quorum": quorum, "group_pubkey": side.GroupKey}
	if res.Signature != nil {
		// Aggregator: independently verify under Go's standard crypto/ed25519
		// (the same RFC 8032 primitive Solana checks) before reporting.
		verified := ed25519.Verify(ed25519.PublicKey(groupKey), msg, res.Signature)
		out["signature"] = hex.EncodeToString(res.Signature)
		out["aggregator"] = true
		out["ed25519_verify"] = verified
		logf("aggregate produced; crypto/ed25519 verify against group key = %v", verified)
	}
	emit(out)
}

func buildNetwork(cfg *kobenet.OperatorConfig, priv ed25519.PrivateKey, peers []kobenet.Peer, selfIdx int, session string, logf func(string, ...any)) (*kobenet.Network, error) {
	if !cfg.TLSEnable {
		return kobenet.NewNetwork(selfIdx, cfg.Moniker, priv, peers, session, logf), nil
	}
	caDER, ownLeafDER, err := kobenet.LoadCertPair(cfg.CAPath, cfg.LeafPath)
	if err != nil {
		return nil, err
	}
	logf("mutual TLS enabled: operator-set CA pinned, presenting own leaf cert")
	return kobenet.NewNetworkTLS(selfIdx, cfg.Moniker, priv, peers, session, ownLeafDER, caDER, logf)
}

// --- helpers ---

func loadPublic(path string) (*frostPublic, error) {
	bz, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p frostPublic
	if err := json.Unmarshal(bz, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func isEncryptedEnvelope(path string) bool {
	bz, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var probe struct {
		KDF        string `json:"kdf"`
		Ciphertext []byte `json:"ciphertext"`
	}
	if err := json.Unmarshal(bz, &probe); err != nil {
		return false
	}
	return probe.KDF != "" && len(probe.Ciphertext) > 0
}

func emit(v any) { bz, _ := json.Marshal(v); fmt.Println(string(bz)) }

func sharePassphrase() []byte { return []byte(os.Getenv("DISTIN_SHARE_PASSPHRASE")) }

func parseQuorum(s string, n int) []int {
	if s == "" {
		log.Fatal("sign: -quorum is required")
	}
	var out []int
	for _, part := range strings.Split(s, ",") {
		i, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || i < 0 || i >= n {
			log.Fatalf("sign: bad quorum index %q", part)
		}
		out = append(out, i)
	}
	return out
}

func indexInQuorum(quorum []int, global int) int {
	for i, g := range quorum {
		if g == global {
			return i
		}
	}
	return -1
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

func frostThreshold(n int) int {
	if n == 3 {
		return 2
	}
	return (n + 2) / 2
}

func portOf(addr string) string {
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[i+1:]
	}
	return addr
}
