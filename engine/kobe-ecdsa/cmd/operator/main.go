// operator is one Distin GG20 signing operator, run as its OWN OS process.
//
// Milestone 6: where the in-process signer ran all 3 parties as goroutines in a
// single process sharing in-memory channels, this binary is launched 3 times —
// 3 distinct PIDs, 3 distinct listen ports, 3 distinct identity keys, and (after
// keygen) 3 distinct share files, each operator holding ONLY its own share. The
// operators run the GG20 DKG and a 2-of-3 threshold sign over real TCP sockets,
// authenticating every wire message with their Ed25519 identity keys.
//
// Two phases:
//
//	operator -config op0.json -phase keygen -threshold 1
//	    Joins the mesh, runs distributed key generation, writes ONLY this
//	    operator's share to its share_path, prints {index, group_eth_address}.
//
//	operator -config op0.json -phase sign -quorum 0,2 -hash <64hex>
//	    If this operator is in -quorum, joins the quorum mesh, loads its own
//	    share, runs the GG20 signing rounds over the network, and (the operator
//	    that finishes) prints {r, s, v, sig65, group_eth_address,
//	    recovered_eth_address, match}. Operators not in the quorum exit 0 idle.
//
// All protocol messages cross the wire; the share never leaves this process.
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"
	keygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	kobe "github.com/distin/kobe-ecdsa"
	kobenet "github.com/distin/kobe-ecdsa/net"
)

func main() {
	configPath := flag.String("config", "", "operator config JSON (identity + peer directory)")
	phase := flag.String("phase", "", "keygen | sign")
	threshold := flag.Int("threshold", 1, "tss-lib threshold t (t+1 sign); 2-of-3 = 1")
	quorum := flag.String("quorum", "", "sign: comma-separated GLOBAL operator indices in the quorum, e.g. 0,2")
	hashHex := flag.String("hash", "", "sign: 32-byte message hash, hex")
	misbehave := flag.Bool("misbehave", false, "sign (M9 demo): corrupt THIS operator's round-2 MtA proof so the honest quorum cryptographically identifies it as the culprit")
	timeout := flag.Duration("timeout", 5*time.Minute, "overall phase timeout")
	flag.Parse()

	if *configPath == "" || *phase == "" {
		log.Fatal("operator: -config and -phase are required")
	}
	cfg, priv, peers, err := kobenet.LoadOperatorConfig(*configPath)
	if err != nil {
		log.Fatalf("operator: load config: %v", err)
	}

	// Every line is prefixed so a tail of all 3 processes shows who did what.
	logf := func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, "[op%d pid=%d port=%s] "+format+"\n",
			append([]any{cfg.Index, os.Getpid(), portOf(cfg.Listen)}, a...)...)
	}
	logf("starting, phase=%s, identity_pub=%s…", *phase, pubShort(priv))

	switch *phase {
	case "keygen":
		runKeygen(cfg, priv, peers, *threshold, *timeout, logf)
	case "sign":
		runSign(cfg, priv, peers, *quorum, *hashHex, *threshold, *misbehave, *timeout, logf)
	default:
		log.Fatalf("operator: unknown phase %q", *phase)
	}
}

func runKeygen(cfg *kobenet.OperatorConfig, priv ed25519.PrivateKey, peers []kobenet.Peer, threshold int, timeout time.Duration, logf func(string, ...any)) {
	pids := kobenet.AllPartyIDs(peers)
	selfIdx := cfg.Index

	// Pre-params (Paillier safe primes) are the slow part of GG20 keygen and are
	// generated LOCALLY by each operator — they are part of this operator's own
	// secret material and never leave the process.
	logf("generating Paillier safe primes (this is the slow part of GG20 DKG)…")
	pre, err := keygen.GeneratePreParams(2 * time.Minute)
	if err != nil {
		log.Fatalf("operator %d: pre-params: %v", selfIdx, err)
	}

	net, err := buildNetwork(cfg, priv, peers, selfIdx, "distin-keygen", logf)
	if err != nil {
		log.Fatalf("operator %d: build network: %v", selfIdx, err)
	}
	logf("dialing/accepting the %d-operator mesh on the wire…", len(peers))
	if err := net.Start(cfg.Listen, timeout); err != nil {
		log.Fatalf("operator %d: mesh start: %v", selfIdx, err)
	}
	defer net.Close()
	logf("mesh up; running distributed key generation over TCP…")

	save, groupPub, err := kobenet.RunKeygen(net, pids, selfIdx, threshold, pre, timeout)
	if err != nil {
		log.Fatalf("operator %d: keygen: %v", selfIdx, err)
	}

	// M10: encrypt the share at rest when a passphrase is provided
	// (DISTIN_SHARE_PASSPHRASE). The plaintext path remains only as an explicit,
	// loudly-logged fallback for the in-process tests / demos that don't set one.
	if pass := sharePassphrase(); len(pass) > 0 {
		if err := kobenet.SaveOperatorShareEncrypted(cfg.SharePath, selfIdx, cfg.Moniker, threshold, save, groupPub, pass); err != nil {
			log.Fatalf("operator %d: save encrypted share: %v", selfIdx, err)
		}
		logf("DKG complete; wrote OUR share ENCRYPTED (AES-256-GCM, argon2id) to %s", cfg.SharePath)
	} else {
		if err := kobenet.SaveOperatorShare(cfg.SharePath, selfIdx, cfg.Moniker, threshold, save, groupPub); err != nil {
			log.Fatalf("operator %d: save share: %v", selfIdx, err)
		}
		logf("DKG complete; wrote OUR share PLAINTEXT to %s (set DISTIN_SHARE_PASSPHRASE to encrypt at rest)", cfg.SharePath)
	}

	emit(map[string]any{
		"index":             selfIdx,
		"phase":             "keygen",
		"share_path":        cfg.SharePath,
		"group_eth_address": kobe.GroupAddress(groupPub).Hex(),
	})
}

func runSign(cfg *kobenet.OperatorConfig, priv ed25519.PrivateKey, peers []kobenet.Peer, quorumStr, hashHex string, threshold int, misbehave bool, timeout time.Duration, logf func(string, ...any)) {
	quorum := parseQuorum(quorumStr, len(peers))
	selfGlobal := cfg.Index

	// Operators outside the quorum stay offline for this signature.
	localIdx := indexInQuorum(quorum, selfGlobal)
	if localIdx < 0 {
		logf("not in quorum %v; staying offline for this signature", quorum)
		emit(map[string]any{"index": selfGlobal, "phase": "sign", "participated": false})
		return
	}

	hash, err := hex.DecodeString(strings.TrimPrefix(hashHex, "0x"))
	if err != nil || len(hash) != 32 {
		log.Fatalf("operator %d: -hash must be 32 bytes hex", selfGlobal)
	}

	// M10: pick the loader by what is actually on disk. An encrypted envelope
	// needs the passphrase; a wrong/absent one fails the GCM tag, never a silent
	// wrong share.
	encrypted, err := kobenet.IsEncryptedShare(cfg.SharePath)
	if err != nil {
		log.Fatalf("operator %d: read share: %v", selfGlobal, err)
	}
	var share *kobenet.OperatorShare
	var groupPub *ecdsa.PublicKey
	if encrypted {
		pass := sharePassphrase()
		if len(pass) == 0 {
			log.Fatalf("operator %d: share at %s is encrypted; set DISTIN_SHARE_PASSPHRASE", selfGlobal, cfg.SharePath)
		}
		share, groupPub, err = kobenet.LoadOperatorShareEncrypted(cfg.SharePath, pass)
	} else {
		share, groupPub, err = kobenet.LoadOperatorShare(cfg.SharePath)
	}
	if err != nil {
		log.Fatalf("operator %d: load OUR share: %v", selfGlobal, err)
	}
	logf("loaded OUR share from %s (group addr %s); joining %d-of quorum %v",
		cfg.SharePath, kobe.GroupAddress(groupPub).Hex(), len(quorum), quorum)

	// The signing mesh contains only the quorum operators, re-indexed to their
	// quorum-LOCAL positions so tss-lib's signing routing (0..k-1) and the
	// transport peer indices line up. We build a peer slice keyed by local index.
	signSortedPIDs, globalForLocal := kobenet.QuorumPartyIDs(peers, quorum)
	localPeers := make([]kobenet.Peer, len(signSortedPIDs))
	var selfLocal int
	for li := range signSortedPIDs {
		gi := globalForLocal[li]
		p := peers[gi]
		p.Index = li // re-index to quorum-local
		localPeers[li] = p
		if gi == selfGlobal {
			selfLocal = li
		}
	}

	signThreshold := len(quorum) - 1 // t+1 = quorum size

	net, err := buildNetwork(cfg, priv, localPeers, selfLocal, "distin-sign", logf)
	if err != nil {
		log.Fatalf("operator %d: build quorum network: %v", selfGlobal, err)
	}
	logf("dialing/accepting the quorum mesh (local idx %d of %d)…", selfLocal, len(quorum))
	if err := net.Start(cfg.Listen, timeout); err != nil {
		log.Fatalf("operator %d: quorum mesh start: %v", selfGlobal, err)
	}
	defer net.Close()
	logf("quorum mesh up; running GG20 threshold signing over TCP…")

	// M9: a misbehaving operator corrupts its own round-2 MtA proof; the honest
	// quorum then cryptographically identifies it (tss-lib Culprits) and each
	// honest operator emits a signed fault attestation instead of a signature.
	var sigData *common.SignatureData
	if misbehave {
		logf("MISBEHAVING: corrupting our round-2 MtA proof to induce an identifiable abort")
		sigData, err = kobenet.RunSignMisbehaving(net, signSortedPIDs, selfLocal, signThreshold, share.Save, hash, timeout)
	} else {
		sigData, err = kobenet.RunSign(net, signSortedPIDs, selfLocal, signThreshold, share.Save, hash, timeout)
	}
	if err != nil {
		var fe *kobenet.FaultError
		if errors.As(err, &fe) {
			// The protocol blamed a specific quorum-local party. Map it to the
			// global operator, sign a fault report, and emit the attestation.
			if len(fe.CulpritLocal) == 0 {
				log.Fatalf("operator %d: fault with no culprit: %v", selfGlobal, err)
			}
			culpritGlobal := globalForLocal[fe.CulpritLocal[0]]
			report := kobenet.FaultReport{
				Session:       "distin-sign",
				MessageHash:   hash,
				Round:         fe.Round,
				CulpritGlobal: culpritGlobal,
				CulpritPubKey: peers[culpritGlobal].PubKey,
			}
			att := kobenet.SignFaultReport(report, selfGlobal, priv)
			logf("identifiable abort: round %d culprit = global operator %d; signed fault attestation",
				fe.Round, culpritGlobal)
			emit(map[string]any{
				"index":           selfGlobal,
				"phase":           "sign",
				"participated":    true,
				"fault":           true,
				"culprit_global":  culpritGlobal,
				"round":           fe.Round,
				"attestation":     att,
			})
			return
		}
		if misbehave {
			// The culprit's own party aborts too; it does not (and must not)
			// attest against itself. Exit cleanly so the honest attestations are
			// what the demo collects.
			logf("misbehaving operator aborted as expected (no self-attestation): %v", err)
			emit(map[string]any{"index": selfGlobal, "phase": "sign", "participated": true, "misbehaved": true})
			return
		}
		log.Fatalf("operator %d: signing: %v", selfGlobal, err)
	}

	// Assemble the standard (r,s,v) and INDEPENDENTLY verify via go-ethereum
	// ecrecover that it recovers the group address — the exact ETH-node primitive.
	sig := &kobe.EthSignature{V: sigData.SignatureRecovery[0]}
	copy(sig.R[:], leftPad32(sigData.R))
	copy(sig.S[:], leftPad32(sigData.S))

	groupAddr := kobe.GroupAddress(groupPub)
	recovered, err := kobe.RecoverAddress(hash, sig)
	if err != nil {
		log.Fatalf("operator %d: ecrecover: %v", selfGlobal, err)
	}
	logf("signing complete; sig recovers to %s (group %s) match=%v",
		recovered.Hex(), groupAddr.Hex(), recovered == groupAddr)

	emit(map[string]any{
		"index":                 selfGlobal,
		"phase":                 "sign",
		"participated":          true,
		"quorum":                quorum,
		"r":                     hex.EncodeToString(sig.R[:]),
		"s":                     hex.EncodeToString(sig.S[:]),
		"v":                     sig.V,
		"sig65":                 hex.EncodeToString(sig.Bytes()),
		"group_eth_address":     groupAddr.Hex(),
		"recovered_eth_address": recovered.Hex(),
		"match":                 recovered == groupAddr,
	})
}

// buildNetwork constructs the operator's Network for one phase: mutual TLS (M8)
// when the config enables it, else the legacy raw-socket path. peers is the
// per-phase peer view (full set for keygen, quorum-local for signing) and
// already carries each peer's pinned leaf cert when TLS is on.
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

// --- small helpers ---

func emit(v any) {
	bz, _ := json.Marshal(v)
	fmt.Println(string(bz)) // result goes to STDOUT; logs go to STDERR
}

// sharePassphrase reads the M10 share-encryption passphrase from the environment.
// Env (not a flag) so it never lands in a process listing or shell history. Empty
// means "no encryption" (plaintext fallback for tests/demos).
func sharePassphrase() []byte {
	return []byte(os.Getenv("DISTIN_SHARE_PASSPHRASE"))
}

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

func portOf(addr string) string {
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[i+1:]
	}
	return addr
}

func pubShort(priv ed25519.PrivateKey) string {
	pk := priv[32:] // ed25519 private key = seed||pub
	return hex.EncodeToString(pk)[:12]
}

func leftPad32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}
