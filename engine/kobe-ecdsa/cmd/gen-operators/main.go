// gen-operators writes N operator config files for a networked Distin GG20
// signing set. Each config gets its OWN fresh Ed25519 identity key and its own
// listen port and share path; every config carries the shared peer directory
// (all operators' identity PUBLIC keys + addresses) so the operators can pin and
// authenticate each other on the wire.
//
//	gen-operators -n 3 -base-port 9100 -dir ./operators        # legacy raw-socket set
//	gen-operators -n 3 -base-port 9100 -dir ./operators -tls    # M8 mutual-TLS set
//
// With -tls the helper ALSO acts as the operator-set enrolment authority: it
// mints a self-signed operator-set CA, issues one leaf certificate per operator
// (subject key = that operator's Ed25519 identity key), writes ca.cert.pem +
// op<i>.cert.pem, and sets the tls/ca_cert/leaf_cert/cert_dir fields in each
// config so the operator processes bring up mutual TLS. The CA private key is
// NOT written to disk — it exists only for the lifetime of this command, which
// is the honest static-enrolment model: enrol once, CA offline thereafter.
//
// This is a setup helper, not part of the protocol: it just mints distinct
// identities (and, with -tls, their certificates) so the operator processes are
// genuinely independent, mutually-authenticated parties.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	kobenet "github.com/distin/kobe-ecdsa/net"
)

type peer struct {
	Index   int    `json:"index"`
	Addr    string `json:"addr"`
	PubHex  string `json:"pubkey"`
	Moniker string `json:"moniker"`
}

type operatorConfig struct {
	Index       int    `json:"index"`
	Moniker     string `json:"moniker"`
	Listen      string `json:"listen"`
	IdentityHex string `json:"identity_key"`
	SharePath   string `json:"share_path"`
	Peers       []peer `json:"peers"`
	CAPath      string `json:"ca_cert,omitempty"`
	LeafPath    string `json:"leaf_cert,omitempty"`
	CertDir     string `json:"cert_dir,omitempty"`
	TLSEnable   bool   `json:"tls,omitempty"`
}

func main() {
	n := flag.Int("n", 3, "number of operators")
	basePort := flag.Int("base-port", 9100, "first listen port (operator i uses base+i)")
	dir := flag.String("dir", "./operators", "output directory for configs + shares")
	host := flag.String("host", "127.0.0.1", "listen host (localhost only)")
	useTLS := flag.Bool("tls", false, "mint an operator-set CA + per-operator leaf certs and enable mutual TLS (M8)")
	flag.Parse()

	if err := os.MkdirAll(*dir, 0o755); err != nil {
		log.Fatalf("mkdir: %v", err)
	}

	privs := make([]ed25519.PrivateKey, *n)
	peers := make([]peer, *n)
	monikers := []string{"alice", "bob", "carol", "dave", "erin", "frank"}
	for i := 0; i < *n; i++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatalf("keygen identity %d: %v", i, err)
		}
		privs[i] = priv
		m := fmt.Sprintf("op%d", i)
		if i < len(monikers) {
			m = monikers[i]
		}
		peers[i] = peer{
			Index:   i,
			Addr:    fmt.Sprintf("%s:%d", *host, *basePort+i),
			PubHex:  hex.EncodeToString(pub),
			Moniker: m,
		}
	}

	// With -tls, mint the operator-set CA and one leaf cert per operator. The CA
	// private key lives only in this process (static enrolment); only its cert
	// and the signed leaves are written.
	var caPath, certDir string
	if *useTLS {
		certDir = *dir
		ca, err := kobenet.NewCA(10 * 365 * 24 * time.Hour)
		if err != nil {
			log.Fatalf("mint operator-set CA: %v", err)
		}
		caPath = filepath.Join(*dir, "ca.cert.pem")
		if err := os.WriteFile(caPath, kobenet.EncodeCertPEM(ca.CertDER), 0o644); err != nil {
			log.Fatalf("write CA cert: %v", err)
		}
		for i := 0; i < *n; i++ {
			pub := privs[i].Public().(ed25519.PublicKey)
			leafDER, err := ca.IssueLeaf(pub, peers[i].Moniker, 365*24*time.Hour)
			if err != nil {
				log.Fatalf("issue leaf %d: %v", i, err)
			}
			leafPath := filepath.Join(*dir, fmt.Sprintf("op%d.cert.pem", i))
			if err := os.WriteFile(leafPath, kobenet.EncodeCertPEM(leafDER), 0o644); err != nil {
				log.Fatalf("write leaf %d: %v", i, err)
			}
		}
		fmt.Printf("minted operator-set CA + %d leaf certs (mutual TLS enabled)\n", *n)
	}

	for i := 0; i < *n; i++ {
		cfg := operatorConfig{
			Index:       i,
			Moniker:     peers[i].Moniker,
			Listen:      peers[i].Addr,
			IdentityHex: hex.EncodeToString(privs[i]),
			SharePath:   filepath.Join(*dir, fmt.Sprintf("op%d.share.json", i)),
			Peers:       peers,
		}
		if *useTLS {
			cfg.TLSEnable = true
			cfg.CAPath = caPath
			cfg.LeafPath = filepath.Join(*dir, fmt.Sprintf("op%d.cert.pem", i))
			cfg.CertDir = certDir
		}
		bz, _ := json.MarshalIndent(cfg, "", "  ")
		path := filepath.Join(*dir, fmt.Sprintf("op%d.json", i))
		if err := os.WriteFile(path, bz, 0o600); err != nil {
			log.Fatalf("write %s: %v", path, err)
		}
		fmt.Printf("wrote %s  (%s, identity_pub %s…, listen %s)\n",
			path, peers[i].Moniker, peers[i].PubHex[:12], peers[i].Addr)
	}
}
