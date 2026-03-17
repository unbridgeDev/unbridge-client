package kobenet

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	keygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// TestEncryptedShareAtRest is the M10 verified artifact: a share written with a
// passphrase is (a) NOT readable as plaintext on disk, (b) round-trips with the
// correct passphrase, and (c) is rejected (GCM auth failure) with a wrong one.
func TestEncryptedShareAtRest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "op.share.json")

	// A representative save: tss-lib's LocalPartySaveData carries the secret share
	// scalar Xi. We plant a recognizable secret so we can prove it never appears
	// in cleartext on disk.
	secret := new(big.Int)
	secret.SetString("112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00", 16)
	var save keygen.LocalPartySaveData
	save.Xi = secret
	groupPub := &ecdsa.PublicKey{Curve: ethcrypto.S256(), X: big.NewInt(7), Y: big.NewInt(11)}

	pass := []byte("correct horse battery staple")
	if err := SaveOperatorShareEncrypted(path, 2, "op2", 2, &save, groupPub, pass); err != nil {
		t.Fatalf("encrypt save: %v", err)
	}

	// (a) The secret scalar must NOT be on disk in cleartext.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(secret.String())) {
		t.Fatal("secret share scalar found in cleartext on disk")
	}
	// The plaintext JSON share fields ("Xi"/"index" inside the save) must be gone.
	if bytes.Contains(raw, []byte("\"Xi\"")) {
		t.Fatal("plaintext share JSON leaked on disk")
	}
	// The file IS recognized as an encrypted envelope.
	enc, err := IsEncryptedShare(path)
	if err != nil || !enc {
		t.Fatalf("IsEncryptedShare = %v, %v; want true, nil", enc, err)
	}

	// (b) Round-trips with the right passphrase, recovering the exact secret.
	got, _, err := LoadOperatorShareEncrypted(path, pass)
	if err != nil {
		t.Fatalf("decrypt with correct passphrase: %v", err)
	}
	if got.Save.Xi.Cmp(secret) != 0 {
		t.Fatalf("recovered share scalar mismatch: got %s want %s", got.Save.Xi, secret)
	}

	// (c) A wrong passphrase fails the GCM tag — never a silently-wrong share.
	if _, _, err := LoadOperatorShareEncrypted(path, []byte("wrong passphrase")); err == nil {
		t.Fatal("decrypt accepted a WRONG passphrase (GCM tag not enforced)")
	}
	t.Logf("M10: share encrypted at rest (AES-256-GCM / argon2id); wrong passphrase rejected")
}

// TestEncryptedShareStillSigns is the M10 end-to-end artifact: a REAL GG20 DKG,
// each operator's share written ENCRYPTED to disk, reloaded ONLY via the
// passphrase-gated loader, and then used to produce a 2-of-3 threshold signature
// that ecrecovers to the group address. This proves encryption-at-rest does not
// degrade the signer: the operator decrypts, signs, verifies.
func TestEncryptedShareStillSigns(t *testing.T) {
	if testing.Short() {
		t.Skip("skips the slow GG20 DKG under -short")
	}
	const n, threshold = 3, 1
	peers, privs, caDER := mintTLSPeers(t, n, 9900)
	pids := AllPartyIDs(peers)
	pass := []byte("operator-disk-passphrase")
	dir := t.TempDir()

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

	// DKG, then write each share ENCRYPTED.
	paths := make([]string, n)
	groupAddr := ""
	kErrs := make([]error, n)
	var kwg sync.WaitGroup
	for i := 0; i < n; i++ {
		kwg.Add(1)
		go func(i int) {
			defer kwg.Done()
			net, err := NewNetworkTLS(i, peers[i].Moniker, privs[i], peers, "enc-keygen", ownLeaf(peers, i), caDER, nil)
			if err != nil {
				kErrs[i] = err
				return
			}
			if err := net.Start(peers[i].Addr, 25*time.Second); err != nil {
				kErrs[i] = err
				return
			}
			defer net.Close()
			save, groupPub, err := RunKeygen(net, pids, i, threshold, pre[i], 120*time.Second)
			if err != nil {
				kErrs[i] = err
				return
			}
			paths[i] = filepath.Join(dir, fmt.Sprintf("op%d.share.json", i))
			if err := SaveOperatorShareEncrypted(paths[i], i, peers[i].Moniker, threshold, save, groupPub, pass); err != nil {
				kErrs[i] = err
				return
			}
			if i == 0 {
				groupAddr = ethcrypto.PubkeyToAddress(*groupPub).Hex()
			}
		}(i)
	}
	kwg.Wait()
	for _, e := range kErrs {
		if e != nil {
			t.Fatal(e)
		}
	}

	// Every share on disk must be encrypted.
	for i := 0; i < n; i++ {
		enc, err := IsEncryptedShare(paths[i])
		if err != nil || !enc {
			t.Fatalf("op%d share not encrypted on disk", i)
		}
	}

	// 2-of-3 sign, quorum {0,2}, loading each share via the ENCRYPTED loader.
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
				p.Addr = fmt.Sprintf("127.0.0.1:%d", 9950+lj)
				localPeers[lj] = p
			}
			// Load THIS operator's share strictly via the passphrase-gated loader.
			share, _, err := LoadOperatorShareEncrypted(paths[gi], pass)
			if err != nil {
				sErrs[li] = err
				return
			}
			net, err := NewNetworkTLS(li, peers[gi].Moniker, privs[gi], localPeers, "enc-sign", ownLeaf(peers, gi), caDER, nil)
			if err != nil {
				sErrs[li] = err
				return
			}
			if err := net.Start(localPeers[li].Addr, 25*time.Second); err != nil {
				sErrs[li] = err
				return
			}
			defer net.Close()
			sd, err := RunSign(net, signPIDs, li, len(quorum)-1, share.Save, hash, 60*time.Second)
			if err != nil {
				sErrs[li] = err
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
	if recovered := ethcrypto.PubkeyToAddress(*pub).Hex(); recovered != groupAddr {
		t.Fatalf("signature from encrypted shares does not recover group address: %s vs %s", recovered, groupAddr)
	}
	t.Logf("M10: encrypted-at-rest shares decrypt and produce a valid 2-of-3 GG20 signature for %s", groupAddr)
}

// TestEmptyPassphraseRejected: refusing to "encrypt" with no key is a guardrail
// against an operator silently writing an unprotected file thinking it is safe.
func TestEmptyPassphraseRejected(t *testing.T) {
	dir := t.TempDir()
	var save keygen.LocalPartySaveData
	save.Xi = big.NewInt(1)
	groupPub := &ecdsa.PublicKey{Curve: ethcrypto.S256(), X: big.NewInt(1), Y: big.NewInt(2)}
	err := SaveOperatorShareEncrypted(filepath.Join(dir, "x"), 0, "op0", 1, &save, groupPub, nil)
	if err == nil {
		t.Fatal("expected refusal to encrypt with an empty passphrase")
	}
}
