package kobenet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"

	keygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/argon2"
)

// OperatorShare is the on-disk form of ONE operator's key share — the share that
// never leaves the operator's own process/host in the networked design. Unlike
// engine/kobe-ecdsa/persist.go (which writes all N shares to one file for the
// in-process simulation), here each operator writes its own single share, so no
// file ever holds the full set and the separation of operators is real.
type OperatorShare struct {
	Index     int                       `json:"index"`
	Moniker   string                    `json:"moniker"`
	Threshold int                       `json:"threshold"`
	GroupPubX string                    `json:"group_pub_x"`
	GroupPubY string                    `json:"group_pub_y"`
	Save      keygen.LocalPartySaveData `json:"save"`
}

// SaveOperatorShare writes this operator's single share to path (mode 0600).
func SaveOperatorShare(path string, index int, moniker string, threshold int, save *keygen.LocalPartySaveData, groupPub *ecdsa.PublicKey) error {
	doc := OperatorShare{
		Index:     index,
		Moniker:   moniker,
		Threshold: threshold,
		GroupPubX: groupPub.X.String(),
		GroupPubY: groupPub.Y.String(),
		Save:      *save,
	}
	bz, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, bz, 0o600)
}

// LoadOperatorShare reads this operator's single share back, returning the save
// data and the group public key.
func LoadOperatorShare(path string) (*OperatorShare, *ecdsa.PublicKey, error) {
	bz, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var doc OperatorShare
	if err := json.Unmarshal(bz, &doc); err != nil {
		return nil, nil, err
	}
	x, ok1 := new(big.Int).SetString(doc.GroupPubX, 10)
	y, ok2 := new(big.Int).SetString(doc.GroupPubY, 10)
	if !ok1 || !ok2 {
		return nil, nil, fmt.Errorf("bad group pubkey in share")
	}
	groupPub := &ecdsa.PublicKey{Curve: ethcrypto.S256(), X: x, Y: y}
	return &doc, groupPub, nil
}

// M10 — secure share storage.
//
// A share is this operator's piece of the group key; `t` of them reconstruct it.
// Plaintext on disk (mode 0600) is NOT protection: a stolen disk, a backup, or
// any root/sibling process reads it directly. Below we encrypt the share at rest
// with AES-256-GCM (an audited AEAD: confidentiality + integrity) under a key
// derived from the operator's passphrase with Argon2id (a memory-hard KDF that
// makes brute-forcing the passphrase expensive). The KDF salt + parameters travel
// in the envelope so the file is self-describing, but the passphrase never does.
//
// Threat model (also in HARDENING.md): a single stolen ENCRYPTED share leaks
// nothing without the passphrase, and even one stolen PLAINTEXT share is below
// threshold (it cannot sign or reconstruct alone). The real catastrophe is `t`
// shares AND their passphrases compromised together — full key recovery — which
// is why operators must hold distinct passphrases and, at the higher tier, an
// HSM/enclave-bound key (noted, not built here).

// argon2id parameters. These are interactive-login-grade defaults (64 MiB, 3
// passes); they are recorded in the envelope so a future tuning does not break
// old files.
const (
	argonTime    = 3
	argonMemKiB  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32 // AES-256
	saltLen      = 16
)

// encryptedShare is the on-disk envelope: the KDF salt + parameters, the GCM
// nonce, and the AEAD ciphertext of the plaintext OperatorShare JSON. `Index`
// and the group pubkey are duplicated in cleartext only for operator
// convenience/audit (which file is which); they are not secret and are NOT
// authenticated as part of the ciphertext, so a tamper there cannot forge a share
// (GCM rejects any modified ciphertext on open).
type encryptedShare struct {
	Version    int    `json:"version"`
	Index      int    `json:"index"`
	Moniker    string `json:"moniker"`
	KDF        string `json:"kdf"` // "argon2id"
	Salt       []byte `json:"salt"`
	Time       uint32 `json:"argon_time"`
	MemoryKiB  uint32 `json:"argon_memory_kib"`
	Threads    uint8  `json:"argon_threads"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

func deriveKey(passphrase, salt []byte) []byte {
	return argon2.IDKey(passphrase, salt, argonTime, argonMemKiB, argonThreads, argonKeyLen)
}

// SaveOperatorShareEncrypted writes this operator's share encrypted at rest under
// `passphrase`. The plaintext OperatorShare never touches the disk.
func SaveOperatorShareEncrypted(path string, index int, moniker string, threshold int, save *keygen.LocalPartySaveData, groupPub *ecdsa.PublicKey, passphrase []byte) error {
	if len(passphrase) == 0 {
		return fmt.Errorf("refusing to encrypt share with an empty passphrase")
	}
	doc := OperatorShare{
		Index:     index,
		Moniker:   moniker,
		Threshold: threshold,
		GroupPubX: groupPub.X.String(),
		GroupPubY: groupPub.Y.String(),
		Save:      *save,
	}
	plaintext, err := json.Marshal(doc)
	if err != nil {
		return err
	}

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	key := deriveKey(passphrase, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	env := encryptedShare{
		Version:    1,
		Index:      index,
		Moniker:    moniker,
		KDF:        "argon2id",
		Salt:       salt,
		Time:       argonTime,
		MemoryKiB:  argonMemKiB,
		Threads:    argonThreads,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}
	bz, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	// Zero the derived key; it has done its job. (Best-effort; Go may have copied
	// it, but this removes the obvious live copy.)
	for i := range key {
		key[i] = 0
	}
	return os.WriteFile(path, bz, 0o600)
}

// LoadOperatorShareEncrypted reads and decrypts an encrypted share envelope. A
// wrong passphrase fails the GCM authentication tag (returns an error), so a
// brute-forcer gets a clean reject, never a silently-wrong share.
func LoadOperatorShareEncrypted(path string, passphrase []byte) (*OperatorShare, *ecdsa.PublicKey, error) {
	bz, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var env encryptedShare
	if err := json.Unmarshal(bz, &env); err != nil {
		return nil, nil, err
	}
	if env.KDF != "argon2id" {
		return nil, nil, fmt.Errorf("unsupported share KDF %q", env.KDF)
	}
	key := argon2.IDKey(passphrase, env.Salt, env.Time, env.MemoryKiB, env.Threads, argonKeyLen)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	if len(env.Nonce) != gcm.NonceSize() {
		return nil, nil, fmt.Errorf("bad nonce length")
	}
	plaintext, err := gcm.Open(nil, env.Nonce, env.Ciphertext, nil)
	for i := range key {
		key[i] = 0
	}
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt share (wrong passphrase or corrupted file): %w", err)
	}
	var doc OperatorShare
	if err := json.Unmarshal(plaintext, &doc); err != nil {
		return nil, nil, err
	}
	x, ok1 := new(big.Int).SetString(doc.GroupPubX, 10)
	y, ok2 := new(big.Int).SetString(doc.GroupPubY, 10)
	if !ok1 || !ok2 {
		return nil, nil, fmt.Errorf("bad group pubkey in share")
	}
	groupPub := &ecdsa.PublicKey{Curve: ethcrypto.S256(), X: x, Y: y}
	return &doc, groupPub, nil
}

// IsEncryptedShare reports whether a share file on disk is an M10 encrypted
// envelope (vs the legacy plaintext form), so the operator can pick the right
// loader without a passphrase prompt on plaintext files.
func IsEncryptedShare(path string) (bool, error) {
	bz, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	var probe struct {
		KDF        string `json:"kdf"`
		Ciphertext []byte `json:"ciphertext"`
	}
	if err := json.Unmarshal(bz, &probe); err != nil {
		return false, nil // not our envelope shape; treat as plaintext
	}
	return probe.KDF != "" && len(probe.Ciphertext) > 0, nil
}

// --- FROST share storage (M11-Part-2) ---
//
// A FROST key share is an opaque serialized KeyPackage from the audited crate
// (engine/kobe). It is encrypted at rest with the SAME AES-256-GCM + Argon2id
// envelope as the GG20 share above, so the FROST operator gets identical
// at-rest protection. The public group key + group PublicKeyPackage are written
// in cleartext alongside (they are public; the aggregator needs the pubpkg).

// SaveFrostShareEncrypted encrypts a FROST KeyPackage blob at rest under
// `passphrase`, writing a self-describing envelope (same shape as the GG20 one).
func SaveFrostShareEncrypted(path string, keyShare, passphrase []byte) error {
	if len(passphrase) == 0 {
		return fmt.Errorf("refusing to encrypt FROST share with an empty passphrase")
	}
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	key := deriveKey(passphrase, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	ciphertext := gcm.Seal(nil, nonce, keyShare, nil)
	env := encryptedShare{
		Version:    1,
		KDF:        "argon2id",
		Salt:       salt,
		Time:       argonTime,
		MemoryKiB:  argonMemKiB,
		Threads:    argonThreads,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}
	bz, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	for i := range key {
		key[i] = 0
	}
	return os.WriteFile(path, bz, 0o600)
}

// LoadFrostShareEncrypted decrypts a FROST KeyPackage blob. A wrong passphrase
// fails the GCM tag (clean error, never a silently-wrong share).
func LoadFrostShareEncrypted(path string, passphrase []byte) ([]byte, error) {
	bz, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var env encryptedShare
	if err := json.Unmarshal(bz, &env); err != nil {
		return nil, err
	}
	if env.KDF != "argon2id" {
		return nil, fmt.Errorf("unsupported FROST share KDF %q", env.KDF)
	}
	key := argon2.IDKey(passphrase, env.Salt, env.Time, env.MemoryKiB, env.Threads, argonKeyLen)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(env.Nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("bad nonce length")
	}
	plaintext, err := gcm.Open(nil, env.Nonce, env.Ciphertext, nil)
	for i := range key {
		key[i] = 0
	}
	if err != nil {
		return nil, fmt.Errorf("decrypt FROST share (wrong passphrase or corrupted file): %w", err)
	}
	return plaintext, nil
}

// QuorumPartyIDs builds the sorted PartyID ordering for a signing quorum and a
// map from quorum-local index back to the global operator index. The signing
// Network is built keyed by quorum-local index, so routing during signing uses
// these local indices consistently on every operator in the quorum.
func QuorumPartyIDs(peers []Peer, quorum []int) (tss.SortedPartyIDs, []int) {
	unsorted := make(tss.UnSortedPartyIDs, len(quorum))
	byKey := make(map[string]int, len(quorum))
	for i, gi := range quorum {
		pid := PartyIDFor(peers[gi])
		unsorted[i] = pid
		byKey[pid.KeyInt().String()] = gi
	}
	sorted := tss.SortPartyIDs(unsorted)
	globalForLocal := make([]int, len(sorted))
	for li, pid := range sorted {
		globalForLocal[li] = byKey[pid.KeyInt().String()]
	}
	return sorted, globalForLocal
}
