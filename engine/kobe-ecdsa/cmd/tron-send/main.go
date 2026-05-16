// tron-send — the group signs and broadcasts a REAL native Tron (TRX) transfer.
//
//	tron-send <dest-T-address> <amount-sun>
//
// Server side, shares never combined: derive the group's Tron address, ask a
// Tron node to build the TransferContract (it serializes the protobuf raw_data),
// have the NETWORKED operators threshold-sign its txID (sha256 raw_data), attach
// the recoverable signature, and broadcast. Uses the Shasta testnet; fund the
// printed group address from the Shasta faucet to run a live send.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/btcsuite/btcd/btcec/v2"
	kobe "github.com/distin/kobe-ecdsa"
)

const tronAPI = "https://api.shasta.trongrid.io"

func main() {
	if len(os.Args) < 3 {
		die("usage: tron-send <dest-T-address> <amount-sun>")
	}
	dest := os.Args[1]
	amount, err := strconv.ParseInt(os.Args[2], 10, 64)
	if err != nil {
		die("bad amount: %v", err)
	}
	pub := groupPubkey()
	from := kobe.TronAddress(pub)
	fmt.Printf("group Tron address : %s\n", from)

	// 1. Node builds the TransferContract (serializes raw_data protobuf for us).
	tx := post("/wallet/createtransaction", map[string]any{
		"owner_address": from, "to_address": dest, "amount": amount, "visible": true,
	})
	txID, _ := tx["txID"].(string)
	if txID == "" {
		die("createtransaction failed: %s", jsonStr(tx))
	}
	fmt.Printf("txID (sha256 raw)  : %s\n", txID)

	// 2. Operators threshold-sign the txID; attach the 65-byte recoverable sig.
	r, s, v := operatorSign(txID)
	sig := &kobe.EthSignature{V: v}
	rb, _ := hex.DecodeString(r)
	sb, _ := hex.DecodeString(s)
	copy(sig.R[:], rb)
	copy(sig.S[:], sb)
	idBytes, _ := hex.DecodeString(txID)
	rec, err := kobe.RecoverTronAddress(idBytes, sig)
	if err != nil || rec != from {
		die("signature does not recover to group Tron address (%s vs %s): %v", rec, from, err)
	}
	fmt.Printf("sig recovers to    : %s == group ✓\n", rec)
	tx["signature"] = []string{hex.EncodeToString(kobe.TronSignature(sig))}

	// 3. Broadcast the signed tx.
	res := post("/wallet/broadcasttransaction", tx)
	if ok, _ := res["result"].(bool); !ok {
		die("broadcast rejected: %s", jsonStr(res))
	}
	fmt.Printf("\nBROADCAST ✓  txid: %s\n", txID)
	fmt.Printf("explorer: https://shasta.tronscan.org/#/transaction/%s\n", txID)
}

func groupPubkey() *ecdsa.PublicKey {
	dir := envOr("DISTIN_KEYS_DIR", filepath.Join(os.Getenv("HOME"), ".distin", "keys"))
	b, err := os.ReadFile(filepath.Join(dir, "gg20", "operators", "op0.share.json"))
	if err != nil {
		die("read group share: %v", err)
	}
	var m struct {
		GroupPubX json.Number `json:"group_pub_x"`
		GroupPubY json.Number `json:"group_pub_y"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		die("parse share: %v", err)
	}
	x, _ := new(big.Int).SetString(m.GroupPubX.String(), 10)
	y, _ := new(big.Int).SetString(m.GroupPubY.String(), 10)
	return &ecdsa.PublicKey{Curve: btcec.S256(), X: x, Y: y}
}

func operatorSign(hashHex string) (r, s string, v byte) {
	binDir := envOr("DISTIN_GG20_BIN_DIR", filepath.Join(os.Getenv("HOME"), ".distin", "keys", "gg20", "bin"))
	keys := envOr("DISTIN_KEYS_DIR", filepath.Join(os.Getenv("HOME"), ".distin", "keys"))
	opsDir := filepath.Join(keys, "gg20", "operators")
	cwd := envOr("KOBE_ECDSA_DIR", filepath.Join(os.Getenv("HOME"), ".distin"))
	var out bytes.Buffer
	var procs []*exec.Cmd
	for idx := 0; idx < 3; idx++ {
		c := exec.Command(filepath.Join(binDir, "operator"),
			"-config", filepath.Join(opsDir, fmt.Sprintf("op%d.json", idx)),
			"-phase", "sign", "-quorum", "0,2", "-hash", hashHex, "-timeout", "120s")
		c.Dir = cwd
		c.Env = os.Environ()
		if idx == 0 {
			c.Stdout = &out
		}
		if err := c.Start(); err != nil {
			die("spawn operator %d: %v", idx, err)
		}
		procs = append(procs, c)
	}
	for _, c := range procs {
		_ = c.Wait()
	}
	for _, line := range bytes.Split(bytes.TrimSpace(out.Bytes()), []byte("\n")) {
		var j struct {
			R, S string
			V    byte
		}
		if json.Unmarshal(line, &j) == nil && j.R != "" {
			r, s, v = j.R, j.S, j.V
		}
	}
	if r == "" {
		die("no signature from operators (output: %s)", out.String())
	}
	return
}

func post(path string, body map[string]any) map[string]any {
	b, _ := json.Marshal(body)
	res, err := http.Post(tronAPI+path, "application/json", bytes.NewReader(b))
	if err != nil {
		die("%s: %v", path, err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	var m map[string]any
	json.Unmarshal(raw, &m)
	return m
}

func jsonStr(m map[string]any) string { b, _ := json.Marshal(m); return string(b) }
func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func die(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...); os.Exit(1) }
