// btc-send — the group signs and broadcasts a REAL native Bitcoin transaction.
//
//	btc-send <dest-tb1-address> <amount-sat> [fee-sat]
//
// End to end, server side (the professional shape: the signer assembles and
// broadcasts, the shares never combine): derive the GG20 group's testnet
// P2WPKH address, fetch its UTXOs from Esplora, build a P2WPKH spend, compute
// the BIP-143 sighash, have the NETWORKED operators threshold-sign it, assemble
// the witness transaction, and broadcast it. To run a live send, fund the
// printed group address from a Bitcoin testnet faucet first.
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
	"sort"
	"strconv"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	kobe "github.com/distin/kobe-ecdsa"
)

var esplora = envOr("DISTIN_ESPLORA", "https://mempool.space/testnet/api")

func main() {
	if len(os.Args) < 3 {
		die("usage: btc-send <dest-tb1-address> <amount-sat> [fee-sat]")
	}
	dest := os.Args[1]
	amount, err := strconv.ParseUint(os.Args[2], 10, 64)
	if err != nil {
		die("bad amount: %v", err)
	}
	fee := uint64(500)
	if len(os.Args) > 3 {
		fee, _ = strconv.ParseUint(os.Args[3], 10, 64)
	}

	pub := groupPubkey()
	comp := compressed(pub)
	addr, err := kobe.BtcP2WPKHAddressTestnet(pub)
	if err != nil {
		die("group testnet address: %v", err)
	}
	fmt.Printf("group BTC testnet address : %s\n", addr)

	utxos := fetchUTXOs(addr)
	total := uint64(0)
	for _, u := range utxos {
		total += u.Value
	}
	fmt.Printf("group UTXOs                : %d (total %d sat)\n", len(utxos), total)
	if total < amount+fee {
		fmt.Printf("\nNOT ENOUGH FUNDS. Fund the group address above from a testnet faucet\n")
		fmt.Printf("(e.g. https://coinfaucet.eu/en/btc-testnet/) then re-run.\n")
		fmt.Printf("Need %d sat (amount %d + fee %d), have %d.\n", amount+fee, amount, fee, total)
		os.Exit(2)
	}

	// Pick UTXOs (largest first) until amount+fee is covered.
	sort.Slice(utxos, func(i, j int) bool { return utxos[i].Value > utxos[j].Value })
	var inputs []kobe.BtcTxInput
	inTotal := uint64(0)
	for _, u := range utxos {
		txid, _ := hex.DecodeString(u.Txid)
		var prev [32]byte
		for i := 0; i < 32; i++ { // Esplora txid is display (reversed) order
			prev[i] = txid[31-i]
		}
		inputs = append(inputs, kobe.BtcTxInput{PrevTxID: prev, Vout: u.Vout, ValueSat: u.Value, Sequence: 0xffffffff})
		inTotal += u.Value
		if inTotal >= amount+fee {
			break
		}
	}

	destScript, err := kobe.DecodeBech32P2WPKH(dest)
	if err != nil {
		die("dest address: %v", err)
	}
	outputs := []kobe.BtcTxOutput{{ValueSat: amount, ScriptPubKey: destScript}}
	if change := inTotal - amount - fee; change > 0 {
		outputs = append(outputs, kobe.BtcTxOutput{ValueSat: change, ScriptPubKey: kobe.P2WPKHScriptForPubkey(pub)})
	}

	// One sighash + threshold signature per input (all spend the same group key).
	derSigs := make([][]byte, len(inputs))
	for i := range inputs {
		sh, err := kobe.BtcSegwitSighash(2, inputs, outputs, i, pub, 0)
		if err != nil {
			die("sighash[%d]: %v", i, err)
		}
		fmt.Printf("input %d BIP-143 sighash    : %x\n", i, sh)
		sig := operatorSign(hex.EncodeToString(sh[:]))
		if ok, _ := kobe.VerifyBtcDERSignature(mustDER(sig), sh[:], pub); !ok {
			die("input %d: signature does not verify against the group key", i)
		}
		derSigs[i] = mustDER(sig)
	}

	raw, txid, err := kobe.SerializeSignedP2WPKHTx(2, inputs, outputs, 0, derSigs, comp)
	if err != nil {
		die("serialize: %v", err)
	}
	display := make([]byte, 32)
	for i := 0; i < 32; i++ {
		display[i] = txid[31-i]
	}
	fmt.Printf("\nassembled signed tx (%d B)  : %s\n", len(raw), hex.EncodeToString(raw))
	fmt.Printf("txid                        : %x\n", display)

	sent := broadcast(hex.EncodeToString(raw))
	fmt.Printf("\nBROADCAST ✓  txid: %s\n", sent)
	fmt.Printf("explorer: https://blockstream.info/testnet/tx/%s\n", sent)
}

// --- group key (from the GG20 share's stored ECDSA point; no reconstruction) ---
func groupPubkey() *ecdsa.PublicKey {
	dir := os.Getenv("DISTIN_KEYS_DIR")
	if dir == "" {
		dir = filepath.Join(os.Getenv("HOME"), ".distin", "keys")
	}
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

func compressed(pub *ecdsa.PublicKey) []byte {
	x := pub.X.Bytes()
	buf := make([]byte, 33)
	buf[0] = 0x02
	if pub.Y.Bit(0) == 1 {
		buf[0] = 0x03
	}
	copy(buf[33-len(x):], x)
	return buf
}

func mustDER(sig *kobe.EthSignature) []byte {
	der, err := kobe.EncodeBtcDERSignature(sig)
	if err != nil {
		die("DER encode: %v", err)
	}
	return der
}

// --- networked operators sign an arbitrary 32-byte hash (shares stay split) ---
func operatorSign(hashHex string) *kobe.EthSignature {
	binDir := envOr("DISTIN_GG20_BIN_DIR", filepath.Join(os.Getenv("HOME"), ".distin", "keys", "gg20", "bin"))
	keys := envOr("DISTIN_KEYS_DIR", filepath.Join(os.Getenv("HOME"), ".distin", "keys"))
	opsDir := filepath.Join(keys, "gg20", "operators")
	cwd := envOr("KOBE_ECDSA_DIR", filepath.Join(os.Getenv("HOME"), ".distin"))

	var op0Out bytes.Buffer
	var procs []*exec.Cmd
	for idx := 0; idx < 3; idx++ {
		c := exec.Command(filepath.Join(binDir, "operator"),
			"-config", filepath.Join(opsDir, fmt.Sprintf("op%d.json", idx)),
			"-phase", "sign", "-quorum", "0,2", "-hash", hashHex, "-timeout", "120s")
		c.Dir = cwd
		c.Env = os.Environ()
		if idx == 0 {
			c.Stdout = &op0Out
		}
		if err := c.Start(); err != nil {
			die("spawn operator %d: %v", idx, err)
		}
		procs = append(procs, c)
	}
	for _, c := range procs {
		_ = c.Wait()
	}
	// op0 (the aggregator) emits {"r","s",...} JSON on the last stdout line.
	var r, s string
	for _, line := range bytes.Split(bytes.TrimSpace(op0Out.Bytes()), []byte("\n")) {
		var j struct{ R, S string }
		if json.Unmarshal(line, &j) == nil && j.R != "" && j.S != "" {
			r, s = j.R, j.S
		}
	}
	if r == "" {
		die("no signature from operators (output: %s)", op0Out.String())
	}
	var sig kobe.EthSignature
	rb, _ := hex.DecodeString(r)
	sb, _ := hex.DecodeString(s)
	copy(sig.R[:], rb)
	copy(sig.S[:], sb)
	return &sig
}

// --- Esplora (testnet) ---
type utxo struct {
	Txid  string `json:"txid"`
	Vout  uint32 `json:"vout"`
	Value uint64 `json:"value"`
}

func fetchUTXOs(addr string) []utxo {
	res, err := http.Get(esplora + "/address/" + addr + "/utxo")
	if err != nil {
		die("esplora utxo: %v", err)
	}
	defer res.Body.Close()
	var us []utxo
	json.NewDecoder(res.Body).Decode(&us)
	return us
}

func broadcast(rawHex string) string {
	res, err := http.Post(esplora+"/tx", "text/plain", bytes.NewBufferString(rawHex))
	if err != nil {
		die("broadcast: %v", err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 {
		die("broadcast rejected (%d): %s", res.StatusCode, string(b))
	}
	return string(b)
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func die(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...); os.Exit(1) }

var _ = time.Second
