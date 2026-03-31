// fault-verify is the M9 quorum collector + on-chain-bundle builder. It ingests
// the fault attestations emitted by the honest operators (each operator's `sign`
// phase prints {"fault":true,"attestation":{…}} when it identifies a culprit),
// verifies that at least `-need` DISTINCT operators signed an identical fault
// report, and prints:
//
//   - the agreed culprit (global operator index + identity key),
//   - the 32-byte fault-report digest (byte-identical to the on-chain
//     `fault_report_digest`), and
//   - the Ed25519 NATIVE-PROGRAM instruction data the relayer attaches as the
//     sibling instruction to `slash_operator_attested`, which the Solana runtime
//     verifies and the Distin program then introspects.
//
//	fault-verify -need 2 -in att0.json -in att1.json
//
// This process holds no shares and runs no tss-lib; it only checks signatures and
// assembles the on-chain bundle, so it is the honest seam between the off-chain
// identifiable-abort and the on-chain attested slash.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	kobenet "github.com/distin/kobe-ecdsa/net"
)

type stringSlice []string

func (s *stringSlice) String() string { return fmt.Sprintf("%v", *s) }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// operatorOut mirrors the operator `sign`-phase JSON; we only need the fault bits.
type operatorOut struct {
	Fault       bool                `json:"fault"`
	Attestation *kobenet.Attestation `json:"attestation"`
}

func main() {
	var inputs stringSlice
	flag.Var(&inputs, "in", "path to an operator's sign-phase JSON output (repeatable)")
	need := flag.Int("need", 2, "number of DISTINCT honest attesters required to slash")
	flag.Parse()

	if len(inputs) == 0 {
		fmt.Fprintln(os.Stderr, "fault-verify: at least one -in is required")
		os.Exit(2)
	}

	var atts []kobenet.Attestation
	for _, p := range inputs {
		bz, err := os.ReadFile(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read %s: %v\n", p, err)
			os.Exit(2)
		}
		var out operatorOut
		if err := json.Unmarshal(bz, &out); err != nil {
			fmt.Fprintf(os.Stderr, "parse %s: %v\n", p, err)
			os.Exit(2)
		}
		if out.Fault && out.Attestation != nil {
			atts = append(atts, *out.Attestation)
		}
	}

	bundle, err := kobenet.CollectFault(atts, *need)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAULT QUORUM NOT REACHED: %v\n", err)
		os.Exit(1)
	}

	report := bundle[0].Report
	digest := kobenet.FaultReportDigest(report)
	edData := buildEd25519IxData(bundle, digest)

	signers := make([]int, 0, len(bundle))
	for _, a := range bundle {
		signers = append(signers, a.AttesterGlobal)
	}

	emit(map[string]any{
		"culprit_global":      report.CulpritGlobal,
		"culprit_pubkey":      hex.EncodeToString(report.CulpritPubKey),
		"round":               report.Round,
		"session":             report.Session,
		"message_hash":        hex.EncodeToString(report.MessageHash),
		"attesters":           signers,
		"attesters_count":     len(bundle),
		"required":            *need,
		"fault_report_digest": hex.EncodeToString(digest[:]),
		"ed25519_ix_data":     hex.EncodeToString(edData),
	})
}

// buildEd25519IxData assembles the Solana Ed25519 native-program instruction data
// for the bundle: `[count][pad]` then a 14-byte offsets block per signature, then
// the appended (pubkey, sig, message) bytes — every reference 0xFFFF (this
// instruction). This is exactly the layout the on-chain `parse_ed25519_signers`
// reads back. The message for every signature is the shared 32-byte digest.
func buildEd25519IxData(bundle []kobenet.Attestation, digest [32]byte) []byte {
	const offsetsStart = 2
	const offsetsSize = 14
	n := len(bundle)
	data := make([]byte, offsetsStart+n*offsetsSize)
	data[0] = byte(n)
	put16 := func(at int, v uint16) {
		data[at] = byte(v)
		data[at+1] = byte(v >> 8)
	}
	const here uint16 = 0xffff
	for i, a := range bundle {
		sigOff := uint16(len(data))
		data = append(data, a.Sig...)
		pkOff := uint16(len(data))
		data = append(data, a.AttesterPubKey...)
		msgOff := uint16(len(data))
		data = append(data, digest[:]...)
		base := offsetsStart + i*offsetsSize
		put16(base+0, sigOff)
		put16(base+2, here)
		put16(base+4, pkOff)
		put16(base+6, here)
		put16(base+8, msgOff)
		put16(base+10, uint16(len(digest)))
		put16(base+12, here)
	}
	return data
}

func emit(v any) {
	bz, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(bz))
}
