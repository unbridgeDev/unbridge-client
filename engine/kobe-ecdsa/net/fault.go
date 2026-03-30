package kobenet

// M9 — identifiable abort (Option A: operator attestation).
//
// GG20 already identifies a cheating party CRYPTOGRAPHICALLY: a signing round
// fails when a specific operator submits an invalid zero-knowledge proof, and
// tss-lib attributes that fault to the offending party via
// `(*tss.Error).Culprits()`. This file turns that protocol-internal fact into an
// on-chain-consumable, m-of-n SIGNED fault report.
//
// The honest operators are the parties tss-lib SHOWS the culprit to (every
// honest party that ran the failed round independently reaches the same
// attribution — it is a verification result, not an opinion). Each honest
// operator therefore signs an identical, canonical FaultReport with its Ed25519
// attestation key. The on-chain program (engine/programs/distin,
// `slash_operator_attested`) slashes the named operator only when it sees at
// least a threshold of these signatures.
//
// Threat model (stated precisely, also in engine/SECURITY.md): this is an
// attestation, not an on-chain re-verification of the GG20 proof. A FALSE
// accusation requires a colluding MAJORITY of the signing operators to sign a
// fault report against an honest operator. That is the SAME honest-majority trust
// boundary the threshold-signature scheme itself already assumes (a dishonest
// majority can already forge signatures / steal funds). Option A therefore adds
// NO new trust assumption. The trustless upgrade — an off-chain SNARK fault-proof
// of the GG20 fault verified on Solana — is documented as the next step in
// engine/HARDENING.md; it is NOT built here.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// FaultRoundFrostShare is the canonical `round` value a FROST signature-share
// fault carries into a FaultReport. GG20 reports the real tss-lib round index
// (typically 3 — the round where the ZK proof fails); FROST has no equivalent
// multi-round transcript, so the fault is always "the signature-share verification
// failed at aggregate". We tag that with a distinct, reserved round value so a
// FROST report and a GG20 report can never share a digest by accident, while
// reusing the SAME FaultReport encoding and the SAME on-chain
// `slash_operator_attested` instruction (the program treats `round` as opaque u32
// bound into the digest). Value chosen well outside GG20's small round range.
const FaultRoundFrostShare = 1001

// SessionFrostSign is the signing-session id FROST attestations bind to. It is
// distinct from the GG20 "distin-sign" session so a fault report from one scheme
// can never be replayed against the other (the session string is hashed into the
// digest the on-chain program reconstructs).
const SessionFrostSign = "distin-frost-sign"

// FaultError is returned by RunSign when a signing round fails and tss-lib
// attributes the failure to specific culprit parties. CulpritLocal holds the
// quorum-LOCAL party indices the protocol blamed; the caller maps these back to
// global operator indices to build a FaultReport.
type FaultError struct {
	Round        int   // tss-lib round in which the fault was detected
	CulpritLocal []int // quorum-local indices of the culprit parties
	cause        error // underlying tss-lib cause
}

func (e *FaultError) Error() string {
	return fmt.Sprintf("identifiable abort: round %d, culprit quorum-local indices %v: %v",
		e.Round, e.CulpritLocal, e.cause)
}

func (e *FaultError) Unwrap() error { return e.cause }

// FaultReport is the canonical statement every honest operator signs: "in the
// signing session for this message, the operator with this global index (and
// this pinned identity key) was the protocol-identified culprit in this round."
// It is bound to the exact signing run (Session + MessageHash) so a report from
// one run cannot be replayed to slash an operator over an unrelated request.
type FaultReport struct {
	Session       string `json:"session"`         // signing session id (e.g. "distin-sign")
	MessageHash   []byte `json:"message_hash"`    // 32-byte hash the quorum was signing
	Round         int    `json:"round"`           // round the fault was detected in
	CulpritGlobal int    `json:"culprit_global"`  // GLOBAL operator index of the culprit
	CulpritPubKey []byte `json:"culprit_pubkey"`  // culprit's pinned Ed25519 identity key
}

// digest32 is the 32-byte message the attestation Ed25519 signature covers. The
// encoding is fixed-width and length-prefixed so two distinct reports can never
// collide and a signature is unambiguously bound to one (culprit, round, run).
// This is also the exact preimage the on-chain program reconstructs and feeds to
// the Ed25519 verifier, so the off-chain and on-chain encodings MUST stay byte
// for byte identical.
func (r *FaultReport) digest32() [32]byte {
	h := sha256.New()
	h.Write([]byte("distin-fault-report-v1\x00"))
	writeLP(h, []byte(r.Session))
	writeLP(h, r.MessageHash)
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(r.Round))
	h.Write(b[:])
	binary.BigEndian.PutUint32(b[:], uint32(r.CulpritGlobal))
	h.Write(b[:])
	writeLP(h, r.CulpritPubKey)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// FaultReportDigest is the exported form of a report's 32-byte attestation
// digest, for callers that assemble the on-chain bundle (cmd/fault-verify).
func FaultReportDigest(r FaultReport) [32]byte { return r.digest32() }

// writeLP writes a 4-byte big-endian length prefix then the bytes.
func writeLP(h interface{ Write([]byte) (int, error) }, b []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	_, _ = h.Write(n[:])
	_, _ = h.Write(b)
}

// FrostFaultReport builds the canonical FaultReport for a FROST identifiable
// abort. It is the FROST analog of the GG20 report assembled in cmd/operator: the
// culprit is named by GLOBAL operator index and its pinned Ed25519 identity key
// (culpritPubKey), bound to the exact message the quorum was signing. The round is
// the reserved FROST tag and the session is the FROST session, so the resulting
// digest is unambiguously a FROST signature-share fault and feeds the SAME on-chain
// `slash_operator_attested` instruction GG20 uses, unchanged.
func FrostFaultReport(msg32 []byte, culpritGlobal int, culpritPubKey []byte) FaultReport {
	return FaultReport{
		Session:       SessionFrostSign,
		MessageHash:   append([]byte(nil), msg32...),
		Round:         FaultRoundFrostShare,
		CulpritGlobal: culpritGlobal,
		CulpritPubKey: append([]byte(nil), culpritPubKey...),
	}
}

// Attestation is one honest operator's signature over a FaultReport's digest.
// Attester{Global,PubKey} identify who signed; Sig is Ed25519 over digest32().
type Attestation struct {
	Report          FaultReport `json:"report"`
	AttesterGlobal  int         `json:"attester_global"`
	AttesterPubKey  []byte      `json:"attester_pubkey"`
	Sig             []byte      `json:"sig"`
}

// SignFaultReport produces this operator's attestation of a fault report. The
// signing key is the operator's Ed25519 identity/attestation key — the SAME key
// pinned in the peer directory and bound on-chain, so an honest operator's
// signature is verifiable against its registered attestation pubkey.
func SignFaultReport(report FaultReport, attesterGlobal int, priv ed25519.PrivateKey) Attestation {
	d := report.digest32()
	return Attestation{
		Report:         report,
		AttesterGlobal: attesterGlobal,
		AttesterPubKey: append([]byte(nil), priv.Public().(ed25519.PublicKey)...),
		Sig:            ed25519.Sign(priv, d[:]),
	}
}

// VerifyAttestation checks that an attestation's signature is valid for its
// report under the attester's claimed Ed25519 key. (It does NOT decide whether
// the attester is an authorized operator — that pinning is the caller's job, and
// on-chain it is enforced by matching the attester pubkey to a registered
// Operator account.)
func VerifyAttestation(a Attestation) bool {
	if len(a.AttesterPubKey) != ed25519.PublicKeySize || len(a.Sig) != ed25519.SignatureSize {
		return false
	}
	d := a.Report.digest32()
	return ed25519.Verify(a.AttesterPubKey, d[:], a.Sig)
}

// CollectFault gathers attestations that all name the SAME culprit over the SAME
// run and verifies each signature. It returns the agreeing attestations once at
// least `need` DISTINCT honest operators have signed an identical report, or an
// error explaining why the quorum was not reached. This is the off-chain mirror
// of the on-chain threshold check: a minority cannot produce a slashable bundle.
func CollectFault(atts []Attestation, need int) ([]Attestation, error) {
	if need < 1 {
		return nil, fmt.Errorf("fault quorum need must be >= 1")
	}
	// Group verified attestations by the report digest they sign.
	type group struct {
		report FaultReport
		bySigner map[int]Attestation
	}
	groups := map[[32]byte]*group{}
	for _, a := range atts {
		if !VerifyAttestation(a) {
			continue // a bad signature simply does not count toward the quorum
		}
		d := a.Report.digest32()
		g := groups[d]
		if g == nil {
			g = &group{report: a.Report, bySigner: map[int]Attestation{}}
			groups[d] = g
		}
		// The attester must not be naming itself, and one operator counts once.
		if a.AttesterGlobal == a.Report.CulpritGlobal {
			continue
		}
		g.bySigner[a.AttesterGlobal] = a
	}
	for _, g := range groups {
		if len(g.bySigner) >= need {
			out := make([]Attestation, 0, len(g.bySigner))
			for _, a := range g.bySigner {
				out = append(out, a)
			}
			return out, nil
		}
	}
	return nil, fmt.Errorf("no culprit reached the fault quorum of %d distinct attesters", need)
}
