package kobenet

// Networked FROST-Ed25519 driver (M11-Part-2 / fork F1).
//
// This mirrors the GG20 driver in protocol.go (RunKeygen/RunSign), but for FROST
// it reuses the SAME hardened Network: mutual TLS + PKI + per-operator pinning +
// identity-key envelopes + the FIN barrier + encrypted shares. The cryptography
// is the audited ZF frost-ed25519 crate, reached over the C ABI in frost_ffi.go;
// no FROST math is reimplemented here. This file only sequences the rounds and
// moves opaque round-package bytes between the separate operator processes.
//
// Index convention: an operator's GLOBAL index i (the transport's addressing,
// Envelope.From / SendTo) maps to the 1-based FROST identifier i+1. DKG runs over
// ALL operators; signing runs over the quorum but every quorum member keeps its
// global identifier i+1 (the share was dealt to that identifier), so the same
// map holds in both phases.
//
// FROST's abort story (documented for HARDENING.md): FROST is fail-stop with
// share-level attribution. There is no GG20-style multi-round ZK transcript to
// pin a cheater across; instead the AGGREGATOR's frost::aggregate verifies each
// signature share against that signer's public verifying share, and a bad share
// names its signer (Error::InvalidSignatureShare{culprits}). RunFrostSign
// surfaces that culprit. A peer that drops / sends garbage / stalls is handled by
// the same transport machinery as GG20: a clean, non-hanging abort (the share
// never aggregates into a forged signature).

import (
	"fmt"
	"time"
)

// FROST round tags. Every FROST payload is prefixed with one tag byte so a single
// transport session can carry all rounds and the receiver can demultiplex by
// round without a separate session per round.
const (
	tagDKGRound1  byte = 1 // broadcast: dkg::round1::Package
	tagDKGRound2  byte = 2 // p2p: dkg::round2::Package (a secret share for ONE peer)
	tagSignRound1 byte = 3 // broadcast: SigningCommitments
	tagSignRound2 byte = 4 // broadcast: SignatureShare
)

func tag(t byte, payload []byte) []byte {
	out := make([]byte, 1+len(payload))
	out[0] = t
	copy(out[1:], payload)
	return out
}

// collectRound reads authenticated inbound envelopes until it has one payload of
// the wanted tag from every peer in `wantFrom` (a set of global operator
// indices), or aborts on a transport error / timeout. Returns global-index ->
// payload (tag byte stripped). Envelopes of a different tag are an error: the
// driver advances strictly round by round, so an out-of-round frame is a
// protocol violation, not something to buffer.
func collectRound(net *Network, wantTag byte, wantFrom map[int]bool, timeout time.Duration) (map[int][]byte, error) {
	got := make(map[int][]byte, len(wantFrom))
	deadline := time.After(timeout)
	for len(got) < len(wantFrom) {
		select {
		case e := <-net.Inbox():
			if !wantFrom[e.From] {
				return nil, fmt.Errorf("frost: unexpected frame from operator %d", e.From)
			}
			if len(e.Payload) == 0 || e.Payload[0] != wantTag {
				return nil, fmt.Errorf("frost: operator %d sent wrong round tag (want %d)", e.From, wantTag)
			}
			if _, dup := got[e.From]; dup {
				return nil, fmt.Errorf("frost: operator %d sent a duplicate round frame", e.From)
			}
			got[e.From] = append([]byte(nil), e.Payload[1:]...)
		case terr := <-net.Errs():
			return nil, fmt.Errorf("frost: transport aborted: %w", terr)
		case <-deadline:
			return nil, fmt.Errorf("frost: round (tag %d) timed out after %s", wantTag, timeout)
		}
	}
	return got, nil
}

// FrostKeygenResult is one operator's output from a networked DKG.
type FrostKeygenResult struct {
	KeyShare []byte // this operator's KeyPackage (secret; encrypt at rest)
	PubPkg   []byte // group PublicKeyPackage (public; aggregator needs it)
	GroupKey []byte // 32-byte Ed25519 group verifying key (register on-chain)
}

// RunFrostKeygen runs this operator's real FROST DKG to completion over the
// network. peerIdxs is every OTHER operator's global index; selfIdx is this
// operator's global index; n / threshold are the set size and min signers.
//
// Three rounds, all over the hardened transport:
//  1. part1 -> BROADCAST round-1 package; collect every peer's round-1 package.
//  2. part2 -> SEND each peer its round-2 secret share p2p (inside the TLS
//     tunnel); collect the round-2 share addressed to me.
//  3. part3 -> my KeyPackage + the group key. No party ever held the full key.
func RunFrostKeygen(net *Network, selfIdx int, peerIdxs []int, n, threshold int, timeout time.Duration) (*FrostKeygenResult, error) {
	selfID := uint16(selfIdx + 1)
	peerSet := make(map[int]bool, len(peerIdxs))
	for _, p := range peerIdxs {
		peerSet[p] = true
	}

	// --- Round 1 ---
	secret1, r1pkg, err := frostDKGPart1(selfID, uint16(n), uint16(threshold))
	if err != nil {
		return nil, err
	}
	if err := net.Broadcast(tag(tagDKGRound1, r1pkg)); err != nil {
		return nil, fmt.Errorf("frost keygen: broadcast round1: %w", err)
	}
	r1Raw, err := collectRound(net, tagDKGRound1, peerSet, timeout)
	if err != nil {
		return nil, err
	}
	r1Items := make([]frostItem, 0, len(r1Raw))
	for gi, b := range r1Raw {
		r1Items = append(r1Items, frostItem{id: uint16(gi + 1), bytes: b})
	}

	// --- Round 2 (per-recipient secret shares) ---
	secret2, r2blob, err := frostDKGPart2(secret1, r1Items)
	if err != nil {
		return nil, err
	}
	r2Out, err := decodeFrostItems(r2blob)
	if err != nil {
		return nil, fmt.Errorf("frost keygen: decode round2: %w", err)
	}
	// Each round-2 package is addressed to ONE peer identifier; send it p2p.
	for _, it := range r2Out {
		dest := int(it.id) - 1 // global index of the recipient
		if err := net.SendTo(dest, tag(tagDKGRound2, it.bytes)); err != nil {
			return nil, fmt.Errorf("frost keygen: send round2 to operator %d: %w", dest, err)
		}
	}
	// Collect the round-2 share each peer addressed to ME.
	r2Raw, err := collectRound(net, tagDKGRound2, peerSet, timeout)
	if err != nil {
		return nil, err
	}
	r2Items := make([]frostItem, 0, len(r2Raw))
	for gi, b := range r2Raw {
		r2Items = append(r2Items, frostItem{id: uint16(gi + 1), bytes: b})
	}

	// --- Round 3: finalize ---
	keyShare, pubPkg, groupKey, err := frostDKGPart3(secret2, r1Items, r2Items)
	if err != nil {
		return nil, err
	}

	// FIN barrier so no operator tears the mesh down before a peer's last frame
	// is delivered — reused verbatim from the GG20 path.
	net.Fin(30 * time.Second)
	return &FrostKeygenResult{KeyShare: keyShare, PubPkg: pubPkg, GroupKey: groupKey}, nil
}

// FrostSignResult is the output of a networked threshold sign. Signature is the
// aggregate (only the aggregator computes it; participants return a nil
// Signature after contributing their share). The group key is the one each
// operator already holds from DKG, so it is not repeated here.
type FrostSignResult struct {
	Signature []byte // 64-byte Ed25519 aggregate (aggregator only), else nil
}

// FrostCulpritError names the operator whose signature share failed verification
// at the aggregator (FROST identifiable abort).
type FrostCulpritError struct {
	Operator int // global operator index of the culprit
}

func (e *FrostCulpritError) Error() string {
	return fmt.Sprintf("frost: identifiable abort — operator %d produced an invalid signature share", e.Operator)
}

// RunFrostSign runs this operator's FROST signing party over the network. The
// quorum is the set of global indices in `quorum`; selfIdx is this operator's
// global index (must be in the quorum); aggregator is the global index of the
// operator that performs the final aggregate (any quorum member; conventionally
// the lowest). keyShare/pubPkg are this operator's DKG outputs; msg32 is the
// 32-byte message to sign.
//
// Two broadcast rounds: round-1 commitments, then round-2 signature shares. The
// aggregator additionally collects all shares and runs frost_aggregate (which
// re-verifies under ed25519-dalek before returning).
func RunFrostSign(net *Network, selfIdx int, quorum []int, aggregator int, keyShare, pubPkg, msg32 []byte, timeout time.Duration) (*FrostSignResult, error) {
	if len(msg32) != 32 {
		return nil, fmt.Errorf("frost sign: message must be 32 bytes, got %d", len(msg32))
	}
	// Peers in the quorum other than self.
	peerSet := make(map[int]bool, len(quorum))
	inQuorum := false
	for _, gi := range quorum {
		if gi == selfIdx {
			inQuorum = true
			continue
		}
		peerSet[gi] = true
	}
	if !inQuorum {
		return nil, fmt.Errorf("frost sign: operator %d not in quorum", selfIdx)
	}

	// --- Round 1: nonce commitments ---
	nonces, commitments, err := frostSignRound1(keyShare)
	if err != nil {
		return nil, err
	}
	if err := net.Broadcast(tag(tagSignRound1, commitments)); err != nil {
		return nil, fmt.Errorf("frost sign: broadcast commitments: %w", err)
	}
	commRaw, err := collectRound(net, tagSignRound1, peerSet, timeout)
	if err != nil {
		return nil, err
	}
	// The signing package needs EVERY quorum member's commitment, including ours.
	commItems := make([]frostItem, 0, len(quorum))
	commItems = append(commItems, frostItem{id: uint16(selfIdx + 1), bytes: commitments})
	for gi, b := range commRaw {
		commItems = append(commItems, frostItem{id: uint16(gi + 1), bytes: b})
	}

	// --- Round 2: signature shares ---
	share, err := frostSignRound2(keyShare, nonces, msg32, commItems)
	if err != nil {
		return nil, err
	}
	if err := net.Broadcast(tag(tagSignRound2, share)); err != nil {
		return nil, fmt.Errorf("frost sign: broadcast share: %w", err)
	}

	// EVERY quorum member — not just the aggregator — collects all round-2 shares
	// and runs the per-share verification. Shares are broadcast, so each honest
	// operator holds the SAME public inputs (msg, commitments, shares, pubpkg) the
	// aggregator does, and frost::aggregate's per-share check is a deterministic
	// function of those inputs: every honest operator independently reaches the
	// SAME culprit attribution. This is what lets the honest set produce an m-of-n
	// fault attestation, exactly like GG20 (where every honest party independently
	// sees the failed ZK proof). Non-aggregators discard the combined signature;
	// they only need the verification verdict (a culprit, or clean).
	shareRaw, err := collectRound(net, tagSignRound2, peerSet, timeout)
	if err != nil {
		return nil, err
	}
	shareItems := make([]frostItem, 0, len(quorum))
	shareItems = append(shareItems, frostItem{id: uint16(selfIdx + 1), bytes: share})
	for gi, b := range shareRaw {
		shareItems = append(shareItems, frostItem{id: uint16(gi + 1), bytes: b})
	}

	signature, culprit, err := frostAggregate(msg32, commItems, shareItems, pubPkg)
	if err != nil {
		if culprit != 0 {
			net.Fin(5 * time.Second)
			return nil, &FrostCulpritError{Operator: int(culprit) - 1}
		}
		return nil, err
	}

	net.Fin(30 * time.Second)
	if selfIdx != aggregator {
		// A non-aggregator verified the shares (and saw no culprit) but does not
		// publish the combined signature; only the aggregator returns it.
		return &FrostSignResult{Signature: nil}, nil
	}
	return &FrostSignResult{Signature: signature}, nil
}

// runFrostSignCorrupt is the adversarial harness for TestFrostIdentifiableAbort:
// this operator runs an OTHERWISE-real signing party but broadcasts a TAMPERED
// signature share (one byte flipped) in round 2. The share still deserializes as
// a scalar, so it reaches the aggregator's per-share verification — where it
// fails against THIS operator's verifying share, so frost::aggregate names this
// operator. It is never used in the honest path. The corrupt operator is not the
// aggregator, so it does not itself aggregate.
func RunFrostSignCorrupt(net *Network, selfIdx int, quorum []int, keyShare, msg32 []byte) error {
	peerSet := make(map[int]bool, len(quorum))
	for _, gi := range quorum {
		if gi != selfIdx {
			peerSet[gi] = true
		}
	}

	nonces, commitments, err := frostSignRound1(keyShare)
	if err != nil {
		return err
	}
	if err := net.Broadcast(tag(tagSignRound1, commitments)); err != nil {
		return err
	}
	commRaw, err := collectRound(net, tagSignRound1, peerSet, 60*time.Second)
	if err != nil {
		return err
	}
	commItems := make([]frostItem, 0, len(quorum))
	commItems = append(commItems, frostItem{id: uint16(selfIdx + 1), bytes: commitments})
	for gi, b := range commRaw {
		commItems = append(commItems, frostItem{id: uint16(gi + 1), bytes: b})
	}

	share, err := frostSignRound2(keyShare, nonces, msg32, commItems)
	if err != nil {
		return err
	}
	// Tamper: flip a byte so the share no longer verifies under this operator's
	// verifying share. It still parses as a scalar, so the aggregator reaches the
	// per-share check and attributes the fault to THIS operator.
	bad := append([]byte(nil), share...)
	bad[0] ^= 0x01
	if err := net.Broadcast(tag(tagSignRound2, bad)); err != nil {
		return err
	}
	net.Fin(5 * time.Second)
	return nil
}
