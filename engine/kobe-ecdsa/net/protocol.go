package kobenet

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"
	keygen "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	signing "github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v2/tss"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// This file is the bridge between tss-lib and the wire. The in-process signer
// (engine/kobe-ecdsa/tss.go) ran ALL N parties as goroutines and routed their
// tss.Message output through in-memory channels. Here each OPERATOR PROCESS runs
// exactly ONE party; its outgoing tss.Message is serialized with WireBytes() and
// pushed onto the Network (broadcast or point-to-point per IsBroadcast/GetTo),
// and inbound authenticated Envelopes are fed back into the party with Update().
//
// The routing logic (broadcast = all-but-sender, p2p = GetTo indices) is exactly
// tss-lib's own contract — the same logic the in-process route()/routeSign()
// used, but the hop is now a real socket instead of a channel.

// RunKeygen runs this operator's keygen party to completion over the network.
// pids is the full sorted party ordering (all operators); selfIdx is this
// operator's index. It returns this operator's share (its own LocalPartySaveData)
// and the group public key. The share never leaves this process.
func RunKeygen(net *Network, pids tss.SortedPartyIDs, selfIdx, threshold int, preParams *keygen.LocalPreParams, timeout time.Duration) (*keygen.LocalPartySaveData, *ecdsa.PublicKey, error) {
	ctx := tss.NewPeerContext(pids)
	params := tss.NewParameters(tss.S256(), ctx, pids[selfIdx], len(pids), threshold)

	outCh := make(chan tss.Message, len(pids)*8)
	endCh := make(chan *keygen.LocalPartySaveData, 1)
	partyErr := make(chan *tss.Error, 1)

	party := keygen.NewLocalParty(params, outCh, endCh, *preParams).(*keygen.LocalParty)
	go func() {
		if err := party.Start(); err != nil {
			partyErr <- err
		}
	}()

	for {
		select {
		case msg := <-outCh:
			if err := dispatch(net, msg); err != nil {
				return nil, nil, fmt.Errorf("operator %d: dispatch: %w", selfIdx, err)
			}
		case e := <-net.Inbox():
			if err := feed(party, pids, e, selfIdx); err != nil {
				return nil, nil, err
			}
		case terr := <-net.Errs():
			return nil, nil, fmt.Errorf("transport aborted: %w", terr)
		case perr := <-partyErr:
			return nil, nil, fmt.Errorf("operator %d: party error: %w", selfIdx, perr.Cause())
		case sd := <-endCh:
			// We finished. Run the FIN barrier so no operator tears down the mesh
			// while a peer still needs its final broadcast.
			net.Fin(30 * time.Second)
			groupPub := &ecdsa.PublicKey{Curve: ethcrypto.S256(), X: sd.ECDSAPub.X(), Y: sd.ECDSAPub.Y()}
			return sd, groupPub, nil
		case <-time.After(timeout):
			return nil, nil, fmt.Errorf("operator %d: keygen timed out after %s", selfIdx, timeout)
		}
	}
}

// RunSign runs this operator's signing party to completion over the network.
// signPIDs is the sorted ordering of the SIGNING quorum (not all operators);
// selfIdx is this operator's position within that quorum. save is this
// operator's own key share. It returns the group SignatureData (r, s, recovery).
//
// M9 identifiable abort: a GG20 signing round can fail because a specific party
// produced an invalid zero-knowledge proof. tss-lib already attributes that fault
// to the offending `*tss.PartyID` (see ecdsa/signing/round_3.go, surfaced via
// `(*tss.Error).Culprits()`). When that happens here, RunSign returns a
// *FaultError naming the culprit's quorum-LOCAL index so the caller can map it to
// the global operator and produce a signed fault attestation. A culprit-bearing
// abort is NOT an anonymous failure: the protocol's own cryptography points at
// the operator that cheated.
func RunSign(net *Network, signPIDs tss.SortedPartyIDs, selfIdx, threshold int, save keygen.LocalPartySaveData, hash32 []byte, timeout time.Duration) (*common.SignatureData, error) {
	return runSign(net, signPIDs, selfIdx, threshold, save, hash32, timeout, false)
}

// RunSignMisbehaving is the M9 adversarial harness: it runs an OTHERWISE-real
// GG20 signing party but corrupts this operator's outgoing round-2 message so its
// zero-knowledge ProofBob fails verification at the honest parties. tss-lib then
// attributes the fault to THIS operator in round 3 — exactly the real fault path
// the honest quorum attests on. This is the only operator that misbehaves; the
// rest run the unmodified protocol. It is never used in the honest signing path.
func RunSignMisbehaving(net *Network, signPIDs tss.SortedPartyIDs, selfIdx, threshold int, save keygen.LocalPartySaveData, hash32 []byte, timeout time.Duration) (*common.SignatureData, error) {
	return runSign(net, signPIDs, selfIdx, threshold, save, hash32, timeout, true)
}

func runSign(net *Network, signPIDs tss.SortedPartyIDs, selfIdx, threshold int, save keygen.LocalPartySaveData, hash32 []byte, timeout time.Duration, corrupt bool) (*common.SignatureData, error) {
	ctx := tss.NewPeerContext(signPIDs)
	params := tss.NewParameters(tss.S256(), ctx, signPIDs[selfIdx], len(signPIDs), threshold)
	msg := new(big.Int).SetBytes(hash32)

	outCh := make(chan tss.Message, len(signPIDs)*8)
	endCh := make(chan *common.SignatureData, 1)
	partyErr := make(chan *tss.Error, 1)

	party := signing.NewLocalParty(msg, params, save, outCh, endCh).(*signing.LocalParty)
	go func() {
		if err := party.Start(); err != nil {
			partyErr <- err
		}
	}()

	for {
		select {
		case msg := <-outCh:
			out := msg
			if corrupt {
				if c := corruptRound2(msg); c != nil {
					out = c
				}
			}
			if err := dispatch(net, out); err != nil {
				return nil, fmt.Errorf("operator %d: dispatch: %w", selfIdx, err)
			}
		case e := <-net.Inbox():
			if err := feed(party, signPIDs, e, selfIdx); err != nil {
				return nil, err
			}
		case terr := <-net.Errs():
			// A peer disconnect during signing can be the SYMPTOM of an
			// identifiable abort: a misbehaving peer (or an honest peer that
			// already detected the culprit) tears its socket down, and we see the
			// drop a beat before our OWN round surfaces the culprit. The culprit is
			// computed locally from round-2 messages we already hold, so give the
			// party a brief grace window to surface a *FaultError before falling
			// back to an anonymous transport abort. This makes identifiable abort
			// deterministic under the teardown race instead of sometimes
			// collapsing to "peer disconnected".
			select {
			case perr := <-partyErr:
				if fe := faultFromTSSError(perr); fe != nil {
					return nil, fe
				}
				return nil, fmt.Errorf("operator %d: party error: %w", selfIdx, perr.Cause())
			case <-time.After(2 * time.Second):
				return nil, fmt.Errorf("transport aborted: %w", terr)
			}
		case perr := <-partyErr:
			if fe := faultFromTSSError(perr); fe != nil {
				return nil, fe
			}
			return nil, fmt.Errorf("operator %d: party error: %w", selfIdx, perr.Cause())
		case sd := <-endCh:
			net.Fin(30 * time.Second)
			return sd, nil
		case <-time.After(timeout):
			return nil, fmt.Errorf("operator %d: signing timed out after %s", selfIdx, timeout)
		}
	}
}

// feed parses an authenticated inbound Envelope into a tss.Message and applies
// it to the party. A parse error (malformed protocol bytes that nonetheless
// passed the wire auth) or a protocol-level Update error aborts the run. When the
// protocol error attributes the fault to specific culprits, feed surfaces a
// *FaultError (M9) instead of collapsing it into an anonymous abort.
func feed(party tss.Party, pids tss.SortedPartyIDs, e *Envelope, selfIdx int) error {
	var from *tss.PartyID
	for _, p := range pids {
		if p.Index == e.From {
			from = p
			break
		}
	}
	if from == nil {
		return fmt.Errorf("operator %d: message from unknown party index %d", selfIdx, e.From)
	}
	pmsg, err := tss.ParseWireMessage(e.Payload, from, e.IsBroadcast)
	if err != nil {
		return fmt.Errorf("operator %d: parse wire message from %d: %w", selfIdx, e.From, err)
	}
	if _, perr := party.Update(pmsg); perr != nil {
		if fe := faultFromTSSError(perr); fe != nil {
			return fe
		}
		return fmt.Errorf("operator %d: protocol update from %d: %w", selfIdx, e.From, perr.Cause())
	}
	return nil
}

// faultFromTSSError converts a tss-lib protocol error into a *FaultError when the
// error names cryptographic culprits (failed ZK-proof verification). It returns
// nil for errors with no attributed culprit, which the caller treats as an
// ordinary (anonymous) abort. The culprit indices are quorum-LOCAL party indices.
func faultFromTSSError(perr *tss.Error) *FaultError {
	if perr == nil {
		return nil
	}
	culprits := perr.Culprits()
	if len(culprits) == 0 {
		return nil
	}
	local := make([]int, 0, len(culprits))
	seen := make(map[int]bool, len(culprits))
	for _, c := range culprits {
		if c == nil || seen[c.Index] {
			continue
		}
		seen[c.Index] = true
		local = append(local, c.Index)
	}
	if len(local) == 0 {
		return nil
	}
	return &FaultError{
		Round:        perr.Round(),
		CulpritLocal: local,
		cause:        perr.Cause(),
	}
}

// corruptRound2 takes this operator's genuine outgoing signing message and, if it
// is the round-2 message (the one carrying the MtA range proofs), returns a copy
// whose ProofBob is tampered so it fails verification at the honest parties. For
// any other message it returns nil (send the original). The corruption keeps the
// proof structurally valid (still ProofBobBytesParts non-empty components, still
// parseable) so it reaches the round-3 cryptographic check rather than being
// rejected as a malformed frame — which is what makes the honest parties blame
// THIS operator specifically.
func corruptRound2(msg tss.Message) tss.Message {
	pm, ok := msg.(tss.ParsedMessage)
	if !ok {
		return nil
	}
	r2, ok := pm.Content().(*signing.SignRound2Message)
	if !ok {
		return nil
	}
	// Clone the content and flip a byte inside the first ProofBob component. The
	// component stays non-empty (ValidateBasic passes) and parses as a big.Int
	// (UnmarshalProofBob passes), but the proof no longer verifies in AliceEnd.
	tampered := &signing.SignRound2Message{
		C1:         r2.C1,
		C2:         r2.C2,
		ProofBob:   cloneBytes2D(r2.ProofBob),
		ProofBobWc: r2.ProofBobWc,
	}
	for i := range tampered.ProofBob {
		if len(tampered.ProofBob[i]) > 0 {
			tampered.ProofBob[i] = append([]byte(nil), tampered.ProofBob[i]...)
			tampered.ProofBob[i][0] ^= 0xff
			break
		}
	}
	routing := tss.MessageRouting{
		From:        msg.GetFrom(),
		To:          msg.GetTo(),
		IsBroadcast: msg.IsBroadcast(),
	}
	wrapper := tss.NewMessageWrapper(routing, tampered)
	return tss.NewMessage(routing, tampered, wrapper)
}

func cloneBytes2D(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i := range in {
		out[i] = in[i]
	}
	return out
}

// dispatch routes one outgoing tss.Message over the network using tss-lib's own
// routing contract: GetTo()==nil is a broadcast (every other participant), else
// it is point-to-point to each listed recipient index.
func dispatch(net *Network, msg tss.Message) error {
	bz, _, err := msg.WireBytes()
	if err != nil {
		return fmt.Errorf("wire bytes: %w", err)
	}
	to := msg.GetTo()
	if to == nil { // broadcast
		return net.Broadcast(bz)
	}
	for _, dest := range to {
		if err := net.SendTo(dest.Index, bz); err != nil {
			return err
		}
	}
	return nil
}
