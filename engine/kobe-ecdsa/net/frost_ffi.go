package kobenet

// CGO binding to the AUDITED ZF frost-ed25519 crate (engine/kobe, built as a
// cdylib). This is the F1 networked-FROST path: the hardened transport in this
// package (mutual TLS, PKI, peer pinning, identity-key envelopes, encrypted
// shares, FIN barrier) stays exactly as the GG20 path uses it; the FROST
// cryptography is NEVER reimplemented in Go — every round is computed by the
// audited Rust crate across this C ABI. See engine/kobe/src/ffi.rs and
// engine/HARDENING.md (M11-Part-2).
//
// Build/link: the dylib path is provided at build time. Run `engine/kobe/`'s
// `cargo build --release` first; the demo/test wiring sets CGO_LDFLAGS to point
// at engine/kobe/target/release.

/*
#include <stdint.h>
#include <stdlib.h>

// Mirror of the #[repr(C)] Buf in engine/kobe/src/ffi.rs.
typedef struct { uint8_t* ptr; uintptr_t len; } Buf;

void  frost_free(Buf b);
int32_t frost_dkg_part1(uint16_t self_idx, uint16_t max_signers, uint16_t min_signers, Buf* out_secret, Buf* out_round1);
int32_t frost_dkg_part2(const uint8_t* secret, uintptr_t secret_len, const uint8_t* round1, uintptr_t round1_len, Buf* out_secret2, Buf* out_round2);
int32_t frost_dkg_part3(const uint8_t* secret2, uintptr_t secret2_len, const uint8_t* round1, uintptr_t round1_len, const uint8_t* round2, uintptr_t round2_len, Buf* out_keyshare, Buf* out_pubpkg, Buf* out_groupkey);
int32_t frost_sign_round1(const uint8_t* keyshare, uintptr_t keyshare_len, Buf* out_nonces, Buf* out_commitments);
int32_t frost_sign_round2(const uint8_t* keyshare, uintptr_t keyshare_len, const uint8_t* nonces, uintptr_t nonces_len, const uint8_t* msg, uintptr_t msg_len, const uint8_t* commitments, uintptr_t commitments_len, Buf* out_share);
int32_t frost_aggregate(const uint8_t* msg, uintptr_t msg_len, const uint8_t* commitments, uintptr_t commitments_len, const uint8_t* shares, uintptr_t shares_len, const uint8_t* pubpkg, uintptr_t pubpkg_len, Buf* out_signature, uint16_t* out_culprit);
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"unsafe"
)

// frostResult codes mirror engine/kobe/src/ffi.rs.
const (
	frostOK       = 0
	frostErrInput = 1
	frostErrFrost = 2
)

func frostErr(code C.int32_t, op string) error {
	switch int(code) {
	case frostOK:
		return nil
	case frostErrInput:
		return fmt.Errorf("frost ffi %s: bad input", op)
	default:
		return fmt.Errorf("frost ffi %s: crypto error (code %d)", op, int(code))
	}
}

// take copies an owned Rust Buf into a Go []byte and frees the Rust allocation.
func take(b C.Buf) []byte {
	if b.ptr == nil || b.len == 0 {
		C.frost_free(b)
		return nil
	}
	out := C.GoBytes(unsafe.Pointer(b.ptr), C.int(b.len))
	C.frost_free(b)
	return out
}

// ptr returns the address of the first byte (or a harmless non-nil for empty
// slices, since the Rust side treats len==0 as empty regardless of pointer).
func ptr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

// --- The encode_items framing must match engine/kobe/src/ffi.rs exactly:
//   [2B BE count] then per item: [2B BE identifier][4B BE len][bytes].
// identifier is the 1-based FROST participant index.

type frostItem struct {
	id    uint16 // 1-based FROST identifier
	bytes []byte
}

func encodeFrostItems(items []frostItem) []byte {
	out := make([]byte, 0, 2+len(items)*8)
	var n [4]byte
	binary.BigEndian.PutUint16(n[:2], uint16(len(items)))
	out = append(out, n[:2]...)
	for _, it := range items {
		binary.BigEndian.PutUint16(n[:2], it.id)
		out = append(out, n[:2]...)
		binary.BigEndian.PutUint32(n[:4], uint32(len(it.bytes)))
		out = append(out, n[:4]...)
		out = append(out, it.bytes...)
	}
	return out
}

func decodeFrostItems(b []byte) ([]frostItem, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("frost items: short buffer")
	}
	n := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	out := make([]frostItem, 0, n)
	for i := 0; i < n; i++ {
		if len(b) < 6 {
			return nil, fmt.Errorf("frost items: truncated header")
		}
		id := binary.BigEndian.Uint16(b[:2])
		ln := int(binary.BigEndian.Uint32(b[2:6]))
		b = b[6:]
		if len(b) < ln {
			return nil, fmt.Errorf("frost items: truncated payload")
		}
		out = append(out, frostItem{id: id, bytes: append([]byte(nil), b[:ln]...)})
		b = b[ln:]
	}
	return out, nil
}

// ===========================================================================
// Thin Go wrappers over the C ABI. Each is pure: bytes in, bytes out. No state
// is held in Go between calls — all secret material round-trips as opaque blobs.
// ===========================================================================

func frostDKGPart1(selfID, maxSigners, minSigners uint16) (secret, round1Pkg []byte, err error) {
	var outSecret, outRound1 C.Buf
	code := C.frost_dkg_part1(C.uint16_t(selfID), C.uint16_t(maxSigners), C.uint16_t(minSigners), &outSecret, &outRound1)
	if e := frostErr(code, "dkg_part1"); e != nil {
		take(outSecret)
		take(outRound1)
		return nil, nil, e
	}
	return take(outSecret), take(outRound1), nil
}

func frostDKGPart2(secret []byte, round1Items []frostItem) (secret2, round2Blob []byte, err error) {
	r1 := encodeFrostItems(round1Items)
	var outSecret2, outRound2 C.Buf
	code := C.frost_dkg_part2(ptr(secret), C.uintptr_t(len(secret)), ptr(r1), C.uintptr_t(len(r1)), &outSecret2, &outRound2)
	if e := frostErr(code, "dkg_part2"); e != nil {
		take(outSecret2)
		take(outRound2)
		return nil, nil, e
	}
	return take(outSecret2), take(outRound2), nil
}

func frostDKGPart3(secret2 []byte, round1Items, round2Items []frostItem) (keyShare, pubPkg, groupKey []byte, err error) {
	r1 := encodeFrostItems(round1Items)
	r2 := encodeFrostItems(round2Items)
	var outKS, outPP, outGK C.Buf
	code := C.frost_dkg_part3(ptr(secret2), C.uintptr_t(len(secret2)), ptr(r1), C.uintptr_t(len(r1)), ptr(r2), C.uintptr_t(len(r2)), &outKS, &outPP, &outGK)
	if e := frostErr(code, "dkg_part3"); e != nil {
		take(outKS)
		take(outPP)
		take(outGK)
		return nil, nil, nil, e
	}
	return take(outKS), take(outPP), take(outGK), nil
}

func frostSignRound1(keyShare []byte) (nonces, commitments []byte, err error) {
	var outNonces, outComm C.Buf
	code := C.frost_sign_round1(ptr(keyShare), C.uintptr_t(len(keyShare)), &outNonces, &outComm)
	if e := frostErr(code, "sign_round1"); e != nil {
		take(outNonces)
		take(outComm)
		return nil, nil, e
	}
	return take(outNonces), take(outComm), nil
}

func frostSignRound2(keyShare, nonces, msg []byte, commitmentItems []frostItem) (share []byte, err error) {
	comm := encodeFrostItems(commitmentItems)
	var outShare C.Buf
	code := C.frost_sign_round2(ptr(keyShare), C.uintptr_t(len(keyShare)), ptr(nonces), C.uintptr_t(len(nonces)), ptr(msg), C.uintptr_t(len(msg)), ptr(comm), C.uintptr_t(len(comm)), &outShare)
	if e := frostErr(code, "sign_round2"); e != nil {
		take(outShare)
		return nil, e
	}
	return take(outShare), nil
}

// frostAggregate combines the quorum's shares into one Ed25519 signature. The
// Rust side ALSO re-verifies under ed25519-dalek before returning. On a bad
// share, culprit is the 1-based FROST identifier of the offending signer (0 if
// none was attributable) — FROST's identifiable-abort analog.
func frostAggregate(msg []byte, commitmentItems, shareItems []frostItem, pubPkg []byte) (signature []byte, culprit uint16, err error) {
	comm := encodeFrostItems(commitmentItems)
	shares := encodeFrostItems(shareItems)
	var outSig C.Buf
	var outCulprit C.uint16_t
	code := C.frost_aggregate(ptr(msg), C.uintptr_t(len(msg)), ptr(comm), C.uintptr_t(len(comm)), ptr(shares), C.uintptr_t(len(shares)), ptr(pubPkg), C.uintptr_t(len(pubPkg)), &outSig, &outCulprit)
	if e := frostErr(code, "aggregate"); e != nil {
		take(outSig)
		return nil, uint16(outCulprit), e
	}
	return take(outSig), uint16(outCulprit), nil
}
