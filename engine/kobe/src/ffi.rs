//! C ABI over the AUDITED ZF `frost-ed25519` crate, for the networked FROST path.
//!
//! ## Why this exists (M11-Part-2 / fork decision F1)
//!
//! The GG20/ECDSA operator path (`engine/kobe-ecdsa/net`) is already production
//! networked + hardened: separate operator processes over mutual-TLS/PKI, peer
//! pinning, identity-key envelopes, encrypted shares at rest, identifiable abort.
//! That transport is **scheme-agnostic** — it carries opaque `[]byte` payloads and
//! never parses tss-lib. So the smallest correct way to network FROST with the
//! SAME hardening is to KEEP that Go transport verbatim and drive the FROST
//! cryptography from the audited Rust crate over this thin C ABI. No new crypto
//! (we wrap the audited crate), no second TLS/PKI stack (we reuse the Go one).
//!
//! See `engine/HARDENING.md` (M11-Part-2) for why F2 (a Go FROST lib) was
//! rejected: the only Go FROST-Ed25519 library is unaudited, explicitly not
//! side-channel-free, and unmaintained since 2021 — swapping it in for Solana key
//! custody would DOWNGRADE crypto provenance, against the campaign's "wrap audited
//! libs, never roll your own / never ship unvetted crypto" rule.
//!
//! ## Contract
//!
//! Every function is **pure**: it takes input bytes, returns output bytes, and
//! holds NO state across calls. All per-operator secret state (the DKG secret
//! packages, the signing nonces, the long-lived key share) lives in opaque blobs
//! that the Go operator stores and passes back in. This keeps the crypto entirely
//! in the audited crate and the orchestration entirely in Go, with a clean seam:
//!
//!   - `frost_dkg_part1(idx, max, min) -> (secret_state, round1_pkg_broadcast)`
//!   - `frost_dkg_part2(secret_state, [round1 pkgs]) -> (secret_state2, [round2 p2p pkgs])`
//!   - `frost_dkg_part3(secret_state2, [round1 pkgs], [round2 pkgs]) -> (key_share, group_pubkey)`
//!   - `frost_sign_round1(key_share) -> (nonces_state, commitments)`
//!   - `frost_sign_round2(key_share, nonces_state, msg, [all commitments]) -> sig_share`
//!   - `frost_aggregate(msg, [all commitments], [all sig shares], group_pkg) -> signature` (+ self-verify under ed25519-dalek)
//!
//! Round packages are addressed: round-1 DKG packages are broadcast; round-2 DKG
//! packages are per-recipient SECRET shares (the Go transport sends them p2p,
//! inside the mutual-TLS tunnel — encrypted in transit). The wire encoding of each
//! package is the crate's own `serialize()`; this module only wraps a tiny
//! length-prefixed framing so multiple packages fit one opaque buffer.

use std::collections::BTreeMap;
use std::slice;

use ed25519_dalek::{Signature as DalekSig, Verifier, VerifyingKey as DalekKey};
use frost_ed25519 as frost;
use frost::keys::dkg;
use frost::{
    keys::{KeyPackage, PublicKeyPackage},
    round1, round2, Identifier, Signature, SigningPackage,
};
use rand::rngs::OsRng;

// ---------------------------------------------------------------------------
// C ABI buffer plumbing. The contract with Go: every fn returns 0 on success,
// nonzero on error; output bytes are written to a freshly-malloc'd buffer whose
// pointer+len are returned through out-params, and Go frees it via `frost_free`.
// ---------------------------------------------------------------------------

/// One owned output buffer handed to Go. Go must call `frost_free` exactly once.
#[repr(C)]
pub struct Buf {
    ptr: *mut u8,
    len: usize,
}

impl Buf {
    fn from_vec(v: Vec<u8>) -> Buf {
        // An empty result carries no heap allocation; hand Go a clean null/0 so the
        // free path never reconstructs a box from a dangling pointer.
        if v.is_empty() {
            return Buf::empty();
        }
        // `into_boxed_slice` GUARANTEES the allocation is exactly `len` bytes (cap ==
        // len), so reconstructing the box on free with the same `len` is sound. This
        // is what makes the Rust↔Go ownership transfer safe: relying on
        // `shrink_to_fit` would NOT, because it is permitted to leave cap > len, and
        // then freeing with `from_raw_parts(ptr, len, len)` would deallocate with the
        // wrong layout size (UB on most allocators).
        let boxed: Box<[u8]> = v.into_boxed_slice();
        let len = boxed.len();
        let ptr = Box::into_raw(boxed) as *mut u8;
        Buf { ptr, len }
    }
    fn empty() -> Buf {
        Buf {
            ptr: std::ptr::null_mut(),
            len: 0,
        }
    }
}

/// Frees a buffer previously returned to Go. Idempotent on a null pointer.
///
/// # Safety
/// `b` must be a `Buf` returned by one of this module's functions and not yet
/// freed. Double-free or freeing a foreign pointer is undefined behaviour.
#[no_mangle]
pub unsafe extern "C" fn frost_free(b: Buf) {
    if !b.ptr.is_null() && b.len != 0 {
        // Reconstruct the exact `Box<[u8]>` `from_vec` leaked (cap == len), so the
        // global allocator sees the identical layout it allocated.
        let slice = std::ptr::slice_from_raw_parts_mut(b.ptr, b.len);
        drop(Box::from_raw(slice));
    }
}

/// Reads a borrowed input slice from a (ptr,len) pair.
///
/// # Safety
/// `ptr`/`len` must describe a valid readable region for the call's duration.
unsafe fn input(ptr: *const u8, len: usize) -> &'static [u8] {
    if ptr.is_null() || len == 0 {
        &[]
    } else {
        slice::from_raw_parts(ptr, len)
    }
}

/// Result codes shared with Go (see frost_ffi.go). 0 == OK.
const OK: i32 = 0;
const ERR_INPUT: i32 = 1;
const ERR_FROST: i32 = 2;

fn ok(out: &mut Buf, v: Vec<u8>) -> i32 {
    *out = Buf::from_vec(v);
    OK
}

// ---------------------------------------------------------------------------
// Length-prefixed framing for "a list of (identifier, package-bytes)" so that an
// entire DKG/signing round fits one opaque buffer. Each item is:
//   [2-byte BE identifier index][4-byte BE len][package bytes]
// The identifier is the 1-based participant index (Identifier::try_from(u16)).
// ---------------------------------------------------------------------------

fn put_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_be_bytes());
}
fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn encode_items(items: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    put_u16(&mut out, items.len() as u16);
    for (idx, bytes) in items {
        put_u16(&mut out, *idx);
        put_u32(&mut out, bytes.len() as u32);
        out.extend_from_slice(bytes);
    }
    out
}

fn decode_items(mut b: &[u8]) -> Option<Vec<(u16, Vec<u8>)>> {
    if b.len() < 2 {
        return None;
    }
    let n = u16::from_be_bytes([b[0], b[1]]) as usize;
    b = &b[2..];
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        if b.len() < 6 {
            return None;
        }
        let idx = u16::from_be_bytes([b[0], b[1]]);
        let len = u32::from_be_bytes([b[2], b[3], b[4], b[5]]) as usize;
        b = &b[6..];
        if b.len() < len {
            return None;
        }
        out.push((idx, b[..len].to_vec()));
        b = &b[len..];
    }
    Some(out)
}

fn ident(u: u16) -> Result<Identifier, i32> {
    Identifier::try_from(u).map_err(|_| ERR_FROST)
}

// ===========================================================================
// DKG — a real distributed key generation (no trusted dealer). RFC 9591 3-part
// flow: nobody ever holds the full signing key; each operator computes its own
// share from the round-1 commitments + round-2 secret shares it receives.
// ===========================================================================

/// part1: this operator samples its polynomial, returns its long-lived round-1
/// SECRET package (opaque, stays in this operator's process) and the round-1
/// public package to BROADCAST to every peer.
///
/// # Safety
/// Out-params must be valid non-null pointers; on OK both buffers are owned by Go.
#[no_mangle]
pub unsafe extern "C" fn frost_dkg_part1(
    self_idx: u16,
    max_signers: u16,
    min_signers: u16,
    out_secret: *mut Buf,
    out_round1: *mut Buf,
) -> i32 {
    let (out_secret, out_round1) = (&mut *out_secret, &mut *out_round1);
    *out_secret = Buf::empty();
    *out_round1 = Buf::empty();
    let id = match ident(self_idx) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let (secret, pkg) = match dkg::part1(id, max_signers, min_signers, OsRng) {
        Ok(v) => v,
        Err(_) => return ERR_FROST,
    };
    let secret_bytes = match secret.serialize() {
        Ok(b) => b,
        Err(_) => return ERR_FROST,
    };
    let pkg_bytes = match pkg.serialize() {
        Ok(b) => b,
        Err(_) => return ERR_FROST,
    };
    ok(out_secret, secret_bytes);
    ok(out_round1, pkg_bytes)
}

/// part2: consume my round-1 secret + every PEER's round-1 public package; return
/// my round-2 secret package (opaque, kept) and the per-recipient round-2 packages
/// (each addressed to one peer identifier — sent p2p inside the TLS tunnel).
///
/// `round1_items` is the encode_items() framing of (peer_idx, round1_pkg_bytes)
/// for all peers EXCEPT self.
///
/// # Safety
/// Pointers must describe valid regions; out-params valid non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn frost_dkg_part2(
    secret_ptr: *const u8,
    secret_len: usize,
    round1_ptr: *const u8,
    round1_len: usize,
    out_secret2: *mut Buf,
    out_round2: *mut Buf,
) -> i32 {
    let (out_secret2, out_round2) = (&mut *out_secret2, &mut *out_round2);
    *out_secret2 = Buf::empty();
    *out_round2 = Buf::empty();

    let secret = match dkg::round1::SecretPackage::deserialize(input(secret_ptr, secret_len)) {
        Ok(s) => s,
        Err(_) => return ERR_INPUT,
    };
    let items = match decode_items(input(round1_ptr, round1_len)) {
        Some(v) => v,
        None => return ERR_INPUT,
    };
    let mut round1_packages: BTreeMap<Identifier, dkg::round1::Package> = BTreeMap::new();
    for (idx, bytes) in &items {
        let id = match ident(*idx) {
            Ok(i) => i,
            Err(e) => return e,
        };
        match dkg::round1::Package::deserialize(bytes) {
            Ok(p) => {
                round1_packages.insert(id, p);
            }
            Err(_) => return ERR_INPUT,
        }
    }
    let (secret2, round2_packages) = match dkg::part2(secret, &round1_packages) {
        Ok(v) => v,
        Err(_) => return ERR_FROST,
    };
    let secret2_bytes = match secret2.serialize() {
        Ok(b) => b,
        Err(_) => return ERR_FROST,
    };
    let mut items_out: Vec<(u16, Vec<u8>)> = Vec::with_capacity(round2_packages.len());
    for (id, pkg) in &round2_packages {
        let idx = id_to_u16(id);
        let b = match pkg.serialize() {
            Ok(b) => b,
            Err(_) => return ERR_FROST,
        };
        items_out.push((idx, b));
    }
    ok(out_secret2, secret2_bytes);
    ok(out_round2, encode_items(&items_out))
}

/// part3: finish DKG. Consume my round-2 secret, all peers' round-1 packages, and
/// the round-2 packages addressed TO me; produce my long-lived KeyPackage (the
/// secret share — opaque, encrypted at rest by the Go side) and the group
/// PublicKeyPackage (public; used by the aggregator). Also returns the 32-byte
/// group verifying key for convenience/registration.
///
/// # Safety
/// Pointers must describe valid regions; out-params valid non-null pointers.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn frost_dkg_part3(
    secret2_ptr: *const u8,
    secret2_len: usize,
    round1_ptr: *const u8,
    round1_len: usize,
    round2_ptr: *const u8,
    round2_len: usize,
    out_keyshare: *mut Buf,
    out_pubpkg: *mut Buf,
    out_groupkey: *mut Buf,
) -> i32 {
    let (out_keyshare, out_pubpkg, out_groupkey) =
        (&mut *out_keyshare, &mut *out_pubpkg, &mut *out_groupkey);
    *out_keyshare = Buf::empty();
    *out_pubpkg = Buf::empty();
    *out_groupkey = Buf::empty();

    let secret2 = match dkg::round2::SecretPackage::deserialize(input(secret2_ptr, secret2_len)) {
        Ok(s) => s,
        Err(_) => return ERR_INPUT,
    };
    let r1_items = match decode_items(input(round1_ptr, round1_len)) {
        Some(v) => v,
        None => return ERR_INPUT,
    };
    let r2_items = match decode_items(input(round2_ptr, round2_len)) {
        Some(v) => v,
        None => return ERR_INPUT,
    };
    let mut round1_packages: BTreeMap<Identifier, dkg::round1::Package> = BTreeMap::new();
    for (idx, bytes) in &r1_items {
        let id = match ident(*idx) {
            Ok(i) => i,
            Err(e) => return e,
        };
        match dkg::round1::Package::deserialize(bytes) {
            Ok(p) => {
                round1_packages.insert(id, p);
            }
            Err(_) => return ERR_INPUT,
        }
    }
    let mut round2_packages: BTreeMap<Identifier, dkg::round2::Package> = BTreeMap::new();
    for (idx, bytes) in &r2_items {
        let id = match ident(*idx) {
            Ok(i) => i,
            Err(e) => return e,
        };
        match dkg::round2::Package::deserialize(bytes) {
            Ok(p) => {
                round2_packages.insert(id, p);
            }
            Err(_) => return ERR_INPUT,
        }
    }
    let (key_package, pubkey_package) =
        match dkg::part3(&secret2, &round1_packages, &round2_packages) {
            Ok(v) => v,
            Err(_) => return ERR_FROST,
        };
    let ks_bytes = match key_package.serialize() {
        Ok(b) => b,
        Err(_) => return ERR_FROST,
    };
    let pp_bytes = match pubkey_package.serialize() {
        Ok(b) => b,
        Err(_) => return ERR_FROST,
    };
    let gk = match pubkey_package.verifying_key().serialize() {
        Ok(b) => b,
        Err(_) => return ERR_FROST,
    };
    ok(out_keyshare, ks_bytes);
    ok(out_pubpkg, pp_bytes);
    ok(out_groupkey, gk)
}

// ===========================================================================
// Signing — FROST round 1 (nonce commitments) / round 2 (signature shares) /
// aggregate. Only a t-subset participates.
// ===========================================================================

/// sign_round1: from my KeyPackage produce my secret nonces (opaque, kept) and my
/// public SigningCommitments (broadcast to the quorum + aggregator).
///
/// # Safety
/// Pointers must describe valid regions; out-params valid non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn frost_sign_round1(
    keyshare_ptr: *const u8,
    keyshare_len: usize,
    out_nonces: *mut Buf,
    out_commitments: *mut Buf,
) -> i32 {
    let (out_nonces, out_commitments) = (&mut *out_nonces, &mut *out_commitments);
    *out_nonces = Buf::empty();
    *out_commitments = Buf::empty();

    let key_package = match KeyPackage::deserialize(input(keyshare_ptr, keyshare_len)) {
        Ok(k) => k,
        Err(_) => return ERR_INPUT,
    };
    let (nonces, commitments) = round1::commit(key_package.signing_share(), &mut OsRng);
    let n_bytes = match nonces.serialize() {
        Ok(b) => b,
        Err(_) => return ERR_FROST,
    };
    let c_bytes = match commitments.serialize() {
        Ok(b) => b,
        Err(_) => return ERR_FROST,
    };
    ok(out_nonces, n_bytes);
    ok(out_commitments, c_bytes)
}

/// build a SigningPackage from the quorum's commitments + the 32-byte message.
fn build_signing_package(
    msg: &[u8],
    commitments_blob: &[u8],
) -> Result<SigningPackage, i32> {
    let items = decode_items(commitments_blob).ok_or(ERR_INPUT)?;
    let mut commitments: BTreeMap<Identifier, round1::SigningCommitments> = BTreeMap::new();
    for (idx, bytes) in &items {
        let id = ident(*idx)?;
        let c = round1::SigningCommitments::deserialize(bytes).map_err(|_| ERR_INPUT)?;
        commitments.insert(id, c);
    }
    Ok(SigningPackage::new(commitments, msg))
}

/// sign_round2: from my KeyPackage + my kept nonces + the quorum's commitments +
/// the message, produce MY signature share (broadcast to the aggregator).
///
/// # Safety
/// Pointers must describe valid regions; out-param a valid non-null pointer.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn frost_sign_round2(
    keyshare_ptr: *const u8,
    keyshare_len: usize,
    nonces_ptr: *const u8,
    nonces_len: usize,
    msg_ptr: *const u8,
    msg_len: usize,
    commitments_ptr: *const u8,
    commitments_len: usize,
    out_share: *mut Buf,
) -> i32 {
    let out_share = &mut *out_share;
    *out_share = Buf::empty();

    let key_package = match KeyPackage::deserialize(input(keyshare_ptr, keyshare_len)) {
        Ok(k) => k,
        Err(_) => return ERR_INPUT,
    };
    let nonces = match round1::SigningNonces::deserialize(input(nonces_ptr, nonces_len)) {
        Ok(n) => n,
        Err(_) => return ERR_INPUT,
    };
    let msg = input(msg_ptr, msg_len);
    let signing_package = match build_signing_package(msg, input(commitments_ptr, commitments_len)) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let share = match round2::sign(&signing_package, &nonces, &key_package) {
        Ok(s) => s,
        Err(_) => return ERR_FROST,
    };
    ok(out_share, share.serialize())
}

/// aggregate: from the message + the quorum's commitments + every signature share
/// + the group PublicKeyPackage, combine into ONE Ed25519 signature. frost's own
/// aggregate verifies the result against the group key; we ALSO re-verify under
/// the independent ed25519-dalek (the RFC 8032 primitive Solana runs) before
/// handing the 64-byte signature back, so a green return is a real cryptographic
/// fact, not "it combined".
///
/// On a bad signature share, frost::aggregate's error names the culprit
/// identifier(s); we surface the first culprit index in `out_culprit` (0 = none)
/// so the Go side can drive FROST's identifiable-abort analog.
///
/// # Safety
/// Pointers must describe valid regions; out-params valid non-null pointers.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn frost_aggregate(
    msg_ptr: *const u8,
    msg_len: usize,
    commitments_ptr: *const u8,
    commitments_len: usize,
    shares_ptr: *const u8,
    shares_len: usize,
    pubpkg_ptr: *const u8,
    pubpkg_len: usize,
    out_signature: *mut Buf,
    out_culprit: *mut u16,
) -> i32 {
    let (out_signature, out_culprit) = (&mut *out_signature, &mut *out_culprit);
    *out_signature = Buf::empty();
    *out_culprit = 0;

    let msg = input(msg_ptr, msg_len);
    let signing_package = match build_signing_package(msg, input(commitments_ptr, commitments_len)) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let share_items = match decode_items(input(shares_ptr, shares_len)) {
        Some(v) => v,
        None => return ERR_INPUT,
    };
    let mut shares: BTreeMap<Identifier, round2::SignatureShare> = BTreeMap::new();
    for (idx, bytes) in &share_items {
        let id = match ident(*idx) {
            Ok(i) => i,
            Err(e) => return e,
        };
        match round2::SignatureShare::deserialize(bytes) {
            Ok(s) => {
                shares.insert(id, s);
            }
            Err(_) => return ERR_INPUT,
        }
    }
    let pubkey_package = match PublicKeyPackage::deserialize(input(pubpkg_ptr, pubpkg_len)) {
        Ok(p) => p,
        Err(_) => return ERR_INPUT,
    };

    let signature: Signature = match frost::aggregate(&signing_package, &shares, &pubkey_package) {
        Ok(s) => s,
        Err(e) => {
            // FROST identifiable abort: a sig share that fails verification is
            // attributed to its signer. Surface the first culprit so Go can
            // abort naming the operator, not anonymously.
            if let frost::Error::InvalidSignatureShare { culprits } = e {
                if let Some(c) = culprits.first() {
                    *out_culprit = id_to_u16(c);
                }
            }
            return ERR_FROST;
        }
    };

    let sig_bytes = match signature.serialize() {
        Ok(b) => b,
        Err(_) => return ERR_FROST,
    };
    let gk = match pubkey_package.verifying_key().serialize() {
        Ok(b) => b,
        Err(_) => return ERR_FROST,
    };

    // Defence in depth: re-verify under the INDEPENDENT standard verifier before
    // releasing the signature. This is the exact check Solana's runtime performs.
    let gk_arr: [u8; 32] = match gk.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return ERR_FROST,
    };
    let sig_arr: [u8; 64] = match sig_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return ERR_FROST,
    };
    let dalek_key = match DalekKey::from_bytes(&gk_arr) {
        Ok(k) => k,
        Err(_) => return ERR_FROST,
    };
    if dalek_key.verify(msg, &DalekSig::from_bytes(&sig_arr)).is_err() {
        return ERR_FROST;
    }

    ok(out_signature, sig_bytes)
}

/// Map a FROST Identifier back to its 1-based u16 index. The Ed25519 ciphersuite
/// serializes an Identifier as the little-endian scalar; for our small indices
/// the value is in the first byte(s). We recover it by matching against the
/// candidate range, which is exact for the operator counts we use.
fn id_to_u16(id: &Identifier) -> u16 {
    let ser = id.serialize();
    // Ed25519 scalars are 32-byte little-endian; a small participant index lives
    // in the low bytes. Read the low 2 bytes.
    let lo = *ser.first().unwrap_or(&0) as u16;
    let hi = *ser.get(1).unwrap_or(&0) as u16;
    lo | (hi << 8)
}
