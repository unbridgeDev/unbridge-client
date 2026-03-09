# kobe-ecdsa — Distin threshold-ECDSA signer (secp256k1: ETH, BTC, Tron)

The secp256k1 half of Distin's off-chain MPC signer: 2-of-3 **threshold ECDSA**
producing one signature that Ethereum, **Bitcoin**, and **Tron** nodes natively
verify. This is the `Gg20Secp256k1` scheme the on-chain `distin` program
references for its EVM / BTC / Tron branch (the Ed25519 / FROST half lives in the
sibling Rust crate `engine/kobe/`).

The same `(r, s)` the GG20 protocol outputs IS a valid signature on all three
chains; the only per-chain work is the envelope around it (address derivation,
what message gets hashed, signature encoding). See `btc.go` / `tron.go`.

It is a standalone Go module, deliberately separate from the Rust on-chain build
so nothing here can perturb the Solana SBF program.

## What it does

```
DistributedKeyGen(3, 1)            -> 3 key shares + one group secp256k1 pubkey
ThresholdSign(any 2 shares, hash)  -> one standard ECDSA (r, s, v) signature
RecoverAddress(hash, sig)          -> the signer's ETH address (go-ethereum Ecrecover)
```

The group private key is never reconstructed. Each party holds only a Shamir
share; the GG20 protocol combines partial signatures into one `(r, s, v)` that
recovers to the group account's Ethereum address.

## Library

[`github.com/bnb-chain/tss-lib`](https://github.com/bnb-chain/tss-lib) **v2.0.2**
— Binance's audited, production-proven reference implementation of GG18/GG20
threshold ECDSA. No hand-rolled curve math or MPC rounds. The curve is set to
`secp256k1` (`go-ethereum/crypto.S256()`) so the output is a standard Ethereum
signature, not the tss-lib default (P-256).

`go.mod` carries the same `replace github.com/agl/ed25519 =>
github.com/binance-chain/edwards25519` directive tss-lib itself uses (a `replace`
in a dependency does not propagate, so it must be repeated here or `go mod tidy`
fails on the dead `agl/ed25519` path).

## Verify it yourself

```
go test -v -timeout 600s     # 3 tests; DKG safe-prime gen makes them slow (~20-30s each)
go run ./cmd/ecdsa_demo      # prints group address, signature, RECOVERED ADDRESS MATCHES
```

## CLI seam (driven by the Rust coordinator)

`cmd/kobe-ecdsa` is the subprocess seam the off-chain Rust coordinator
(`engine/coordinator`, bin `eth-demo`) invokes to obtain a real GG20 signature
for an on-chain `Gg20Secp256k1` request. It speaks JSON on stdout. Keygen is
split from signing so the slow distributed keygen runs once and the group key
can be registered on-chain before any request is signed:

```
go run ./cmd/kobe-ecdsa keygen -n 3 -t 1 -out shares.json
  -> {"group_pub":"04…","group_eth_address":"0x…", …}   # writes the shares file

go run ./cmd/kobe-ecdsa sign -shares shares.json -hash <64-hex> -quorum 0,2
  -> {"r":"…","s":"…","v":0,"sig65":"…","recovered_eth_address":"0x…","match":true}
```

Two more subcommands sign for Bitcoin and Tron from the SAME shares — they reuse
the identical secp256k1 signature and only change the per-chain envelope:

```
go run ./cmd/kobe-ecdsa btc -shares shares.json -sighash <64-hex> -quorum 0,2
  -> {"btc_address":"bc1q…","der_sighash_all":"30…01","verified":true}
     # threshold-signs a BIP-143 sighash, DER+SIGHASH_ALL encodes it, and
     # verifies it against the derived pubkey with decred secp256k1 (NOT tss-lib)

go run ./cmd/kobe-ecdsa tron -shares shares.json -txid <64-hex> -quorum 1,2
  -> {"tron_address":"T…","sig65":"…","recovered_tron_address":"T…","match":true}
     # threshold-signs the Tron tx id (sha256 of raw_data), formats the 65-byte
     # (r,s,v), and recovers the Tron address via go-ethereum Ecrecover
```

`shares.json` holds secret share material (it is `.gitignore`d). In production
each share would stay on its own operator host; the in-process simulation writes
them together so a separate `sign` invocation can drive the quorum.

The flagship check (`TestTwoOfThreeRecoversGroupEthAddress`) asserts the address
recovered from `(r, s, v)` by go-ethereum's `Ecrecover` — the exact primitive a
real ETH node runs — equals `keccak256(groupPubkey)[12:]`. Negative controls
(wrong message, tampered signature) must NOT recover the group address.
`TestSignatureIsEthWireFormat` additionally checks go-ethereum's
`VerifySignature` accepts the 64-byte `[R||S]` form against the compressed
group key.

## Scope / honest limits

- The N parties are simulated **in-process** over Go channels (no operator
  network, no wire transport).
- Wired into the full on-chain loop on localnet (Milestone 4): the Rust
  coordinator drives this signer over an on-chain `Gg20Secp256k1` request's
  `message_hash`, records the resulting `r||s` on-chain via `aggregate_and_emit`,
  and independently recovers the group ETH address from the on-chain bytes. The
  on-chain layer coordinates + records; the real group-combine happens here.
- **Bitcoin / Tron support is real and independently verified** (Milestone 5):
  - BTC: P2WPKH (bech32) address derivation matches the BIP-173 generator-pubkey
    vector; the BIP-143 sighash is byte-exact against an independent
    reimplementation; the DER+SIGHASH_ALL signature verifies under decred
    secp256k1 (a different library than the one that signed). Low-S (BIP-62)
    enforced. See `btc_test.go`.
  - Tron: keccak256 → 0x41 → base58check address (cross-checked against the
    privkey-1 vector `TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC`); the (r,s,v) recovers
    via go-ethereum Ecrecover to the same Tron address. See `tron_test.go`.
  - What's still simulated here: nothing on the crypto side; the per-chain
    *transaction assembly* (full PSBT/witness for BTC, protobuf `raw_data` for
    Tron) is the wallet's job and is out of scope — these subcommands sign the
    sighash/txid a wallet hands them.
- Nothing here is audited for real value. tss-lib is audited; this integration
  is not, and DKG ceremony security is out of scope for this milestone.

## Networked operator set (Milestone 6)

The `DistributedKeyGen` / `ThresholdSign` functions above run all parties
**in-process** over Go channels — convenient, but not a distributed protocol.
The `net/` package and `cmd/operator` binary turn that into a real one: **three
separate operator processes** that run the GG20 DKG and a 2-of-3 threshold sign
over actual TCP sockets, each holding only its own share, authenticating every
wire message with its Ed25519 identity key.

```
# one command runs the whole proof: networked DKG + sign + independent verify +
# the two negative cases (offline peer, spoofed operator)
./net/demo.sh
```

Or by hand, separate processes:

```
go run ./cmd/gen-operators -n 3 -base-port 9100 -dir ./operators
# distributed key generation — each line below is a SEPARATE process:
go run ./cmd/operator -config operators/op0.json -phase keygen -threshold 1 &
go run ./cmd/operator -config operators/op1.json -phase keygen -threshold 1 &
go run ./cmd/operator -config operators/op2.json -phase keygen -threshold 1 &
# 2-of-3 sign over the network (op1 stays offline):
go run ./cmd/operator -config operators/op0.json -phase sign -quorum 0,2 -hash <64hex> &
go run ./cmd/operator -config operators/op2.json -phase sign -quorum 0,2 -hash <64hex> &
```

- **Transport**: TCP (Go stdlib `net`), one length-prefixed connection per peer
  pair, full mesh. tss-lib already hands us a transport-ready `[]byte` +
  `IsBroadcast`/`GetTo` routing, so a byte stream is the natural fit; gRPC/ws/proto
  would add framing that buys nothing on localhost.
- **Authentication**: each operator has an Ed25519 identity key. A handshake
  pins the peer's public key from the static directory and runs a nonce
  challenge-response (proving private-key ownership); every protocol frame is
  then signed over `(session, from, to, is_broadcast, fin, payload)` and verified
  against the pinned key. A spoofed key or a tampered/re-addressed frame is
  rejected.
- **Clean abort**: a peer that never comes up, drops mid-protocol, or fails the
  handshake makes the run abort cleanly (bounded by timeout, nonzero exit, **no
  partial/garbage signature emitted**) rather than hanging.

### What is real vs still simplified

- REAL: three independent OS processes (distinct PIDs / ports / identity keys /
  share files), the GG20 DKG and 2-of-3 sign genuinely crossing TCP sockets,
  Ed25519 wire authentication, and the resulting signature verifying via an
  independent go-ethereum ecrecover to the group address.
- SIMPLIFIED (localhost proof, not a hardened network): no TLS and no PKI (the
  peer directory is a static pinned-key file, not a CA); no peer discovery or
  reconnection; in this milestone the abort is **fail-stop**; GG20 *identifiable* abort
  (attributing the operator and slashing it) is implemented in later milestones
  (`fault_demo` + `slash_operator_attested`), not in this in-process demo; shares
  are written to local files rather than an HSM/enclave. This demo is not wired
  into the on-chain loop (Milestones 3-4 use the in-process signer). Not audited
  for real value.
