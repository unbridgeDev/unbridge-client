# coordinator — Distin's off-chain MPC coordinator (Milestones 3, 4, 7)

Proves the **full end-to-end loop** on localnet: an on-chain signing request
drives the off-chain FROST MPC to produce a REAL Ed25519 signature, and the
on-chain state records the completed signing.

This is a standalone host crate (own `[workspace]`), so its `solana-client` /
`solana-sdk` dependency tree never perturbs the SBF program build. It depends on
[`kobe`](../kobe) (the audited-crate FROST signer) by path for the cryptography.

## What it does

```
0. kobe::KeySet::generate(3, 2)        trusted-dealer FROST keygen, 2-of-3
1. initialize + register_operator x3   bootstrap; each operator carries the group key
2. create_signing_request              the on-chain INTENT (FrostEd25519 / SVM)
3. read the request back off-chain  ->  kobe runs FROST round 1/2 + aggregate
   submit_partial_signature x2          participation receipts (stake accounting)
   aggregate_and_emit(aggregate_sig)    records the REAL signature on-chain
4. re-read the finalized request  ->   independent ed25519 verify of the recorded sig
```

## Run it

Requires the (reconciled) program deployed to a local validator:

```sh
export PATH="$HOME/.cargo/bin:$HOME/.local/share/solana/install/active_release/bin:/opt/homebrew/bin:$PATH"
export COPYFILE_DISABLE=1                       # macOS genesis-tar workaround

# 1. validator with the rebuilt program
solana-test-validator --reset --ledger /tmp/distin-ledger \
  --bpf-program 4xy9dYHfAzi7cAcX5JHxNR6EoMJ9PGfeQDMHx6YUQQM6 \
  ../target/deploy/distin.so &

# 2. the loop
cargo run --release
```

The demo asserts, in-process, that the on-chain-recorded signature equals the
real FROST aggregate and verifies under `ed25519-dalek` against the group key and
the request's `message_hash`. For a verification with **zero shared code** with
the demo, pull the bytes from chain and verify with OpenSSL:

```sh
solana account <request-PDA> --url localhost --output json   # read aggregate_sig + message_hash
# DER-wrap the 32-byte group key, then:
openssl pkeyutl -verify -pubin -inkey gpk.der -keyform DER -rawin -in msg.bin -sigfile sig.bin
# => Signature Verified Successfully
```

## Real vs simulated

- **Real:** FROST cryptography (ZF `frost-ed25519`, audited), the Ed25519
  signature, the on-chain program + all PDAs/threshold gates, the on-chain
  recording of the signature, and the independent verification.
- **Simulated:** the N operators run in one process (no real network), one
  funded keypair plays admin/operators/requester, and the LST oracle is a
  non-default placeholder (1:1 SOL peg, per `compute_stake_weight`).

## Milestone 7 — the on-chain request drives the REAL NETWORKED operators

`bin/net-demo` (`src/net_demo.rs`) is the integration capstone. Where the M3/M4
demos ran the operators in one process, here the coordinator stands up the M6
**networked operator set** ([`../kobe-ecdsa/net`](../kobe-ecdsa/net) +
`cmd/operator`): three SEPARATE OS processes (distinct PIDs, ports, identity
keys, share files) that run the GG20 DKG and a 2-of-3 threshold sign over
authenticated TCP. The **on-chain `SigningRequest` is the trigger** — the
coordinator reads `message_hash` off-chain and dispatches it to the operator
processes; the signature they produce over the wire is recorded on-chain and
independently ecrecover-verified to the group's Ethereum address.

```
0. launch 3 operator PROCESSES -> networked GG20 DKG over TCP; all agree group addr
1. initialize + register_operator x3   bootstrap (group's ETH addr = economic identity)
2. create_signing_request              the on-chain INTENT (Gg20Secp256k1 / Evm)
3. read message_hash off-chain  ->  dispatch to the operator PROCESSES (quorum {0,2})
   submit_partial_signature x2          participation receipts
   aggregate_and_emit(r||s)             records the NETWORKED signature on-chain
4. re-read finalized request  ->  k256 ecrecover the on-chain bytes to the group addr
   negative control: drop an operator -> sign aborts, request stays Pending, no garbage
```

One command stands up a fresh validator, builds everything, and prints the
evidence (then tears the validator down):

```sh
cd engine/coordinator && ./m7-demo.sh
```

For verification with **zero shared code** with the demo: read the request PDA
with `solana account <pda> --output json`, decode `aggregate_sig` + `message_hash`
at their fixed offsets, then ecrecover with the standalone go-ethereum verifier
(a third path, independent of both the demo and k256):

```sh
go run ../kobe-ecdsa/cmd/verify-sig -hash <message_hash> -sig65 <r||s||v> -expect 0x<group-addr>
# v is not stored on-chain; try v=00 and v=01 — exactly one MATCHes the group addr.
```

**Real vs simplified (M7):** the operators are genuinely separate networked
processes and signing is triggered by the on-chain request (not a local call);
the GG20 signature, the program/PDAs/threshold gates, the on-chain record, and
all three independent ecrecover paths are real. Still simplified on the M7 networked path: the static pinned-key directory (TLS/PKI exists but is off on this path), fail-stop abort in this demo (GG20 identifiable-abort-to-slash is built and tested, just not wired into this single run), shares in local files (encryption-at-rest exists but is off here, no HSM), one Solana keypair on the on-chain side, the LST oracle placeholder. The FROST/ed25519 path can follow
the identical wiring (a `net/` operator for the FROST signer) — only GG20/ETH is
proven networked end to end here.

Remaining to production: the reconciled bytecode is now live on devnet, but re-deploy should move to CI (needs operator SOL); a security audit (needs a firm); wiring identifiable-abort end-to-end across the networked-to-chain boundary, plus TLS and HSM hardening on the M7 path.
