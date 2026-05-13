# Running a Distin operator (independent onboarding)

Distin's economic security comes from a **distributed** operator set: each
operator holds its own key share, bonds its own LST, runs its own process, and
is slashable for misbehavior. The signature is a threshold — no single party
(including the team) can produce it alone.

This document is the path for an **independent third party** to join that set.
Today the reference set (`engine/coordinator/keys/`) runs on one host for the
devnet demo; this guide is what makes the set genuinely distributed.

## What you provide

1. **A Solana authority keypair** — signs your `register_operator` /
   `submit_partial_signature` transactions and owns your on-chain `Operator` PDA.
2. **Bonded LST collateral** — Token-2022 LST transferred into the protocol
   `bond_vault`. This is your slashable stake; its live value is read from the
   Pyth feed the protocol is configured with (`compute_stake_weight`).
3. **An operator host** — a machine with a public address that runs the signing
   process and stays online during signing ceremonies.

## GG20 (secp256k1 — Bitcoin / Ethereum / Tron / Cosmos)

The GG20 path is already a real networked protocol (`engine/kobe-ecdsa/net`):
mutual-TLS between operators, a public-key-pinned peer directory, and encrypted
share transport. An independent operator:

1. **Generates identity** — a fresh Ed25519 identity key + leaf certificate
   (`cmd/gen-operators` produces the config; in production each operator runs
   this locally and only publishes its *public* identity + address).
2. **Exchanges the peer directory** — every operator's `{index, addr, pubkey}`
   is shared so each can pin and authenticate its peers (no trust anchor beyond
   the pinned keys).
3. **Runs distributed keygen** — `operator -phase keygen`; each process writes
   **only its own** share (`op<i>.share.json`), and all agree on one group ECDSA
   pubkey / ETH address. The group secret is never assembled in one place.
4. **Registers on-chain** — bonds LST and calls `register_operator` with the
   group pubkey (33-byte compressed).
5. **Serves signatures** — `operator -phase sign -hash <onchain_message_hash>`
   when a `SigningRequest` appears; the coordinator submits the partials and
   `aggregate_and_emit`. The recorded `r||s` ecrecovers to the group address.

## FROST (Ed25519 — Aptos / SVM / Cosmos)

The FROST path is a real networked protocol too, on par with GG20. The audited
crypto (`engine/kobe`, ZF `frost-ed25519`) is driven over the same hardened
mTLS/PKI transport by `cmd/frost-operator` + `net/frost.go`, and
`net/frost_demo.sh` runs it end-to-end: three **separate OS processes** perform
distributed keygen (each writing only its own AES-256-GCM/argon2id-encrypted
share), then a 2-of-3 threshold sign with one operator offline whose aggregate
verifies under `crypto/ed25519` (RFC 8032 — what Solana checks). Its negatives
pass too: an offline peer aborts cleanly, a rogue-CA operator is rejected at the
handshake, and a misbehaving operator triggers an **identifiable abort** that
names the culprit and emits a signed fault attestation.

An independent FROST operator therefore runs exactly like a GG20 one:
`frost-operator -phase keygen` (own encrypted share) then `-phase sign` per
request. The live bridge is wired: `signerd bootstrap-frostnet` registers the
networked group on-chain, and when the frostnet set exists on disk the daemon
dispatches every scheme-0 request to the three separate operator processes over
mTLS (the coordinator independently re-verifies each aggregate under
ed25519-dalek against the on-chain-registered group key before submitting).
The reference deployment signs devnet requests this way today.

## Bond, weight, and slashing (on-chain, live)

- `register_operator(group_pubkey, bond_amount)` pulls your LST into the vault
  and credits stake weight. Weight is gated on a **live Pyth price** — a bond
  only counts while its LST is priced on-chain (`compute_stake_weight`, feed set
  via `set_lst_price_feed`, currently Pyth SOL/USD `7UVimffx…` on devnet).
- A request finalizes only when the **distinct-operator count** and **staked
  weight** both clear the threshold (`threshold_bps`) inside the slot deadline.
- `slash_operator` / `slash_operator_attested` burn a misbehaving operator's
  bond. Attested slashing verifies a signed fault report against the operator's
  registered identity, so honest operators can prove misbehavior on-chain.

## What is genuinely distributed vs. still centralized

- **Distributed today:** GG20 key shares, transport (mTLS/PKI), on-chain bond +
  slashing accounting, threshold enforcement. A third party can run a GG20
  operator on their own host with their own share and bond.
- **Still centralized (honest gaps):**
  - The devnet reference set runs on one host (this repo). Real distribution
    needs independent operators actually running the above on their own boxes.
  - FROST signing is in-process pending the networked-FROST cutover described.
  - Production operators should ultimately hold shares in an HSM; the daemon
    supports encryption-at-rest today (see below) as the interim baseline.

## Keys at rest (encryption)

`signerd` encrypts its FROST keyset and operator keypairs at rest when
`DISTIN_KEY_PASSPHRASE` is set — Argon2id derives the file key, ChaCha20-Poly1305
seals each file (`DSTNK1` header). It is **opt-in and backward-compatible**: a
plaintext key file still loads, so enabling it never bricks a running daemon.
The reference deployment runs this way: its keys are sealed and the daemon
signs devnet requests from them (verified end-to-end).

To seal an existing (plaintext) key directory:

```
export DISTIN_KEY_PASSPHRASE='…'      # a strong secret; store it in the
                                      # host's secret manager, not in the repo
signerd seal-keys                     # re-writes keyset.bin + op*.json sealed
```

Then keep `DISTIN_KEY_PASSPHRASE` in the daemon's environment (a launchd
`EnvironmentVariables` entry, a Docker/K8s secret, or a cloud KMS-injected env)
so `run` can decrypt on start. The passphrase is the only thing the host secret
manager must hold; the shares themselves are never on disk in the clear.
GG20 shares under `keys/gg20/` are written by the Go operator and are not yet
covered by this — that is the remaining gap before a full at-rest guarantee.

Real decentralization is reached when independent operators complete the GG20
onboarding above on their own infrastructure. This document is the on-ramp; the
participants are the missing piece, by design.
