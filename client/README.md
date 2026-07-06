# Unbridge client scripts

Node.js CLI tools that produce the witnesses, run the FROST signing
ceremony, and submit shielded transactions to the on-chain program at
`6ESjwd4u6qW8SP9PtNwNus1hBJTxKViWra91C36RRALu`.

Everything in this directory runs in Node, not the browser. The browser
client at [unbridge.dev](https://unbridge.dev) is a repackaging of these
same primitives; the pinned browser bundle will be published here after
the trusted-setup ceremony's next-key rotation.

## Layout

```
scripts/
|-- gen_input.mjs         # build the JSON input for a circuit from user args
|-- gen_verifying_key.mjs # extract Rust byte arrays from a snarkjs .zkey
|-- deposit_witness.mjs   # witness generation for pool_deposit.circom
|-- withdraw_witness.mjs  # witness generation for pool_tx.circom, withdraw side
|-- witness_pool.mjs      # witness generation for pool_tx.circom, internal
|-- frost_sign.mjs        # FROST signing over Baby Jubjub, spike-quality
|-- threshold_sign.mjs    # threshold-signing driver used by frost_sign
|-- to_solana.mjs         # pack a Groth16 proof into the on-chain instruction shape
|-- init_client.cjs       # one-time pool + global-config initialisation (admin only)
|-- deposit_send.cjs      # submit a deposit tx
|-- withdraw_send.cjs     # submit a withdraw tx
|-- push_assoc_root.cjs   # ASP authority publishes a new association-set root
|-- read_root.cjs         # read the current Merkle root from chain
|-- build.sh              # compile circuits, run trusted setup, emit verifying keys
|-- ceremony.sh           # run the current-epoch phase-2 contribution
`-- seed-pool.sh          # devnet-only: seed the pool with mock deposits
```

## Requirements

- Node.js 18+
- `snarkjs` and `circomlibjs` installed at repo root or globally
- `@noble/curves` for off-chain signature checks
- `@solana/web3.js` for tx submission
- A Solana wallet keypair reachable via `UNBRIDGE_KEYPAIR_PATH`

Environment variables live in [`../.env.example`](../.env.example).

## Typical flow

```bash
# One-time setup for the current epoch (admin only)
./scripts/build.sh
./scripts/ceremony.sh
./scripts/init_client.cjs

# A regular deposit
node scripts/gen_input.mjs deposit 1.0 > input/deposit.json
node scripts/deposit_witness.mjs input/deposit.json
node scripts/to_solana.mjs deposit_proof.json > tx/deposit.tx
node scripts/deposit_send.cjs tx/deposit.tx

# A team-authorised withdrawal (t-of-n via FROST)
node scripts/frost_sign.mjs --members m1,m2 --message "$spend_msg"
node scripts/gen_input.mjs withdraw 0.5 --signature $sig > input/withdraw.json
node scripts/withdraw_witness.mjs input/withdraw.json
node scripts/to_solana.mjs withdraw_proof.json > tx/withdraw.tx
node scripts/withdraw_send.cjs tx/withdraw.tx
```

`init_client.cjs`, `push_assoc_root.cjs`, and the `_send` scripts hit the
mainnet program by default; override via `UNBRIDGE_NETWORK=devnet` for
devnet. `seed-pool.sh` is devnet-only and refuses to run against mainnet.

## Status

Spike quality. The browser client at unbridge.dev is the supported user
surface; these scripts are what integrators reference when building against
the program directly. Comments in individual files call out the spots
where the browser client diverges (batching, session storage, WebCrypto
key wrapping).
