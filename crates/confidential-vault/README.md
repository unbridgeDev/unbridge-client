# confidential-vault

Reference driver for Token-2022 confidential balances configured to be owned
by a FROST group key.

The point of this crate is one small but load-bearing detail: the account's
ElGamal view key is generated **independently** of the owner's signature. The
usual Solana convention (derive the view key from a signature the owner
produces on a fixed message) breaks under FROST, because a FROST signature is
freshly randomised per session and would produce a different view key every
time. This crate configures the account with a new random ElGamal key, then
that key is split across the team out of band. Result: a threshold group can
own a confidential account and any member can decrypt the balance without
being able to spend it.

The rest is scaffolding to prove the setup actually works against the
re-enabled Token-2022 confidential program on devnet:

1. Create a confidential-transfer mint.
2. Configure an ATA with an independent ElGamal view key, submitting the
   corresponding pubkey-validity proof.
3. Mint public tokens, then deposit them into the confidential balance.
4. Read the on-chain balance back as an ElGamal ciphertext.

## Why this exists as its own crate

The Solana confidential-transfer sample floating around the ecosystem pins
`solana-zk-sdk = 4.0.0`, which predates the Fiat-Shamir transcript fix that
shipped when the ZK ELGAMAL PROOF program was re-enabled on 2026-06-29
(Agave 4.1.0). Its proofs are rejected on current devnet. This crate pins
6.0.1 (with the correct transcript) and spl-token-2022 11.

## Run

```bash
export UNBRIDGE_RPC_URL=https://api.devnet.solana.com
export UNBRIDGE_KEYPAIR_PATH=~/.config/solana/id.json  # needs devnet SOL

cargo run -p confidential-vault
```

The keypair at `UNBRIDGE_KEYPAIR_PATH` funds every tx and owns the ATA. The
final output prints the mint address, the confidential ATA, and a link to
the Solana Explorer.

## Status

Milestone spike. Not a production driver. Comments mark the swap points
where the browser client wires this into the FROST-owned team vault.
