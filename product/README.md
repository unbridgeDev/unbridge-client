# Distin — product

The app a user actually uses. One Solana account posts a cross-VM signing intent;
the bonded operator set fulfils it. The ONE core user action is
**`create_signing_request`** — wired to the real on-chain program, verified on a
local validator.

```
product/
  web/                Next.js frontend (the user-facing app)
    app/distin.ts     on-chain client: PDAs, instruction encoding, send+confirm
    app/page.tsx      the UI — drives create_signing_request as a real tx
  scripts/
    bootstrap.mjs     localnet bootstrap: mint LST, initialize, register operator
```

## Run it on localnet

The program needs an initialized protocol with at least one bonded operator
before a user can post an intent (`require!(operator_count > 0)`). Bootstrap is a
one-time admin/operator step; the frontend then performs the user action.

```bash
# 1. local chain (unlimited free airdrops, resets each run)
solana-test-validator --reset            # RPC: http://127.0.0.1:8899

# 2. deploy the program (engine/)
cd engine
solana program deploy \
  --program-id target/deploy/distin-keypair.json \
  --url localhost target/deploy/distin.so

# 3. bootstrap: Token-2022 LST mint + initialize + register_operator
cd ../product/scripts
ln -sfn ../../../../templates/nextjs/node_modules node_modules   # web3.js + spl-token
node bootstrap.mjs

# 4. run the frontend against localnet
cd ../web
cp .env.local.example .env.local
npm run build && npm start                # http://localhost:3000
```

Connect a wallet (Phantom on a localnet RPC), pick a chain, and press
**Request threshold signature**. That signs and sends a real
`create_signing_request` transaction; the on-chain request nonce advances and the
intent appears in the feed with its confirmed signature.

## Shipping to devnet/mainnet (operator's call)

The frontend is RPC/program-id configurable via `.env.local`
(`NEXT_PUBLIC_RPC_URL`, `NEXT_PUBLIC_PROGRAM_ID`, `NEXT_PUBLIC_CLUSTER`). Point it
at devnet, deploy the program there, run the bootstrap once, and the same UI works
unchanged. Localnet is the verification target; devnet/mainnet is the ship step.

## Verified on localnet

Program deployed and the core action confirmed end-to-end. Driving the actual
frontend module (`app/distin.ts`) against the deployed program created a real
`SigningRequest` account on chain (`scheme=GG20 secp256k1`, `target_vm=Bitcoin`),
confirmed with `solana confirm <sig> --url localhost`.
