// Distin DEVNET bootstrap + core-action verification.
//
// Adapted from bootstrap.mjs (localnet). Differences:
//   * RPC  = https://api.devnet.solana.com
//   * payer/admin/operator/requester = engine/deploy.json (NO airdrops — devnet
//     SOL is rate-limited; the deploy wallet is already funded). Conserve SOL.
//
// Brings the protocol to a usable state and drives the ONE user action:
//   1. mint a Token-2022 LST + fund the operator's ATA
//   2. initialize the protocol (admin)
//   3. register_operator (so operator_count > 0)
//   4. create_signing_request  <-- the core user action the frontend drives
//
// Run from product/web (so @solana/* resolves):
//   node ../scripts/bootstrap.devnet.mjs

import {
  Connection, Keypair, PublicKey, SystemProgram, SYSVAR_RENT_PUBKEY,
  Transaction, TransactionInstruction, sendAndConfirmTransaction,
} from "@solana/web3.js";
import {
  TOKEN_2022_PROGRAM_ID, createMint, getOrCreateAssociatedTokenAccount, mintTo,
} from "@solana/spl-token";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const RPC = "https://api.devnet.solana.com";
const PROGRAM_ID = new PublicKey("4xy9dYHfAzi7cAcX5JHxNR6EoMJ9PGfeQDMHx6YUQQM6");
const PAYER_PATH = new URL("../../engine/deploy.json", import.meta.url);

const DISC = {
  initialize: Buffer.from([175, 175, 109, 31, 13, 152, 155, 237]),
  register_operator: Buffer.from([49, 242, 151, 125, 212, 136, 31, 89]),
  create_signing_request: Buffer.from([81, 124, 188, 129, 112, 241, 32, 39]),
};

const SEED = {
  protocol: Buffer.from("protocol"),
  bond_vault: Buffer.from("bond_vault"),
  slash_pool: Buffer.from("slash_pool"),
  operator: Buffer.from("operator"),
  request: Buffer.from("request"),
};

const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; };
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const log = (...a) => console.log(...a);

function loadKeypair(url) {
  return Keypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync(url, "utf8"))));
}

async function main() {
  const conn = new Connection(RPC, "confirmed");

  const admin = loadKeypair(PAYER_PATH); // admin + operator authority + requester
  log("payer/admin/operator/requester:", admin.publicKey.toBase58());
  const startLamports = await conn.getBalance(admin.publicKey);
  log("starting balance:", (startLamports / 1e9).toFixed(6), "SOL");

  // --- PDAs ---
  const [protocol] = PublicKey.findProgramAddressSync([SEED.protocol], PROGRAM_ID);
  const [bondVault] = PublicKey.findProgramAddressSync([SEED.bond_vault, protocol.toBuffer()], PROGRAM_ID);
  const [slashPool] = PublicKey.findProgramAddressSync([SEED.slash_pool, protocol.toBuffer()], PROGRAM_ID);
  const [operator] = PublicKey.findProgramAddressSync([SEED.operator, protocol.toBuffer(), admin.publicKey.toBuffer()], PROGRAM_ID);

  // --- 1. Token-2022 LST mint + operator bond funding ---
  // Reuse a previously-created mint if recorded, else mint a fresh one.
  let mint;
  let oracle;
  let prev;
  try { prev = JSON.parse(readFileSync(new URL("./devnet.json", import.meta.url), "utf8")); } catch {}
  if (prev?.bondMint && prev?.oracle) {
    mint = new PublicKey(prev.bondMint);
    oracle = new PublicKey(prev.oracle);
    log("reusing bond mint:", mint.toBase58());
  } else {
    mint = await createMint(conn, admin, admin.publicKey, null, 9, undefined, undefined, TOKEN_2022_PROGRAM_ID);
    oracle = Keypair.generate().publicKey; // any non-default account; compute_stake_weight only checks non-default
    log("bond mint (Token-2022):", mint.toBase58());
  }
  const opAta = await getOrCreateAssociatedTokenAccount(conn, admin, mint, admin.publicKey, false, undefined, undefined, TOKEN_2022_PROGRAM_ID);

  // --- 2. initialize (idempotent) ---
  const exists = await conn.getAccountInfo(protocol);
  if (!exists) {
    const data = Buffer.concat([
      DISC.initialize,
      u16(6667),                 // threshold_bps (66.67%)
      u64(1_000_000),            // min_bond
      u64(10),                   // unbonding_slots
      u64(0),                    // request_fee (0 lamports — keep the user action free)
      u64(216_000),              // max_validity_slots
      oracle.toBuffer(),         // lst_price_feed
    ]);
    const ix = new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: admin.publicKey, isSigner: true, isWritable: true },
        { pubkey: protocol, isSigner: false, isWritable: true },
        { pubkey: mint, isSigner: false, isWritable: false },
        { pubkey: bondVault, isSigner: false, isWritable: true },
        { pubkey: slashPool, isSigner: false, isWritable: true },
        { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        { pubkey: SYSVAR_RENT_PUBKEY, isSigner: false, isWritable: false },
      ],
      data,
    });
    const sig = await sendAndConfirmTransaction(conn, new Transaction().add(ix), [admin]);
    log("initialize tx:", sig);
  } else {
    log("protocol already initialized, skipping");
    // recover the oracle the program was initialized with (lst_price_feed offset)
    const lstOff = 8 + 32 * 5;
    oracle = new PublicKey(exists.data.subarray(lstOff, lstOff + 32));
  }

  // Ensure the operator ATA holds enough LST to bond (mint only what's needed).
  const bondAmount = 10_000_000n;
  await mintTo(conn, admin, mint, opAta.address, admin, bondAmount, [], undefined, TOKEN_2022_PROGRAM_ID);

  // --- 3. register_operator ---
  let registerSig = null;
  const opInfo = await conn.getAccountInfo(operator);
  if (!opInfo) {
    const groupPubkey = Buffer.alloc(33, 1); // 33-byte compressed group key placeholder
    const data = Buffer.concat([DISC.register_operator, groupPubkey, u64(Number(bondAmount))]);
    const ix = new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: admin.publicKey, isSigner: true, isWritable: true },
        { pubkey: protocol, isSigner: false, isWritable: true },
        { pubkey: operator, isSigner: false, isWritable: true },
        { pubkey: mint, isSigner: false, isWritable: false },
        { pubkey: opAta.address, isSigner: false, isWritable: true },
        { pubkey: bondVault, isSigner: false, isWritable: true },
        { pubkey: oracle, isSigner: false, isWritable: false },
        { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data,
    });
    registerSig = await sendAndConfirmTransaction(conn, new Transaction().add(ix), [admin]);
    log("register_operator tx:", registerSig);
  } else {
    log("operator already registered, skipping");
  }

  // --- 4. create_signing_request  (THE CORE USER ACTION) ---
  const protoAcct = await conn.getAccountInfo(protocol);
  const nonce = readRequestNonce(protoAcct.data);
  const [request] = PublicKey.findProgramAddressSync([SEED.request, protocol.toBuffer(), u64(nonce)], PROGRAM_ID);

  const messageHash = createHash("sha256").update("send 0.5 BTC to bc1q... via Distin").digest();
  const data = Buffer.concat([
    DISC.create_signing_request,
    Buffer.from([1]),    // scheme: Gg20Secp256k1 (enum index 1) — BTC/EVM family
    Buffer.from([4]),    // target_vm: Bitcoin (enum index 4)
    u64(0),              // target_chain_id
    messageHash,         // 32-byte message hash
    u16(1),              // threshold (1 partial is enough for this operator set)
    u64(1000),           // validity_slots
  ]);
  const ix = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: admin.publicKey, isSigner: true, isWritable: true },
      { pubkey: protocol, isSigner: false, isWritable: true },
      { pubkey: request, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
  const coreSig = await sendAndConfirmTransaction(conn, new Transaction().add(ix), [admin]);
  log("\n>>> create_signing_request (CORE ACTION) tx:", coreSig);
  log(">>> request PDA:", request.toBase58(), "nonce:", nonce.toString());

  const endLamports = await conn.getBalance(admin.publicKey);
  log("\nending balance:", (endLamports / 1e9).toFixed(6), "SOL");
  log("spent:", ((startLamports - endLamports) / 1e9).toFixed(6), "SOL");

  writeFileSync(new URL("./devnet.json", import.meta.url), JSON.stringify({
    cluster: "devnet",
    rpc: RPC,
    programId: PROGRAM_ID.toBase58(),
    protocol: protocol.toBase58(),
    bondMint: mint.toBase58(),
    oracle: oracle.toBase58(),
    operator: operator.toBase58(),
    registerOperatorSig: registerSig,
    coreActionSig: coreSig,
    requestPda: request.toBase58(),
  }, null, 2));
  log("wrote product/scripts/devnet.json");
}

function readRequestNonce(buf) {
  const off = 8 + 32 * 6 + 2 + 8 * 4 + 4 + 8;
  return buf.readBigUInt64LE(off);
}

main().catch((e) => { console.error(e); process.exit(1); });
