// Distin localnet bootstrap + core-action verification.
//
// Brings the protocol to a state where the ONE user-facing action
// (create_signing_request) can succeed, then performs it and confirms the tx.
//
//   1. mint a Token-2022 LST + fund a test operator
//   2. initialize the protocol (admin)
//   3. register_operator (so operator_count > 0)
//   4. create_signing_request  <-- the core user action the frontend drives
//
// Run: node product/scripts/bootstrap.mjs
// Requires a running solana-test-validator on localhost:8899.

import {
  Connection, Keypair, PublicKey, SystemProgram, SYSVAR_RENT_PUBKEY,
  Transaction, TransactionInstruction, sendAndConfirmTransaction,
} from "@solana/web3.js";
import {
  TOKEN_2022_PROGRAM_ID, createMint, getOrCreateAssociatedTokenAccount, mintTo,
} from "@solana/spl-token";
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";

const RPC = "http://127.0.0.1:8899";
const PROGRAM_ID = new PublicKey("4xy9dYHfAzi7cAcX5JHxNR6EoMJ9PGfeQDMHx6YUQQM6");

// Anchor instruction discriminators (first 8 bytes of sha256("global:<ix_name>")).
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

async function airdrop(conn, pk, sol) {
  const sig = await conn.requestAirdrop(pk, sol * 1e9);
  await conn.confirmTransaction(sig, "confirmed");
}

async function main() {
  const conn = new Connection(RPC, "confirmed");

  const admin = Keypair.generate();      // protocol admin + operator authority + requester
  await airdrop(conn, admin.publicKey, 100);
  log("admin/operator/requester:", admin.publicKey.toBase58());

  // --- 1. Token-2022 LST mint + operator bond funding ---
  const mint = await createMint(conn, admin, admin.publicKey, null, 9, undefined, undefined, TOKEN_2022_PROGRAM_ID);
  log("bond mint (Token-2022):", mint.toBase58());
  const opAta = await getOrCreateAssociatedTokenAccount(conn, admin, mint, admin.publicKey, false, undefined, undefined, TOKEN_2022_PROGRAM_ID);
  await mintTo(conn, admin, mint, opAta.address, admin, 1_000_000_000_000n, [], undefined, TOKEN_2022_PROGRAM_ID);

  // --- PDAs ---
  const [protocol] = PublicKey.findProgramAddressSync([SEED.protocol], PROGRAM_ID);
  const [bondVault] = PublicKey.findProgramAddressSync([SEED.bond_vault, protocol.toBuffer()], PROGRAM_ID);
  const [slashPool] = PublicKey.findProgramAddressSync([SEED.slash_pool, protocol.toBuffer()], PROGRAM_ID);
  const [operator] = PublicKey.findProgramAddressSync([SEED.operator, protocol.toBuffer(), admin.publicKey.toBuffer()], PROGRAM_ID);

  // Oracle feed: any non-default account. compute_stake_weight only checks it is non-default.
  const oracle = Keypair.generate().publicKey;

  // --- 2. initialize (idempotent across re-runs: skip if already there) ---
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
  }

  // --- 3. register_operator ---
  const opInfo = await conn.getAccountInfo(operator);
  if (!opInfo) {
    const groupPubkey = Buffer.alloc(33, 1); // 33-byte compressed group key placeholder
    const data = Buffer.concat([DISC.register_operator, groupPubkey, u64(10_000_000)]);
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
    const sig = await sendAndConfirmTransaction(conn, new Transaction().add(ix), [admin]);
    log("register_operator tx:", sig);
  } else {
    log("operator already registered, skipping");
  }

  // --- 4. create_signing_request  (THE CORE USER ACTION) ---
  const protoAcct = await conn.getAccountInfo(protocol);
  // request_nonce lives at a fixed offset in the Protocol account; rederive the
  // request PDA the same way the frontend does — read the live nonce on chain.
  const nonce = readRequestNonce(protoAcct.data);
  const [request] = PublicKey.findProgramAddressSync([SEED.request, protocol.toBuffer(), u64(nonce)], PROGRAM_ID);

  const messageHash = createHash("sha256").update("send 0.5 BTC to bc1q... via Distin").digest(); // 32 bytes
  const data = Buffer.concat([
    DISC.create_signing_request,
    Buffer.from([1]),    // scheme: Gg20Secp256k1 (enum index 1) — BTC/EVM family
    Buffer.from([4]),    // target_vm: Bitcoin (enum index 4)
    u64(0),              // target_chain_id
    messageHash,         // 32-byte message hash
    u16(1),              // threshold (1 partial enough for this operator set)
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
  const sig = await sendAndConfirmTransaction(conn, new Transaction().add(ix), [admin]);
  log("\n>>> create_signing_request (CORE ACTION) tx:", sig);
  log(">>> request PDA:", request.toBase58(), "nonce:", nonce);

  // Persist the bootstrapped protocol context so the frontend points at the
  // same mint/protocol on this validator session.
  writeFileSync(new URL("./localnet.json", import.meta.url), JSON.stringify({
    programId: PROGRAM_ID.toBase58(),
    protocol: protocol.toBase58(),
    bondMint: mint.toBase58(),
    coreActionSig: sig,
  }, null, 2));
  log("\nwrote product/scripts/localnet.json");
}

// Protocol layout (after 8-byte discriminator):
// admin 32 + pending_admin 32 + bond_mint 32 + bond_vault 32 + slash_pool 32
// + lst_price_feed 32 + threshold_bps 2 + min_bond 8 + unbonding_slots 8
// + request_fee 8 + max_validity_slots 8 + operator_count 4 + total_bonded 8
// + request_nonce 8 ...
function readRequestNonce(buf) {
  const off = 8 + 32 * 6 + 2 + 8 * 4 + 4 + 8; // start of request_nonce
  return buf.readBigUInt64LE(off);
}

main().catch((e) => { console.error(e); process.exit(1); });
