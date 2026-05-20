// On-chain client for the Distin threshold-signature coordinator.
//
// The ONE core user action is `create_signing_request`: a single Solana account
// posts a cross-VM signing intent that the bonded operator set then fulfils.
// This module builds that instruction with raw @solana/web3.js (no anchor client
// in the browser) and derives PDAs with the exact seeds the on-chain program uses.

import {
  Connection,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";

// --- Deployment config (env-overridable for devnet/mainnet shipping) ---
export const RPC_URL =
  process.env.NEXT_PUBLIC_RPC_URL ?? "http://127.0.0.1:8899";
export const PROGRAM_ID = new PublicKey(
  process.env.NEXT_PUBLIC_PROGRAM_ID ??
    "4xy9dYHfAzi7cAcX5JHxNR6EoMJ9PGfeQDMHx6YUQQM6"
);
export const CLUSTER_LABEL = process.env.NEXT_PUBLIC_CLUSTER ?? "localnet";

// Anchor discriminator: first 8 bytes of sha256("global:create_signing_request").
const CREATE_REQUEST_DISC = new Uint8Array([81, 124, 188, 129, 112, 241, 32, 39]);

const PROTOCOL_SEED = new TextEncoder().encode("protocol");
const REQUEST_SEED = new TextEncoder().encode("request");

// SignatureScheme enum (program order).
export enum Scheme {
  FrostEd25519 = 0,
  Gg20Secp256k1 = 1,
}
// TargetVm enum (program order).
export enum TargetVm {
  Svm = 0,
  Evm = 1,
  Tron = 2,
  Cosmos = 3,
  Bitcoin = 4,
}

export const protocolPda = () =>
  PublicKey.findProgramAddressSync([PROTOCOL_SEED], PROGRAM_ID)[0];

// request_nonce offset inside the Protocol account data (after the 8-byte disc):
// admin 32 + pending_admin 32 + bond_mint 32 + bond_vault 32 + slash_pool 32
// + lst_price_feed 32 + threshold_bps 2 + min_bond 8 + unbonding_slots 8
// + request_fee 8 + max_validity_slots 8 + operator_count 4 + total_bonded 8.
const NONCE_OFFSET = 8 + 32 * 6 + 2 + 8 * 4 + 4 + 8;

export type ProtocolState = {
  initialized: boolean;
  operatorCount: number;
  requestNonce: bigint;
  totalBonded: bigint;
};

// SigningRequest account layout (after the 8-byte disc): protocol 32 +
// requester 32 + request_id 8 + scheme 1 + target_vm 1 + target_chain_id 8 +
// message_hash 32 + threshold 2 + partials_collected 2 + stake_collected 8 +
// required_stake 8 + created_slot 8 + expiry_slot 8 → status 1 → signature 64.
// NOTE: protocol comes FIRST — the requester lives at bytes 40..72.
const REQ_STATUS_OFFSET = 8 + 32 + 32 + 8 + 1 + 1 + 8 + 32 + 2 + 2 + 8 + 8 + 8 + 8;
const REQ_SIG_OFFSET = REQ_STATUS_OFFSET + 1;

export type RequestResult = {
  exists: boolean;
  signed: boolean;
  // 128-hex threshold signature the operator set recorded on-chain (once signed).
  signatureHex: string | null;
};

const hex = (b: Uint8Array) =>
  Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");

// Read the result the bonded operators wrote back: a request is "signed" once a
// non-zero threshold signature is recorded (ed25519 for FROST, r||s for GG20).
export async function readRequest(conn: Connection, request: PublicKey): Promise<RequestResult> {
  const info = await conn.getAccountInfo(request);
  if (!info) return { exists: false, signed: false, signatureHex: null };
  const sig = info.data.subarray(REQ_SIG_OFFSET, REQ_SIG_OFFSET + 64);
  const signed = sig.some((x) => x !== 0);
  return { exists: true, signed, signatureHex: signed ? hex(sig) : null };
}

export type DashStats = {
  totalRequests: number;
  settled: number;
  operators: number;
  bondedWeight: number;
  frost: number; // FROST (Ed25519) requests
  gg20: number; // GG20 (secp256k1) requests
  // Requests bucketed by target_vm: [Svm, Evm, Tron, Cosmos, Bitcoin].
  byVm: [number, number, number, number, number];
};

// Real, on-chain dashboard numbers. Scans every SigningRequest account (matched
// by the Anchor account discriminator) and buckets by scheme + settled status.
// No historical time-series — there is no indexer, so we never fabricate one.
export async function readDashboard(conn: Connection, proto: ProtocolState): Promise<DashStats> {
  const disc = (await sha256("account:SigningRequest")).slice(0, 8);
  const accts = await conn.getProgramAccounts(PROGRAM_ID);
  let settled = 0, frost = 0, gg20 = 0;
  const byVm: [number, number, number, number, number] = [0, 0, 0, 0, 0];
  for (const { account } of accts) {
    const d = account.data;
    if (d.length < REQ_SIG_OFFSET + 64) continue;
    let isReq = true;
    for (let i = 0; i < 8; i++) if (d[i] !== disc[i]) { isReq = false; break; }
    if (!isReq) continue;
    const scheme = d[8 + 32 + 32 + 8]; // 0=FROST, 1=GG20
    const vm = d[8 + 32 + 32 + 8 + 1]; // 0=Svm 1=Evm 2=Tron 3=Cosmos 4=Bitcoin
    if (scheme === 0) frost++; else if (scheme === 1) gg20++;
    if (vm >= 0 && vm <= 4) byVm[vm]++;
    if (d.subarray(REQ_SIG_OFFSET, REQ_SIG_OFFSET + 64).some((x) => x !== 0)) settled++;
  }
  return {
    totalRequests: Number(proto.requestNonce),
    settled,
    operators: proto.operatorCount,
    bondedWeight: Number(proto.totalBonded) / 1e9,
    frost,
    gg20,
    byVm,
  };
}

export type ActivityItem = {
  request: string; // request PDA
  requestId: number;
  vm: number; // 0=Svm 1=Evm 2=Tron 3=Cosmos 4=Bitcoin
  scheme: number; // 0=FROST 1=GG20
  signed: boolean;
  // Unsigned past its expiry slot — the operator set will no longer pick it up.
  expired: boolean;
  signatureHex: string | null;
};

// The connected wallet's own signing requests, read straight from chain (matched
// by the SigningRequest discriminator + requester == wallet). Newest first.
export async function readMyActivity(conn: Connection, wallet: PublicKey): Promise<ActivityItem[]> {
  const disc = (await sha256("account:SigningRequest")).slice(0, 8);
  const w = wallet.toBytes();
  const [accts, slot] = await Promise.all([conn.getProgramAccounts(PROGRAM_ID), conn.getSlot()]);
  const items: ActivityItem[] = [];
  for (const { pubkey, account } of accts) {
    const d = account.data;
    if (d.length < REQ_SIG_OFFSET + 64) continue;
    let ok = true;
    for (let i = 0; i < 8; i++) if (d[i] !== disc[i]) { ok = false; break; }
    if (!ok) continue;
    let mine = true;
    for (let i = 0; i < 32; i++) if (d[40 + i] !== w[i]) { mine = false; break; }
    if (!mine) continue;
    const dv = new DataView(d.buffer, d.byteOffset, d.byteLength);
    const requestId = Number(dv.getBigUint64(8 + 32 + 32, true));
    const scheme = d[8 + 32 + 32 + 8];
    const vm = d[8 + 32 + 32 + 8 + 1];
    // expiry_slot sits right before the status byte.
    const expirySlot = dv.getBigUint64(REQ_STATUS_OFFSET - 8, true);
    const sig = d.subarray(REQ_SIG_OFFSET, REQ_SIG_OFFSET + 64);
    const signed = sig.some((x) => x !== 0);
    const expired = !signed && BigInt(slot) > expirySlot;
    items.push({ request: pubkey.toBase58(), requestId, vm, scheme, signed, expired, signatureHex: signed ? hex(sig) : null });
  }
  items.sort((a, b) => b.requestId - a.requestId);
  return items;
}

export async function readProtocol(conn: Connection): Promise<ProtocolState> {
  const info = await conn.getAccountInfo(protocolPda());
  if (!info) {
    return { initialized: false, operatorCount: 0, requestNonce: 0n, totalBonded: 0n };
  }
  const dv = new DataView(info.data.buffer, info.data.byteOffset, info.data.byteLength);
  const opCountOff = 8 + 32 * 6 + 2 + 8 * 4;
  return {
    initialized: true,
    operatorCount: dv.getUint32(opCountOff, true),
    totalBonded: dv.getBigUint64(opCountOff + 4, true),
    requestNonce: dv.getBigUint64(NONCE_OFFSET, true),
  };
}

async function sha256(input: string): Promise<Uint8Array> {
  const data = new TextEncoder().encode(input);
  const buf = new ArrayBuffer(data.byteLength);
  new Uint8Array(buf).set(data);
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return new Uint8Array(digest);
}

export type IntentArgs = {
  scheme: Scheme;
  targetVm: TargetVm;
  targetChainId: bigint;
  // human-readable intent ("0.5 BTC -> bc1q...") hashed to the 32-byte message.
  intent: string;
  threshold: number;
  validitySlots: bigint;
  // When set, this exact 32-byte digest is signed instead of sha256(intent) —
  // used to sign the real sighash of an on-target-chain transaction.
  messageHash?: Uint8Array;
};

// Build the create_signing_request instruction for the connected wallet.
export async function buildCreateRequestIx(
  conn: Connection,
  requester: PublicKey,
  args: IntentArgs
): Promise<{ ix: TransactionInstruction; request: PublicKey }> {
  const protocol = protocolPda();

  // A client-chosen random nonce fully determines the request PDA (seeded by
  // requester + this nonce), so the address never depends on a global counter.
  // That removes the race that made wallet pre-flight simulation fail.
  const cnLE = crypto.getRandomValues(new Uint8Array(8));
  const request = PublicKey.findProgramAddressSync(
    [REQUEST_SEED, requester.toBuffer(), cnLE],
    PROGRAM_ID
  )[0];

  const messageHash = args.messageHash ?? (await sha256(args.intent));

  // Borsh-style little-endian arg encoding, matching the program signature
  // (client_nonce is the FIRST arg, right after the discriminator).
  const buf = new Uint8Array(8 + 8 + 1 + 1 + 8 + 32 + 2 + 8);
  let o = 0;
  buf.set(CREATE_REQUEST_DISC, o); o += 8;
  buf.set(cnLE, o); o += 8;
  buf[o++] = args.scheme;
  buf[o++] = args.targetVm;
  new DataView(buf.buffer).setBigUint64(o, args.targetChainId, true); o += 8;
  buf.set(messageHash, o); o += 32;
  new DataView(buf.buffer).setUint16(o, args.threshold, true); o += 2;
  new DataView(buf.buffer).setBigUint64(o, args.validitySlots, true); o += 8;

  const ix = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: requester, isSigner: true, isWritable: true },
      { pubkey: protocol, isSigner: false, isWritable: true },
      { pubkey: request, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.from(buf),
  });

  return { ix, request };
}

// Sign + send via the injected wallet, then confirm. Returns the tx signature.
export async function sendCreateRequest(
  conn: Connection,
  wallet: { publicKey: PublicKey; signTransaction: (t: Transaction) => Promise<Transaction> },
  args: IntentArgs
): Promise<{ signature: string; request: PublicKey }> {
  const { ix, request } = await buildCreateRequestIx(conn, wallet.publicKey, args);
  const tx = new Transaction().add(ix);
  tx.feePayer = wallet.publicKey;
  const { blockhash, lastValidBlockHeight } = await conn.getLatestBlockhash();
  tx.recentBlockhash = blockhash;

  const signed = await wallet.signTransaction(tx);
  const signature = await conn.sendRawTransaction(signed.serialize());
  await conn.confirmTransaction({ signature, blockhash, lastValidBlockHeight }, "confirmed");
  return { signature, request };
}
