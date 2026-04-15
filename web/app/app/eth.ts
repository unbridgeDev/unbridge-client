// Ethereum assembly for the Distin product flow.
//
// The Solana program records only the 32-byte message and the 64-byte r||s the
// operators produced — it carries no transaction fields. So the browser owns the
// Ethereum transaction: it builds a real EIP-1559 transaction, posts THAT
// transaction's sighash as the request message, and once the operators sign it,
// assembles the broadcastable signed transaction from r||s here. The recovery id
// v is not stored on-chain, so we try both and keep the one whose sender is the
// group address — the exact check an Ethereum node makes.

import {
  serializeTransaction,
  keccak256,
  recoverAddress,
  type TransactionSerializableEIP1559,
  type Hex,
} from "viem";

export const SEPOLIA_CHAIN_ID = 11155111;

// The GG20 group's Ethereum address (the account the operators jointly control).
export const ETH_GROUP_ADDRESS = (process.env.NEXT_PUBLIC_ETH_GROUP_ADDRESS ??
  "0x4bC73Eb097B673F0004B65B7a3747c6a02a97bb4") as `0x${string}`;

const SEPOLIA_RPC =
  process.env.NEXT_PUBLIC_SEPOLIA_RPC ?? "https://ethereum-sepolia-rpc.publicnode.com";

export type EthTx = TransactionSerializableEIP1559;

async function rpc(method: string, params: unknown[]): Promise<any> {
  const res = await fetch(SEPOLIA_RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const j = await res.json();
  if (j.error) throw new Error(`${method}: ${j.error.message}`);
  return j.result;
}

// Build a real EIP-1559 Sepolia transfer from the group account, reading the
// account's live nonce so the assembled tx is actually broadcastable.
export async function buildEthTransfer(to: string, valueEth: number): Promise<EthTx> {
  const nonceHex = await rpc("eth_getTransactionCount", [ETH_GROUP_ADDRESS, "pending"]);
  return {
    chainId: SEPOLIA_CHAIN_ID,
    type: "eip1559",
    nonce: Number(BigInt(nonceHex)),
    to: to as `0x${string}`,
    value: BigInt(Math.round(valueEth * 1e18)),
    maxPriorityFeePerGas: 1_500_000_000n,
    maxFeePerGas: 30_000_000_000n,
    gas: 21000n,
  };
}

// The 32-byte digest the operators must sign for this transaction — identical to
// what go-ethereum computes (verified byte-for-byte against cmd/eth-tx).
export function ethSighash(tx: EthTx): Hex {
  return keccak256(serializeTransaction(tx));
}

// Assemble the signed, broadcastable transaction from the on-chain r||s. Picks
// the recovery id whose recovered signer is the group address; throws if neither
// matches (the operators did not sign this exact transaction).
export async function assembleSignedTx(
  tx: EthTx,
  rs64: Uint8Array
): Promise<{ raw: Hex; hash: Hex }> {
  const r = ("0x" + toHex(rs64.slice(0, 32))) as Hex;
  const s = ("0x" + toHex(rs64.slice(32, 64))) as Hex;
  const sighash = ethSighash(tx);
  for (const yParity of [0, 1] as const) {
    const recovered = await recoverAddress({ hash: sighash, signature: { r, s, yParity } });
    if (recovered.toLowerCase() === ETH_GROUP_ADDRESS.toLowerCase()) {
      const raw = serializeTransaction(tx, { r, s, yParity });
      return { raw, hash: keccak256(raw) };
    }
  }
  throw new Error("neither recovery id recovers to the group address");
}

// Broadcast a raw signed transaction to Sepolia. Fails if the group address is
// unfunded — fund it from a Sepolia faucet first.
export async function broadcastEth(raw: Hex): Promise<string> {
  return rpc("eth_sendRawTransaction", [raw]);
}

function toHex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}
