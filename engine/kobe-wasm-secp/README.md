# kobe-wasm-secp

Browser-side threshold Schnorr over secp256k1, for Bitcoin Taproot custody.
Uses the official ZF `frost-secp256k1-tr` (FROST + Taproot / BIP340).

Go/no-go spike result (verified): the audited crate compiles to wasm, a 2-of-2
produces a 32-byte x-only key + 64-byte signature, and that signature verifies
under an INDEPENDENT standard BIP340 verifier (`@noble/curves` schnorr) — i.e. a
signature Bitcoin's own Taproot rules accept. This clears the load-bearing risk
for browser BTC custody, mirroring how kobe-wasm cleared it for Ed25519 / Solana.

```
wasm-pack build --target nodejs --out-dir pkg
node -e "console.log(require('./pkg/kobe_wasm_secp.js').secp_selftest('a1'.repeat(32)))"
```

Remaining to actually send BTC (bounded plumbing, not crypto risk): P2TR address
derivation from the x-only group key, BIP341 sighash, transaction + witness
assembly, testnet broadcast. Then the same split ceremony as kobe-wasm.

Not covered: native Ethereum. ETH is ECDSA-only; FROST is Schnorr, so native ETH
transaction signing needs threshold ECDSA (no clean wasm path). `frost-secp256k1-evm`
exists but targets contract-side verification, not native tx signing.
