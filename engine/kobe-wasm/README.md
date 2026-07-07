# kobe-wasm

Browser-side FROST Ed25519 for the user-mandatory custody model. The audited
`frost-ed25519` crate compiled to WebAssembly, so a user's key share can live
in the browser and the user is a *mandatory* signer: the operator network alone
is below threshold and cannot produce a signature.

```
# node proof
wasm-pack build --target nodejs --out-dir pkg && node test.mjs

# browser demo
wasm-pack build --target web --out-dir pkg-web && node serve.mjs
# open http://localhost:4600
```

`custody_selftest` runs the full 2-of-2 (user + network) and returns a JSON
report. The granular round1/round2 entry points are what the real
browser-to-daemon ceremony drives, with the two shares on two machines.

Phase 1 (this crate): FROST proven to run in the browser.
Next: split the two parties across browser and daemon, 2-party DKG at wallet
creation, a backup share for recovery, and per-user group-key registration
against the on-chain program.
