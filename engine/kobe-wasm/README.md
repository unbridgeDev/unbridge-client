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

`custody_selftest` runs the full 2-of-2 (user + network) in one call, for the
standalone browser proof (`demo.html`).

## Split ceremony (browser + signer process)

The real model: the user share stays in the browser, a separate process holds
the network share, and neither ever sees the other's. To sign, the two
co-operate over HTTP; the signer, given its full share, cannot finalize alone.

```
# node proof of the split (two parties, network-alone blocked)
wasm-pack build --target nodejs --out-dir pkg && node split-test.mjs

# live browser demo
wasm-pack build --target web --out-dir pkg-web
node network-signer.mjs          # holds the network share, :4700
node serve.mjs                   # static server, :4600
# open http://localhost:4600/split-demo.html
```

The granular entry points (`keygen_2of2`, `round1`, `round2`, `aggregate`,
`network_sign_alone`) are what the browser and the signer drive. In production
the signer's share is itself produced by the on-chain t-of-n operator set.

## Distributed key generation (no trusted dealer)

`dkg_part1/2/3` run the FROST DKG across the two parties, so neither side ever
sees the other's share, not even at wallet creation. `node dkg-test.mjs` proves
it (both parties derive the same group key independently, then co-sign). The
split demo's "Create wallet" uses this: each process generates its own share.

## Live demo

The split demo is live at **unbridge.dev/custody**: your share is generated and
held in the browser, the network share lives in a hosted signer process, and the
"make the server sign alone" button fails. The signer is a small standalone
service (`network-signer.mjs`, multi-tenant, demo-only shares, no funds or
on-chain keys) deployed with `Dockerfile.signer` + `fly.signer.toml`:

```
# deploy the demo signer (from a dir holding network-signer.mjs + pkg/)
wasm-pack build --target nodejs --out-dir pkg
flyctl deploy --app unbridge-custody-demo --dockerfile Dockerfile.signer
```

Phase 1 (done): FROST proven to run in the browser.
Phase 2 (done): genuine browser + signer-process split, network-alone blocked.
Phase 3 (done): 2-party DKG (no dealer), and per-user group-key registration
on-chain via the program's `register_custody_key`.
Live (done): the split demo hosted at unbridge.dev/custody.
Next: a backup share (2-of-3) for recovery, and wiring the on-chain binding into
the browser flow.
