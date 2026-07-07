// Locks the browser-FROST custody property. Run after `wasm-pack build
// --target nodejs --out-dir pkg`:  node test.mjs
//
// Asserts that the audited frost-ed25519, compiled to wasm, produces a real
// 2-of-2 signature where the operator party alone cannot sign. If this passes,
// the user's key share can live in the browser and the user is a mandatory
// signer with a share that never leaves their device.
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const w = require("./pkg/kobe_wasm.js");

let failures = 0;
const check = (name, cond) => {
  console.log(`${cond ? "ok  " : "FAIL"}  ${name}`);
  if (!cond) failures++;
};

const msg = "a1".repeat(32);
const r = JSON.parse(w.custody_selftest(msg));

check("wasm FROST 2-of-2 runs", r.ok === true);
check("operator network alone cannot sign", r.operator_only_blocked === true);
check("user + network signature verifies (RFC 8032)", r.verified === true);
check("group public key is 32 bytes", (r.group_pubkey ?? "").length === 64);
check("signature is 64 bytes", (r.signature ?? "").length === 128);

// A malformed message must be reported, not panic the wasm module.
const bad = JSON.parse(w.custody_selftest("nothex"));
check("bad input fails closed", bad.ok === false);

if (failures) {
  console.error(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log("\nall custody checks passed");
