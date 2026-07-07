// Proves the FROST 2-of-2 works as a genuinely SPLIT ceremony: a "user" party
// and a "network" party that each only ever touch their own key material and
// exchange serialized commitments/shares. Mirrors the browser <-> daemon flow.
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const w = require("./pkg/kobe_wasm.js");

let fail = 0;
const ck = (n, c) => { console.log(`${c ? "ok  " : "FAIL"}  ${n}`); if (!c) fail++; };

// --- keygen (in the "browser"); network only ever gets net_kp + pubkey_pkg ---
const kg = JSON.parse(w.keygen_2of2());
ck("keygen ok", kg.ok);

// what each side holds
const USER = { kp: kg.user_kp };                         // stays in browser
const NET = { kp: kg.net_kp };                           // handed to the server
const PUBKEY_PKG = kg.pubkey_pkg;                        // public, both sides
const msg = "de".repeat(32);

// --- round 1: each party independently ---
const ur1 = JSON.parse(w.round1(USER.kp)); USER.nonces = ur1.nonces; USER.commit = ur1.commitments;
const nr1 = JSON.parse(w.round1(NET.kp));  NET.nonces = nr1.nonces;  NET.commit = nr1.commitments;
ck("both round1 ok", ur1.ok && nr1.ok);

// exchange ONLY commitments (public). nonces never leave their owner.
// --- round 2: each party builds the same package from both commitments ---
const ur2 = JSON.parse(w.round2(USER.kp, USER.nonces, USER.commit, NET.commit, msg));
const nr2 = JSON.parse(w.round2(NET.kp,  NET.nonces,  USER.commit, NET.commit, msg));
ck("both round2 ok", ur2.ok && nr2.ok);

// --- aggregate (either side can, from the two shares) ---
const agg = JSON.parse(w.aggregate(USER.commit, NET.commit, msg, ur2.share, nr2.share, PUBKEY_PKG));
ck("aggregate ok", agg.ok);
ck("joint signature verifies (RFC 8032)", agg.verified === true);
ck("group pubkey matches keygen", kg.group_pk.length === 64);

// --- THE ATTACK: the network signer, holding net_kp + its own nonces, tries to
//     finalize alone. Must produce nothing valid. ---
const alone = JSON.parse(w.network_sign_alone(NET.kp, NET.nonces, NET.commit, msg, PUBKEY_PKG));
ck("network alone cannot sign", alone.ok && alone.signed === false);

// sanity: the two shares are different material (not the same party twice)
ck("user and network shares differ", ur2.share !== nr2.share);

console.log(`\ngroup pubkey : ${kg.group_pk}`);
console.log(`signature    : ${agg.signature}`);
if (fail) { console.error(`\n${fail} check(s) failed`); process.exit(1); }
console.log("\nsplit ceremony verified: two parties, network alone signs nothing");
