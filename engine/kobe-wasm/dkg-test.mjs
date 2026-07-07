// Proves a genuine 2-party DKG: no trusted dealer, neither side ever holds the
// other's key package or secret material. The two parties exchange only public
// round1/round2 packages, then each derives its own key package independently,
// and the resulting 2-of-2 signs (with network-alone still blocked).
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const w = require("./pkg/kobe_wasm.js");

let fail = 0;
const ck = (n, c) => { console.log(`${c ? "ok  " : "FAIL"}  ${n}`); if (!c) fail++; };

const USER = 1, NET = 2;
const U = {}, N = {}; // each object holds ONLY its own party's material

// --- DKG round 1: each party generates independently ---
const u1 = JSON.parse(w.dkg_part1(USER)); U.r1s = u1.secret; U.r1p = u1.package;
const n1 = JSON.parse(w.dkg_part1(NET));  N.r1s = n1.secret; N.r1p = n1.package;
ck("dkg part1 both ok", u1.ok && n1.ok);
// exchange ONLY the public round1 packages (u1.package <-> n1.package)

// --- DKG round 2: each consumes its own r1 secret + the other's r1 package ---
const u2 = JSON.parse(w.dkg_part2(U.r1s, NET, N.r1p)); U.r2s = u2.secret; U.r2p = u2.package;
const n2 = JSON.parse(w.dkg_part2(N.r1s, USER, U.r1p)); N.r2s = n2.secret; N.r2p = n2.package;
ck("dkg part2 both ok", u2.ok && n2.ok);
// exchange ONLY the round2 packages addressed to the peer (u2.package -> N, n2.package -> U)

// --- DKG round 3: each derives its OWN key package + the shared group key ---
const u3 = JSON.parse(w.dkg_part3(U.r2s, NET, N.r1p, N.r2p)); U.kp = u3.key_package;
const n3 = JSON.parse(w.dkg_part3(N.r2s, USER, U.r1p, U.r2p)); N.kp = n3.key_package;
ck("dkg part3 both ok", u3.ok && n3.ok);
ck("both parties agree on the group key", u3.group_pk === n3.group_pk);
ck("group key is 32 bytes", (u3.group_pk ?? "").length === 64);
ck("the two key packages differ (not the same share)", U.kp !== N.kp);
const PUBKEY_PKG = u3.pubkey_pkg;

// --- now sign with the DKG-produced shares (same split ceremony as phase 2) ---
const msg = "be".repeat(32);
const ur1 = JSON.parse(w.round1(U.kp)); const nr1 = JSON.parse(w.round1(N.kp));
const ur2 = JSON.parse(w.round2(U.kp, ur1.nonces, ur1.commitments, nr1.commitments, msg));
const nr2 = JSON.parse(w.round2(N.kp, nr1.nonces, ur1.commitments, nr1.commitments, msg));
const agg = JSON.parse(w.aggregate(ur1.commitments, nr1.commitments, msg, ur2.share, nr2.share, PUBKEY_PKG));
ck("DKG shares co-sign and verify", agg.ok && agg.verified === true);

// --- attack: network alone, with its DKG share, still cannot sign ---
const alone = JSON.parse(w.network_sign_alone(N.kp, nr1.nonces, nr1.commitments, msg, PUBKEY_PKG));
ck("network alone cannot sign (post-DKG)", alone.signed === false);

console.log(`\ngroup pubkey : ${u3.group_pk}`);
console.log(`signature    : ${agg.signature}`);
if (fail) { console.error(`\n${fail} check(s) failed`); process.exit(1); }
console.log("\nDKG verified: no trusted dealer, neither side saw the other's share");
