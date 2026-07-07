// The "network" party of the 2-of-2 custody model, as a standalone process. It
// holds ONLY network key shares; it never sees a user share, which stays in the
// browser. This is the split that makes the demo real: the user calls this
// service to co-sign, and the /sign-alone endpoint proves the service cannot
// sign without the user even holding its full share.
//
//   node network-signer.mjs        # listens on :4700 (PORT overridable)
//
// Multi-tenant for the public demo: each visitor generates a walletId and gets
// their own ephemeral network share. Shares are demo-only (no real funds, no
// on-chain keys) and live in memory with a bounded LRU so the process can host
// many visitors without growing without limit. Uses the same wasm FROST build
// as the browser, so serialization matches by construction.
import { createServer } from "node:http";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const w = require("./pkg/kobe_wasm.js");

const PORT = process.env.PORT ? Number(process.env.PORT) : 4700;
const MAX_WALLETS = 500; // bound memory; oldest evicted past this

const USER_ID = 1, NET_ID = 2;

// walletId -> { net_kp, pubkey_pkg, group_pk, sessions: Map, ts }
const wallets = new Map();
// walletId -> { r1s, r2s } transient DKG secrets while a wallet is generated
const dkgs = new Map();

const touch = (id, obj) => {
  wallets.delete(id);
  wallets.set(id, { ...obj, ts: Date.now() });
  while (wallets.size > MAX_WALLETS) wallets.delete(wallets.keys().next().value);
};

const send = (res, code, obj) => {
  res.writeHead(code, {
    "content-type": "application/json",
    "access-control-allow-origin": "*",
    "access-control-allow-headers": "content-type",
    "access-control-allow-methods": "POST, GET, OPTIONS",
  });
  res.end(JSON.stringify(obj));
};

const body = (req) =>
  new Promise((resolve) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => { try { resolve(JSON.parse(b || "{}")); } catch { resolve({}); } });
  });

createServer(async (req, res) => {
  if (req.method === "OPTIONS") return send(res, 204, {});
  const url = new URL(req.url, "http://x").pathname;
  try {
    if (url === "/health") return send(res, 200, { ok: true, wallets: wallets.size });

    // --- distributed key generation: the signer derives its OWN share; the
    //     user share is never sent here, not even at wallet creation ---
    if (url === "/dkg1") {
      const { walletId } = await body(req);
      if (!walletId) return send(res, 400, { ok: false, error: "missing walletId" });
      const r = JSON.parse(w.dkg_part1(NET_ID));
      if (!r.ok) return send(res, 500, r);
      dkgs.set(walletId, { r1s: r.secret });
      while (dkgs.size > MAX_WALLETS) dkgs.delete(dkgs.keys().next().value);
      return send(res, 200, { ok: true, net_r1: r.package });
    }
    if (url === "/dkg2") {
      const { walletId, user_r1 } = await body(req);
      const d = dkgs.get(walletId);
      if (!d) return send(res, 400, { ok: false, error: "no dkg in progress" });
      const r = JSON.parse(w.dkg_part2(d.r1s, USER_ID, user_r1));
      if (!r.ok) return send(res, 500, r);
      d.r2s = r.secret;
      return send(res, 200, { ok: true, net_r2: r.package });
    }
    if (url === "/dkg3") {
      const { walletId, user_r1, user_r2 } = await body(req);
      const d = dkgs.get(walletId);
      if (!d || !d.r2s) return send(res, 400, { ok: false, error: "dkg not at round 3" });
      const r = JSON.parse(w.dkg_part3(d.r2s, USER_ID, user_r1, user_r2));
      if (!r.ok) return send(res, 500, r);
      dkgs.delete(walletId);
      touch(walletId, { net_kp: r.key_package, pubkey_pkg: r.pubkey_pkg, group_pk: r.group_pk, sessions: new Map() });
      return send(res, 200, { ok: true, holding: "network share only", group_pk: r.group_pk });
    }

    if (url === "/round1") {
      const { walletId, session } = await body(req);
      const wl = wallets.get(walletId);
      if (!wl) return send(res, 400, { ok: false, error: "no wallet" });
      const r = JSON.parse(w.round1(wl.net_kp));
      if (!r.ok) return send(res, 500, r);
      wl.sessions.set(session, { nonces: r.nonces, commit: r.commitments });
      return send(res, 200, { ok: true, net_commit: r.commitments });
    }
    if (url === "/round2") {
      const { walletId, session, user_commit, message } = await body(req);
      const wl = wallets.get(walletId);
      if (!wl) return send(res, 400, { ok: false, error: "no wallet" });
      const s = wl.sessions.get(session);
      if (!s) return send(res, 400, { ok: false, error: "unknown session" });
      const r = JSON.parse(w.round2(wl.net_kp, s.nonces, user_commit, s.commit, message));
      if (!r.ok) return send(res, 500, r);
      wl.sessions.delete(session);
      return send(res, 200, { ok: true, net_share: r.share, net_commit: s.commit });
    }
    if (url === "/sign-alone") {
      // The attack: the service, with its full share and a fresh round1, tries
      // to finalize by itself. Must return signed:false.
      const { walletId, message } = await body(req);
      const wl = wallets.get(walletId);
      if (!wl) return send(res, 400, { ok: false, error: "no wallet" });
      const r1 = JSON.parse(w.round1(wl.net_kp));
      const r = JSON.parse(w.network_sign_alone(wl.net_kp, r1.nonces, r1.commitments, message, wl.pubkey_pkg));
      return send(res, 200, { ok: true, signed: r.signed });
    }
    return send(res, 404, { ok: false, error: "not found" });
  } catch (e) {
    return send(res, 500, { ok: false, error: String(e) });
  }
}).listen(PORT, () => console.log(`network signer (holds network shares only) on :${PORT}`));
