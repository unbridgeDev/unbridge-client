// The "network" party of the 2-of-2, as a standalone process. It holds ONLY the
// network key share; it never sees the user's share, which stays in the browser.
// This is the split that makes the demo real: the user calls this service to
// co-sign, and the /sign-alone endpoint proves the service cannot sign without
// the user, even holding all of its own material.
//
//   node network-signer.mjs        # listens on :4700
//
// State is in-memory and single-wallet for the demo. Uses the same wasm FROST
// build as the browser, so serialization matches by construction.
import { createServer } from "node:http";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const w = require("./pkg/kobe_wasm.js");

const PORT = process.env.PORT ? Number(process.env.PORT) : 4700;

// Per-wallet network material, and per-session round-1 nonces (single wallet).
let wallet = null; // { net_kp, pubkey_pkg, group_pk }
const sessions = new Map(); // sessionId -> { nonces, commit }

const send = (res, code, obj) => {
  res.writeHead(code, {
    "content-type": "application/json",
    "access-control-allow-origin": "*",
    "access-control-allow-headers": "content-type",
    "access-control-allow-methods": "POST, OPTIONS",
  });
  res.end(JSON.stringify(obj));
};

const body = (req) =>
  new Promise((resolve) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      try { resolve(JSON.parse(b || "{}")); } catch { resolve({}); }
    });
  });

createServer(async (req, res) => {
  if (req.method === "OPTIONS") return send(res, 204, {});
  const url = new URL(req.url, "http://x").pathname;
  try {
    if (url === "/register") {
      const { net_kp, pubkey_pkg, group_pk } = await body(req);
      if (!net_kp || !pubkey_pkg) return send(res, 400, { ok: false, error: "missing share" });
      wallet = { net_kp, pubkey_pkg, group_pk };
      sessions.clear();
      return send(res, 200, { ok: true, holding: "network share only" });
    }
    if (url === "/round1") {
      if (!wallet) return send(res, 400, { ok: false, error: "no wallet registered" });
      const { session } = await body(req);
      const r = JSON.parse(w.round1(wallet.net_kp));
      if (!r.ok) return send(res, 500, r);
      sessions.set(session, { nonces: r.nonces, commit: r.commitments });
      return send(res, 200, { ok: true, net_commit: r.commitments });
    }
    if (url === "/round2") {
      if (!wallet) return send(res, 400, { ok: false, error: "no wallet" });
      const { session, user_commit, message } = await body(req);
      const s = sessions.get(session);
      if (!s) return send(res, 400, { ok: false, error: "unknown session" });
      const r = JSON.parse(
        w.round2(wallet.net_kp, s.nonces, user_commit, s.commit, message)
      );
      if (!r.ok) return send(res, 500, r);
      return send(res, 200, { ok: true, net_share: r.share, net_commit: s.commit });
    }
    if (url === "/sign-alone") {
      // The attack: the service, with its full share and a fresh round1, tries
      // to finalize by itself. Must return signed:false.
      if (!wallet) return send(res, 400, { ok: false, error: "no wallet" });
      const { message } = await body(req);
      const r1 = JSON.parse(w.round1(wallet.net_kp));
      const r = JSON.parse(
        w.network_sign_alone(wallet.net_kp, r1.nonces, r1.commitments, message, wallet.pubkey_pkg)
      );
      return send(res, 200, { ok: true, signed: r.signed });
    }
    return send(res, 404, { ok: false, error: "not found" });
  } catch (e) {
    return send(res, 500, { ok: false, error: String(e) });
  }
}).listen(PORT, () => console.log(`network signer (holds network share only) on http://localhost:${PORT}`));
