"use client";

import { useState, useRef, useMemo, useCallback, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Connection, PublicKey, Transaction } from "@solana/web3.js";
import { Wallet, ShieldCheck, Loader2, Check, Radio, Zap, ArrowDown, ArrowDownRight, AlertTriangle, FileText, Code, ChevronDown } from "lucide-react";
import {
  RPC_URL, PROGRAM_ID,
  Scheme, TargetVm, readProtocol, readRequest, readDashboard, readMyActivity, sendCreateRequest,
  type ProtocolState, type DashStats, type ActivityItem,
} from "./distin";
import { BarChart3 } from "lucide-react";
import { hexToBytes } from "viem";
import { buildEthTransfer, ethSighash, assembleSignedTx, broadcastEth } from "./eth";

// Chains map to the program's SignatureScheme / TargetVm enums.
const CHAINS = [
  { key: "bitcoin", name: "Bitcoin", curve: "secp256k1", scheme: "GG20 ECDSA", dot: "#f7931a", logo: "/chains/bitcoin.png", sample: "bc1qak9zl3xm7v2p0qd8sehua4rk0n6n9d3p2yq7lk", sig: Scheme.Gg20Secp256k1, vm: TargetVm.Bitcoin, chainId: 0n },
  { key: "ethereum", name: "Ethereum", curve: "secp256k1", scheme: "GG20 ECDSA", dot: "#8aa0e8", logo: "/chains/ethereum.png", sample: "0x9f3aE12bC0d44eF77a1c0b88E2d5F3a91C7d4e02", sig: Scheme.Gg20Secp256k1, vm: TargetVm.Evm, chainId: 1n },
  { key: "tron", name: "Tron", curve: "secp256k1", scheme: "GG20 ECDSA", dot: "#e0746e", logo: "/chains/tron.png", sample: "TQ5n8Wp3kJ2vQ7rL9mXa4Yb6Zc1Df0Eg2H", sig: Scheme.Gg20Secp256k1, vm: TargetVm.Tron, chainId: 0n },
  { key: "cosmos", name: "Cosmos", curve: "secp256k1", scheme: "GG20 ECDSA", dot: "#aab0cc", logo: "/chains/cosmos.png", sample: "cosmos1p8a3v9k2m7q0xs4r6n1d5e8y2t7w3l9c0z4b", sig: Scheme.Gg20Secp256k1, vm: TargetVm.Cosmos, chainId: 0n },
  { key: "aptos", name: "Aptos", curve: "ed25519", scheme: "FROST", dot: "#5fd8c4", logo: "/chains/aptos.png", sample: "0x4a7c2e91d0f3b6a8c5e2147d9f0b3a6c8e1d4f7a0b2c5e8d1f4a7c0e3b6d9f2a", sig: Scheme.FrostEd25519, vm: TargetVm.Svm, chainId: 0n },
];

// Chain logo as a round <img>, replacing the old colored dot.
const chainImg = (src: string, size = 20) => (
  <img src={src} alt="" width={size} height={size} style={{ width: size, height: size, borderRadius: 999, flex: "0 0 auto", objectFit: "cover" }} />
);

const mid = (s: string, l = 8, r = 6) => (s.length <= l + r + 1 ? s : `${s.slice(0, l)}…${s.slice(-r)}`);

type Row =
  | { kind: "intent"; id: string; chain: string; logo: string; dest: string; amt: string; sig: string; request: string; threshSig: string | null; ethRaw?: string | null; ethHash?: string; ethSent?: string; ethErr?: string }
  | { kind: "error"; id: string; msg: string };

const PALETTE: React.CSSProperties = {
  ["--bg" as any]: "#0a0d10",
  ["--bg2" as any]: "#111519",
  ["--bg3" as any]: "#181d23",
  ["--border" as any]: "#242b33",
  ["--text" as any]: "#eef3f6",
  ["--text2" as any]: "#93a1ac",
  ["--accent" as any]: "#23dcc8",
  ["--accent-soft" as any]: "rgba(35,220,200,0.13)",
  ["--accent-border" as any]: "rgba(35,220,200,0.42)",
  ["--warn" as any]: "#f0a35e",
  ["--warn-soft" as any]: "rgba(240,163,94,0.12)",
};

// Minimal shape of the injected wallet provider (Phantom / Solflare etc.).
type Provider = {
  isConnected?: boolean;
  publicKey?: { toString(): string; toBuffer(): Buffer } & PublicKey;
  connect: () => Promise<{ publicKey: { toString(): string } }>;
  disconnect: () => Promise<void>;
  signTransaction: (t: Transaction) => Promise<Transaction>;
};
const getProvider = (): Provider | undefined =>
  typeof window !== "undefined" ? (window as any)?.solana : undefined;

export default function Page() {
  const [selected, setSelected] = useState(0);
  const [destination, setDestination] = useState("");
  const [amount, setAmount] = useState("");
  const [running, setRunning] = useState(false);
  const [feed, setFeed] = useState<Row[]>([]);
  const [intents, setIntents] = useState(0);
  const [wallet, setWallet] = useState<string | null>(null);
  const [proto, setProto] = useState<ProtocolState | null>(null);
  const [view, setView] = useState<"sign" | "dashboard" | "activity">("sign");
  const [dash, setDash] = useState<DashStats | null>(null);
  const [activity, setActivity] = useState<ActivityItem[] | null>(null);
  const [chainMenu, setChainMenu] = useState(false);
  const idRef = useRef(0);

  const conn = useMemo(() => new Connection(RPC_URL, "confirmed"), []);
  const chain = CHAINS[selected];
  const nextId = () => `r${idRef.current++}`;
  const pushRow = useCallback((row: Row) => {
    setFeed((f) => [row, ...f].slice(0, 60));
  }, []);

  // Read live protocol state from chain (operator count + request nonce).
  useEffect(() => {
    let live = true;
    const load = async () => {
      try {
        const s = await readProtocol(conn);
        if (live) setProto(s);
      } catch { /* RPC unreachable — surfaced in the status line */ }
    };
    load();
    const t = setInterval(load, 6000);
    return () => { live = false; clearInterval(t); };
  }, [conn]);

  // Load real dashboard numbers whenever the dashboard is open.
  useEffect(() => {
    if (view !== "dashboard" || !proto) return;
    let live = true;
    readDashboard(conn, proto).then((d) => { if (live) setDash(d); }).catch(() => {});
    return () => { live = false; };
  }, [view, proto, conn]);

  // Load the connected wallet's own on-chain signing history for Activity, and
  // keep it fresh while the tab is open (a request signs seconds after posting).
  useEffect(() => {
    if (view !== "activity" || !wallet) return;
    let live = true;
    setActivity(null);
    const load = () =>
      readMyActivity(conn, new PublicKey(wallet)).then((a) => { if (live) setActivity(a); }).catch(() => { if (live) setActivity((p) => p ?? []); });
    load();
    const t = setInterval(load, 6000);
    return () => { live = false; clearInterval(t); };
  }, [view, wallet, conn]);

  useEffect(() => {
    const sol = getProvider();
    if (sol?.isConnected && sol.publicKey) setWallet(sol.publicKey.toString());
  }, []);

  const connect = useCallback(async () => {
    const sol = getProvider();
    if (!sol) { window.open("https://phantom.app/", "_blank"); return; }
    if (wallet) {
      try { await sol.disconnect(); } catch {}
      setWallet(null);
      return;
    }
    try {
      const res = await sol.connect();
      setWallet(res?.publicKey?.toString() ?? sol.publicKey?.toString() ?? null);
    } catch {}
  }, [wallet]);

  const ready = proto?.initialized && (proto?.operatorCount ?? 0) > 0;


  // THE CORE USER ACTION: post a real cross-VM signing intent on-chain.
  const run = useCallback(async () => {
    if (running) return;
    const sol = getProvider();
    if (!sol || !wallet) { await connect(); return; }
    if (!ready) {
      pushRow({ kind: "error", id: nextId(), msg: "No active operators are bonded right now. Try again shortly." });
      return;
    }
    setRunning(true);
    const c = CHAINS[selected];
    const dest = destination.trim() || c.sample;
    const amt = (amount.trim() || "0.50").replace(/[^0-9.]/g, "") || "0.50";
    try {
      // For Ethereum, sign the REAL sighash of an EIP-1559 transaction so the
      // result assembles into a broadcastable tx (not a demo string hash).
      const isEth = c.key === "ethereum";
      const ethTx = isEth ? await buildEthTransfer(dest, Number(amt)) : null;
      const messageHash = ethTx ? hexToBytes(ethSighash(ethTx)) : undefined;

      const { signature, request } = await sendCreateRequest(
        conn,
        { publicKey: new PublicKey(wallet), signTransaction: (t) => sol.signTransaction(t) },
        {
          scheme: c.sig,
          targetVm: c.vm,
          targetChainId: c.chainId,
          intent: `${amt} ${c.name} -> ${dest}`,
          threshold: 1,
          validitySlots: 1000n,
          messageHash,
        }
      );
      const rowId = nextId();
      pushRow({ kind: "intent", id: rowId, chain: c.name, logo: c.logo, dest, amt, sig: signature, request: request.toString(), threshSig: null, ethRaw: isEth ? null : undefined });
      setIntents((v) => v + 1);
      setProto(await readProtocol(conn));
      // Poll for the operator set's threshold signature, then reveal it — and for
      // Ethereum, assemble the broadcastable signed transaction from r||s.
      void (async () => {
        for (let i = 0; i < 40; i++) {
          await new Promise((r) => setTimeout(r, 3000));
          try {
            const res = await readRequest(conn, request);
            if (res.signed && res.signatureHex) {
              const patch: Partial<Extract<Row, { kind: "intent" }>> = { threshSig: res.signatureHex };
              if (ethTx) {
                try {
                  const { raw, hash } = await assembleSignedTx(ethTx, hexToBytes(("0x" + res.signatureHex) as `0x${string}`));
                  patch.ethRaw = raw;
                  patch.ethHash = hash;
                } catch (e: any) {
                  patch.ethErr = e?.message ?? "assembly failed";
                }
              }
              setFeed((f) => f.map((row) => (row.id === rowId && row.kind === "intent" ? { ...row, ...patch } : row)));
              return;
            }
          } catch { /* transient RPC — keep polling */ }
        }
      })();
    } catch (e: any) {
      pushRow({ kind: "error", id: nextId(), msg: e?.message ?? "Transaction failed." });
    } finally {
      setRunning(false);
    }
  }, [running, wallet, ready, selected, destination, amount, conn, connect, pushRow]);

  // Broadcast an assembled Ethereum tx to Sepolia (needs the group address funded).
  const broadcast = useCallback(async (rowId: string, raw: string) => {
    try {
      const hash = await broadcastEth(raw as `0x${string}`);
      setFeed((f) => f.map((row) => (row.id === rowId && row.kind === "intent" ? { ...row, ethSent: hash } : row)));
    } catch (e: any) {
      setFeed((f) => f.map((row) => (row.id === rowId && row.kind === "intent" ? { ...row, ethErr: e?.message ?? "broadcast failed" } : row)));
    }
  }, []);

  const wrap: React.CSSProperties = { minWidth: 0, overflowWrap: "anywhere", wordBreak: "break-word" };
  const mono = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace";

  const rowShell: React.CSSProperties = {
    border: "1px solid var(--border)", background: "var(--bg3)", borderRadius: 12,
    padding: "12px 14px", display: "flex", flexDirection: "column", gap: 6, minWidth: 0,
  };
  const rowHead: React.CSSProperties = {
    display: "flex", alignItems: "center", gap: 8, fontSize: 18, fontWeight: 700, color: "var(--text)", minWidth: 0,
  };
  const rowMeta: React.CSSProperties = { fontSize: 18, color: "var(--text2)", fontFamily: mono, ...wrap };

  // THORChain-style stacked boxes with a circular divider.
  const sendBox: React.CSSProperties = { background: "var(--bg3)", border: "1px solid var(--border)", borderRadius: 14, padding: "12px 15px", boxSizing: "border-box" };
  const boxHead: React.CSSProperties = { display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: 15, color: "var(--text2)", marginBottom: 9 };
  const bareInput: React.CSSProperties = { width: "100%", boxSizing: "border-box", background: "transparent", border: "none", color: "var(--text)", fontFamily: mono, padding: 0, outline: "none" };

  const navItem = (icon: React.ReactNode, label: string, active?: boolean, onClick?: () => void, href?: string) => {
    const style: React.CSSProperties = {
      display: "flex", alignItems: "center", gap: 11, padding: "11px 12px", borderRadius: 11,
      fontSize: 17, fontWeight: 600, cursor: "pointer", textDecoration: "none",
      color: active ? "var(--text)" : "var(--text2)",
      background: active ? "var(--accent-soft)" : "transparent",
      border: `1px solid ${active ? "var(--accent-border)" : "transparent"}`,
    };
    return href
      ? <a key={label} href={href} target="_blank" rel="noreferrer" style={style}>{icon}<span>{label}</span></a>
      : <button key={label} onClick={onClick} style={{ ...style, width: "100%", textAlign: "left", fontFamily: "inherit" }}>{icon}<span>{label}</span></button>;
  };

  return (
    <main style={{ height: "100vh", width: "100%", background: "var(--bg)", color: "var(--text)", overflow: "hidden", display: "flex", position: "relative", isolation: "isolate", fontFamily: "var(--font-geist-sans), ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif", ...PALETTE }}>
      {/* Ambient background: the brand video, running strong behind the panels. */}
      <div aria-hidden style={{ position: "fixed", inset: 0, zIndex: 0, overflow: "hidden", pointerEvents: "none" }}>
        <video autoPlay muted loop playsInline style={{ width: "100%", height: "100%", objectFit: "cover", opacity: 0.5 }}>
          <source src="/bg_video.mp4" type="video/mp4" />
        </video>
        <div style={{ position: "absolute", inset: 0, background: "radial-gradient(130% 100% at 72% 28%, rgba(10,13,16,0.12) 0%, rgba(10,13,16,0.5) 62%, rgba(10,13,16,0.82) 100%)" }} />
      </div>
      <aside className="sidebar" style={{ width: 236, flex: "0 0 236px", boxSizing: "border-box", borderRight: "1px solid var(--border)", background: "rgba(17,21,25,0.55)", backdropFilter: "blur(14px)", WebkitBackdropFilter: "blur(14px)", padding: "20px 14px", display: "flex", flexDirection: "column", gap: 4, position: "sticky", top: 0, height: "100vh", zIndex: 2 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "6px 8px 20px" }}>
          <span style={{ fontSize: 22, fontWeight: 800, letterSpacing: "-0.02em" }}>unbridge</span>
        </div>
        <div style={{ fontSize: 13, fontWeight: 700, letterSpacing: "0.08em", color: "var(--text2)", padding: "8px 12px 6px" }}>MENU</div>
        {navItem(<Zap size={19} />, "Sign", view === "sign", () => setView("sign"))}
        {navItem(<BarChart3 size={19} />, "Dashboard", view === "dashboard", () => setView("dashboard"))}
        {navItem(<Radio size={19} />, "Activity", view === "activity", () => setView("activity"))}

        <div style={{ fontSize: 13, fontWeight: 700, letterSpacing: "0.08em", color: "var(--text2)", padding: "18px 12px 6px" }}>RESOURCES</div>
        {navItem(<FileText size={19} />, "Docs", false, undefined, "https://distin.xyz/docs")}
        {navItem(<Code size={19} />, "GitHub", false, undefined, "https://github.com/unbridgeDev/unbridge")}

        {/* Live protocol status — fills the rail, pinned near the bottom */}
        <div style={{ marginTop: "auto" }}>
          <div style={{ background: "var(--bg3)", border: "1px solid var(--border)", borderRadius: 12, padding: "13px 13px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
              <span className="live-dot" style={{ width: 8, height: 8, borderRadius: 999, background: ready ? "var(--accent)" : "var(--warn)", boxShadow: ready ? "0 0 8px var(--accent)" : "none", flex: "0 0 auto" }} />
              <span style={{ fontSize: 15, fontWeight: 700 }}>{ready ? "Live on Solana" : "Connecting…"}</span>
            </div>
            {([
              ["Operators", proto ? String(proto.operatorCount) : "—"],
              ["Requests", proto ? String(Number(proto.requestNonce)) : "—"],
            ] as [string, string][]).map(([k, v]) => (
              <div key={k} style={{ display: "flex", justifyContent: "space-between", fontSize: 15, padding: "3px 0" }}>
                <span style={{ color: "var(--text2)" }}>{k}</span>
                <span style={{ fontWeight: 700, fontFamily: mono }}>{v}</span>
              </div>
            ))}
          </div>
          <div style={{ fontSize: 14, color: "var(--text2)", padding: "12px 8px 2px", lineHeight: 1.5 }}>
            Threshold signing,<br />coordinated on Solana.
          </div>
        </div>
      </aside>

      <div style={{ flex: 1, minWidth: 0, height: "100vh", overflowY: "auto", position: "relative", zIndex: 1 }}>
      <header
        style={{
          display: "flex", alignItems: "center", justifyContent: "flex-end",
          padding: "18px 22px", borderBottom: "1px solid var(--border)", gap: 12, boxSizing: "border-box",
          position: "sticky", top: 0, background: "rgba(10,13,16,0.5)", backdropFilter: "blur(14px)", WebkitBackdropFilter: "blur(14px)", zIndex: 5,
        }}
      >
        <button
          id="connect"
          onClick={connect}
          style={{
            display: "flex", alignItems: "center", gap: 9,
            background: wallet ? "var(--accent-soft)" : "var(--bg3)",
            border: `1px solid ${wallet ? "var(--accent-border)" : "var(--border)"}`,
            color: "var(--text)", fontSize: 18, fontWeight: 600, fontFamily: mono,
            padding: "11px 16px", borderRadius: 999, cursor: "pointer", flex: "0 0 auto", transition: "all 0.18s ease",
          }}
        >
          <Wallet size={18} />
          {wallet ? mid(wallet, 4, 4) : "Connect Wallet"}
        </button>
      </header>

      {view === "dashboard" && (
        <section style={{ maxWidth: 1040, margin: "0 auto", padding: "34px 22px 80px", boxSizing: "border-box" }}>
          <div style={{ fontSize: 30, fontWeight: 800, marginBottom: 22, letterSpacing: "-0.02em" }}>Network stats</div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 14, marginBottom: 14 }}>
            {([
              ["Requests to date", dash ? dash.totalRequests.toLocaleString() : "—"],
              ["Signatures settled", dash ? dash.settled.toLocaleString() : "—"],
              ["Active operators", proto ? String(proto.operatorCount) : "—"],
              ["Bonded weight", proto ? (Number(proto.totalBonded) / 1e9).toFixed(2) : "—"],
            ] as [string, string][]).map(([label, value]) => (
              <div key={label} style={{ background: "var(--bg2)", border: "1px solid var(--border)", borderRadius: 16, padding: "20px 20px" }}>
                <div style={{ fontSize: 17, color: "var(--text2)", marginBottom: 8 }}>{label}</div>
                <div style={{ fontSize: 34, fontWeight: 800, fontFamily: mono }}>{value}</div>
              </div>
            ))}
          </div>

          {(() => {
            const f = dash?.frost ?? 0, g = dash?.gg20 ?? 0, total = f + g;
            const C = 2 * Math.PI * 46;
            const fFrac = total ? f / total : 0;
            const chains: [string, number, string][] = [
              ["Bitcoin", dash?.byVm?.[4] ?? 0, "#f7931a"],
              ["Ethereum", dash?.byVm?.[1] ?? 0, "#8aa0e8"],
              ["Tron", dash?.byVm?.[2] ?? 0, "#e0746e"],
              ["Cosmos", dash?.byVm?.[3] ?? 0, "#aab0cc"],
              ["Aptos", dash?.byVm?.[0] ?? 0, "#5fd8c4"],
            ];
            const maxVm = Math.max(1, ...chains.map((c) => c[1]));
            const settlePct = dash && dash.totalRequests ? Math.round((dash.settled / dash.totalRequests) * 100) : 0;
            const card: React.CSSProperties = { background: "var(--bg2)", border: "1px solid var(--border)", borderRadius: 16, padding: "22px 22px", minWidth: 0 };
            const cardTitle: React.CSSProperties = { fontSize: 20, fontWeight: 700, marginBottom: 3 };
            const cardSub: React.CSSProperties = { fontSize: 15, color: "var(--text2)", marginBottom: 18 };
            return (
              <>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: 14, marginBottom: 14 }}>
                  {/* Scheme split donut */}
                  <div style={card}>
                    <div style={cardTitle}>Signature scheme</div>
                    <div style={cardSub}>Live on-chain split, nothing fabricated.</div>
                    <div style={{ display: "flex", alignItems: "center", gap: 26 }}>
                      <svg width={128} height={128} viewBox="0 0 120 120" style={{ transform: "rotate(-90deg)", flex: "0 0 auto" }}>
                        <circle cx="60" cy="60" r="46" fill="none" stroke="var(--bg3)" strokeWidth="15" />
                        <circle cx="60" cy="60" r="46" fill="none" stroke="#3aa0ff" strokeWidth="15" strokeDasharray={`${C} ${C}`} strokeDashoffset={0} strokeLinecap="butt" />
                        <circle cx="60" cy="60" r="46" fill="none" stroke="#23dcc8" strokeWidth="15" strokeDasharray={`${fFrac * C} ${C}`} strokeDashoffset={0} strokeLinecap="butt" style={{ transition: "stroke-dasharray 0.5s ease" }} />
                        <text x="60" y="60" textAnchor="middle" dominantBaseline="central" transform="rotate(90 60 60)" fill="var(--text)" fontSize="26" fontWeight="800" fontFamily={mono}>{total}</text>
                      </svg>
                      <div style={{ display: "flex", flexDirection: "column", gap: 16, minWidth: 0 }}>
                        {([["FROST · Ed25519", f, "#23dcc8"], ["GG20 · secp256k1", g, "#3aa0ff"]] as [string, number, string][]).map(([n, c, col]) => (
                          <div key={n} style={{ display: "flex", alignItems: "center", gap: 10 }}>
                            <span style={{ width: 12, height: 12, borderRadius: 4, background: col, flex: "0 0 auto" }} />
                            <div style={{ minWidth: 0 }}>
                              <div style={{ fontSize: 17, fontWeight: 700 }}>{n}</div>
                              <div style={{ fontSize: 15, color: "var(--text2)", fontFamily: mono }}>{c} · {total ? Math.round((c / total) * 100) : 0}%</div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Requests by chain */}
                  <div style={card}>
                    <div style={cardTitle}>Requests by chain</div>
                    <div style={cardSub}>Native signatures produced per target chain.</div>
                    <div style={{ display: "flex", flexDirection: "column", gap: 13 }}>
                      {chains.map(([name, count, col]) => (
                        <div key={name} style={{ display: "flex", alignItems: "center", gap: 12 }}>
                          <span style={{ width: 66, fontSize: 16, color: "var(--text2)", flex: "0 0 auto" }}>{name}</span>
                          <div style={{ flex: 1, height: 14, borderRadius: 999, background: "var(--bg3)", overflow: "hidden", minWidth: 0 }}>
                            <div style={{ height: "100%", width: `${(count / maxVm) * 100}%`, background: col, borderRadius: 999, transition: "width 0.5s ease" }} />
                          </div>
                          <span style={{ width: 28, textAlign: "right", fontSize: 17, fontWeight: 700, fontFamily: mono, flex: "0 0 auto" }}>{count}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Settlement rate */}
                <div style={card}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 10 }}>
                    <span style={cardTitle}>Settlement rate</span>
                    <span style={{ fontSize: 26, fontWeight: 800, fontFamily: mono, color: "var(--accent)" }}>{settlePct}%</span>
                  </div>
                  <div style={{ height: 14, borderRadius: 999, background: "var(--bg3)", overflow: "hidden", marginBottom: 10 }}>
                    <div style={{ height: "100%", width: `${settlePct}%`, background: "linear-gradient(90deg, #23dcc8, #3aa0ff)", borderRadius: 999, transition: "width 0.5s ease" }} />
                  </div>
                  <div style={{ fontSize: 15, color: "var(--text2)" }}>{dash?.settled ?? 0} of {dash?.totalRequests ?? 0} requests threshold-signed by the operator set.</div>
                </div>

                <div style={{ marginTop: 22, fontSize: 16, color: "var(--text2)", fontFamily: mono, ...wrap }}>
                  Solana · coordinator {mid(PROGRAM_ID.toBase58(), 6, 6)} · no historical index (live reads only)
                </div>
              </>
            );
          })()}
        </section>
      )}

      {view === "activity" && (
        <section style={{ maxWidth: 900, margin: "0 auto", padding: "24px 22px 40px", boxSizing: "border-box" }}>
          <div style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 26, fontWeight: 800, letterSpacing: "-0.02em" }}>Your activity</div>
            <div style={{ fontSize: 17, color: "var(--text2)", marginTop: 3 }}>Signing requests posted by your wallet, read from chain.</div>
          </div>
          {(() => {
            const VM = [
              { name: "Aptos", logo: "/chains/aptos.png" }, { name: "Ethereum", logo: "/chains/ethereum.png" }, { name: "Tron", logo: "/chains/tron.png" },
              { name: "Cosmos", logo: "/chains/cosmos.png" }, { name: "Bitcoin", logo: "/chains/bitcoin.png" },
            ];
            const empty = (msg: string) => (
              <div style={{ border: "1px dashed var(--border)", background: "var(--bg2)", borderRadius: 14, padding: "40px 20px", fontSize: 18, color: "var(--text2)", textAlign: "center" }}>{msg}</div>
            );
            if (!wallet) return empty("Connect your wallet to see your signing history.");
            if (activity === null) return empty("Loading your requests…");
            if (activity.length === 0) return empty("No signing requests yet. Post one from Sign.");
            return (
              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                {activity.map((a) => {
                  const c = VM[a.vm] ?? { name: `vm${a.vm}`, logo: "" };
                  return (
                    <a
                      key={a.request}
                      href={`https://solscan.io/account/${a.request}?cluster=devnet`}
                      target="_blank"
                      rel="noreferrer"
                      style={{ background: "var(--bg2)", border: "1px solid var(--border)", borderRadius: 14, padding: "14px 16px", display: "flex", alignItems: "center", gap: 14, minWidth: 0, textDecoration: "none", color: "inherit", cursor: "pointer" }}
                    >
                      {c.logo ? chainImg(c.logo, 22) : <span style={{ width: 11, height: 11, borderRadius: 999, background: "#888", flex: "0 0 auto" }} />}
                      <div style={{ minWidth: 0, flex: 1 }}>
                        <div style={{ fontSize: 18, fontWeight: 700 }}>{c.name} <span style={{ fontSize: 15, color: "var(--text2)", fontWeight: 500 }}>· #{a.requestId} · {a.scheme === 0 ? "FROST" : "GG20"}</span></div>
                        <div style={{ fontSize: 15, color: "var(--text2)", fontFamily: mono, ...wrap }}>{a.signatureHex ? `sig ${mid(a.signatureHex, 12, 10)}` : a.expired ? "expired before the operator set signed" : "awaiting operator threshold signature…"}</div>
                      </div>
                      <span style={{ flex: "0 0 auto", display: "inline-flex", alignItems: "center", gap: 6, fontSize: 15, fontWeight: 700, padding: "5px 11px", borderRadius: 999, background: a.signed ? "var(--accent-soft)" : "var(--bg3)", color: a.signed ? "var(--accent)" : "var(--text2)", border: `1px solid ${a.signed ? "var(--accent-border)" : "var(--border)"}`, opacity: a.expired ? 0.75 : 1 }}>
                        {a.signed ? <><Check size={15} /> Signed</> : a.expired ? <>Expired</> : <><Loader2 size={15} className="spin" /> Pending</>}
                      </span>
                    </a>
                  );
                })}
              </div>
            );
          })()}
          <div style={{ marginTop: 22, fontSize: 16, color: "var(--text2)", fontFamily: mono, ...wrap }}>
            Solana · coordinator {mid(PROGRAM_ID.toBase58(), 6, 6)}
          </div>
        </section>
      )}

      {view === "sign" && (
      <section style={{ maxWidth: 1060, margin: "0 auto", padding: "24px 22px 40px", boxSizing: "border-box" }}>
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 26, fontWeight: 800, letterSpacing: "-0.02em" }}>Sign</div>
          <div style={{ fontSize: 17, color: "var(--text2)", marginTop: 3 }}>Threshold-sign a native asset on any chain.</div>
        </div>
        <div className="signgrid" style={{ display: "grid", gridTemplateColumns: "minmax(0, 500px) minmax(0, 1fr)", gap: 22, alignItems: "start" }}>
        <div style={{ minWidth: 0 }}>
        <div
          style={{
            background: "var(--bg2)", border: "1px solid var(--border)", borderRadius: 18,
            padding: 18, boxSizing: "border-box",
            boxShadow: "0 1px 0 rgba(255,255,255,0.02) inset, 0 24px 60px -40px rgba(0,0,0,0.9)",
          }}
        >
          {/* You send — amount on the left, chain dropdown on the right (THORSwap style) */}
          <div style={{ ...sendBox, position: "relative" }}>
            <div style={boxHead}>
              <span>You send</span>
              <span>native · no wrapping</span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <input
                value={amount}
                onChange={(e) => setAmount(e.target.value)}
                placeholder="0.00"
                inputMode="decimal"
                style={{ ...bareInput, fontSize: 30, fontWeight: 700, flex: 1, minWidth: 0 }}
              />
              <button
                onClick={() => setChainMenu((v) => !v)}
                style={{ display: "flex", alignItems: "center", gap: 8, flex: "0 0 auto", background: "var(--bg2)", border: "1px solid var(--border)", borderRadius: 999, padding: "8px 12px", cursor: "pointer", fontFamily: "inherit" }}
              >
                {chainImg(chain.logo, 22)}
                <span style={{ fontSize: 18, fontWeight: 700, color: "var(--text)" }}>{chain.name}</span>
                <ChevronDown size={17} color="var(--text2)" style={{ transform: chainMenu ? "rotate(180deg)" : "none", transition: "transform 0.15s" }} />
              </button>
            </div>
            <div style={{ fontSize: 15, color: "var(--text2)", marginTop: 6 }}>{chain.scheme} · {chain.curve}</div>
            {chainMenu && (
              <div style={{ position: "absolute", right: 15, top: 62, zIndex: 10, background: "var(--bg2)", border: "1px solid var(--border)", borderRadius: 14, padding: 6, minWidth: 180, boxShadow: "0 20px 50px -20px rgba(0,0,0,0.9)" }}>
                {CHAINS.map((c, i) => (
                  <button
                    key={c.key}
                    onClick={() => { setSelected(i); setChainMenu(false); }}
                    style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", textAlign: "left", background: i === selected ? "var(--accent-soft)" : "transparent", border: "none", borderRadius: 10, padding: "10px 12px", cursor: "pointer", fontFamily: "inherit", color: "var(--text)" }}
                  >
                    {chainImg(c.logo, 22)}
                    <span style={{ fontSize: 17, fontWeight: 600 }}>{c.name}</span>
                    <span style={{ marginLeft: "auto", fontSize: 14, color: "var(--text2)" }}>{c.curve}</span>
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* divider */}
          <div style={{ display: "flex", justifyContent: "center", margin: "-11px 0", position: "relative", zIndex: 2 }}>
            <div style={{ width: 38, height: 38, borderRadius: 999, background: "var(--accent)", border: "4px solid var(--bg2)", display: "grid", placeItems: "center" }}>
              <ArrowDown size={18} color="#07100e" strokeWidth={2.5} />
            </div>
          </div>

          {/* Destination */}
          <div style={{ ...sendBox, marginBottom: 12 }}>
            <div style={boxHead}>
              <span>Destination on {chain.name}</span>
              {chainImg(chain.logo, 18)}
            </div>
            <input
              value={destination}
              onChange={(e) => setDestination(e.target.value)}
              placeholder={chain.sample}
              spellCheck={false}
              style={{ ...bareInput, fontSize: 18 }}
            />
          </div>

          {/* details table */}
          <div style={{ background: "var(--bg3)", border: "1px solid var(--border)", borderRadius: 12, padding: "11px 14px", marginBottom: 14, display: "flex", flexDirection: "column", gap: 6 }}>
            {([
              ["Signed by", `${proto?.operatorCount ?? 0} bonded operators`],
              ["Scheme", `${chain.scheme} · ${chain.curve}`],
              ["Settles as", `native ${chain.name}, no wrapping`],
            ] as [string, string][]).map(([k, v]) => (
              <div key={k} style={{ display: "flex", justifyContent: "space-between", gap: 14, fontSize: 16 }}>
                <span style={{ color: "var(--text2)", flex: "0 0 auto" }}>{k}</span>
                <span style={{ color: "var(--text)", fontFamily: mono, textAlign: "right", ...wrap }}>{v}</span>
              </div>
            ))}
          </div>

          {proto && !ready && (
            <div style={{ display: "flex", alignItems: "center", gap: 9, fontSize: 18, color: "var(--text)", background: "var(--warn-soft)", border: "1px solid var(--warn)", borderRadius: 12, padding: "12px 14px", marginBottom: 18 }}>
              <AlertTriangle size={18} color="var(--warn)" style={{ flex: "0 0 auto" }} />
              <span style={{ ...wrap }}>
                {proto.initialized ? "No active operators bonded yet." : "Protocol not initialized on this RPC."}
              </span>
            </div>
          )}

          <button
            id="action"
            onClick={run}
            disabled={running}
            style={{
              width: "100%", display: "flex", alignItems: "center", justifyContent: "center", gap: 10,
              background: running ? "var(--bg3)" : "linear-gradient(90deg, #23dcc8 0%, #3aa0ff 100%)",
              color: running ? "var(--text2)" : "#07100e",
              border: "none", fontSize: 19, fontWeight: 800, padding: "14px 18px", borderRadius: 14,
              cursor: running ? "default" : "pointer", boxSizing: "border-box", transition: "all 0.18s ease",
            }}
          >
            {running ? <Loader2 size={20} style={{ animation: "spin 0.9s linear infinite" }} /> : <Zap size={20} />}
            <span style={wrap}>
              {running ? "Posting signing intent on-chain" : wallet ? "Request threshold signature" : "Connect wallet to sign"}
            </span>
          </button>
        </div>
        </div>

        {/* Right column: live activity */}
        <div id="feed" style={{ minWidth: 0, scrollMarginTop: 20 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 9, marginBottom: 12, height: 44 }}>
          <Radio size={18} color="var(--accent)" style={{ flex: "0 0 auto" }} />
          <span style={{ fontSize: 19, fontWeight: 700 }}>Signing intents</span>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 10, minWidth: 0 }}>
          {feed.length === 0 && (
            <div style={{ border: "1px dashed var(--border)", background: "var(--bg2)", borderRadius: 12, padding: "20px 16px", fontSize: 18, color: "var(--text2)", textAlign: "center" }}>
              Request a threshold signature to post your first on-chain intent.
            </div>
          )}

          <AnimatePresence initial={false}>
            {feed.map((r) => (
              <motion.div key={r.id} initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.22, ease: "easeOut" }} style={rowShell}>
                {r.kind === "intent" && (
                  <>
                    <div style={rowHead}>
                      <ArrowDownRight size={18} color="var(--accent)" style={{ flex: "0 0 auto" }} />
                      <span style={{ ...wrap }}>Intent posted</span>
                      {chainImg(r.logo, 18)}
                      <span style={{ color: "var(--text2)", fontWeight: 600, ...wrap }}>{r.chain}</span>
                      <Check size={16} color="var(--accent)" style={{ flex: "0 0 auto" }} />
                    </div>
                    <div style={rowMeta}>{r.amt} → {mid(r.dest)}</div>
                    <a href={`https://solscan.io/tx/${r.sig}?cluster=devnet`} target="_blank" rel="noreferrer" style={{ ...rowMeta, color: "var(--accent)", textDecoration: "none" }}>tx {mid(r.sig, 8, 8)} ↗</a>
                    {r.threshSig ? (
                      <div style={{ ...rowMeta, color: "var(--accent)", display: "flex", alignItems: "center", gap: 8 }}>
                        <ShieldCheck size={16} color="var(--accent)" style={{ flex: "0 0 auto" }} />
                        <span style={{ ...wrap }}>signed by operators · {mid(r.threshSig, 10, 8)}</span>
                      </div>
                    ) : (
                      <div style={{ ...rowMeta, display: "flex", alignItems: "center", gap: 8 }}>
                        <Loader2 size={16} className="spin" style={{ flex: "0 0 auto" }} />
                        <span style={{ ...wrap }}>awaiting operator threshold signature…</span>
                      </div>
                    )}
                    {r.ethRaw && !r.ethSent && (
                      <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 10, marginTop: 2 }}>
                        <span style={{ ...rowMeta, color: "var(--accent)" }}>chain-valid tx assembled · {mid(r.ethHash ?? "", 10, 8)}</span>
                        <button
                          onClick={() => broadcast(r.id, r.ethRaw!)}
                          style={{ fontSize: 18, fontWeight: 600, color: "#0d0f13", background: "var(--accent)", border: "none", borderRadius: 9, padding: "8px 16px", cursor: "pointer", fontFamily: "inherit" }}
                        >
                          Broadcast to Sepolia
                        </button>
                      </div>
                    )}
                    {r.ethSent && (
                      <a href={`https://sepolia.etherscan.io/tx/${r.ethSent}`} target="_blank" rel="noreferrer" style={{ ...rowMeta, color: "var(--accent)", textDecoration: "underline" }}>
                        broadcast · view on Etherscan ↗
                      </a>
                    )}
                    {r.ethErr && <div style={{ ...rowMeta, color: "var(--warn)" }}>{r.ethErr}</div>}
                  </>
                )}
                {r.kind === "error" && (
                  <>
                    <div style={{ ...rowHead, color: "var(--warn)" }}>
                      <AlertTriangle size={18} color="var(--warn)" style={{ flex: "0 0 auto" }} />
                      <span style={{ ...wrap }}>Rejected</span>
                    </div>
                    <div style={rowMeta}>{r.msg}</div>
                  </>
                )}
              </motion.div>
            ))}
          </AnimatePresence>
        </div>
        </div>
        </div>

        <div style={{ marginTop: 24, fontSize: 18, color: "var(--text2)", fontFamily: mono, ...wrap }}>
          Solana · coordinator {mid(PROGRAM_ID.toBase58(), 6, 6)}
        </div>
      </section>
      )}
      </div>

      <style>{`@keyframes spin { to { transform: rotate(360deg); } } @media (max-width: 860px){ .sidebar{ display:none !important } } @media (max-width: 900px){ .signgrid{ grid-template-columns: minmax(0,1fr) !important } }`}</style>
    </main>
  );
}
