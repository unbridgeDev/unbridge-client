"use client"

import { useEffect, useRef, useState } from "react"
import {
  motion,
  AnimatePresence,
  useScroll,
  useTransform,
  useInView,
  useMotionValue,
  animate,
} from "framer-motion"
import { AtSign, MessageCircle, Globe, Plus, Minus, ArrowRight, ArrowUpRight } from "lucide-react"
import dynamic from "next/dynamic"

const BgScene = dynamic(() => import("./BgScene"), { ssr: false })
const UnicornBg = dynamic(() => import("./UnicornBg"), { ssr: false })
const AmbientAudio = dynamic(() => import("./AmbientAudio"), { ssr: false })

// True only if the browser can actually create a WebGL context. On a machine
// where WebGL is disabled/unavailable, mounting an R3F Canvas throws "Error
// creating WebGL context" (an unhandled rejection that also shows up as Next dev
// issues); skipping the mount lets the instant gradient poster stand in cleanly.
function webglAvailable(): boolean {
  try {
    const c = document.createElement("canvas")
    return !!(c.getContext("webgl2") || c.getContext("webgl"))
  } catch {
    return false
  }
}

// Mount heavy WebGL only after the browser is idle, so the 3D boot stays out
// of the initial load / time-to-interactive window. 3D quality is untouched.
function DeferredMount({ children }: { children: React.ReactNode }) {
  const [ready, setReady] = useState(false)
  useEffect(() => {
    if (!webglAvailable()) return // no WebGL: leave the poster, never throw
    const w = window as typeof window & {
      requestIdleCallback?: (cb: () => void, opts?: { timeout: number }) => number
    }
    const ric = w.requestIdleCallback
    if (ric) {
      const id = ric(() => setReady(true), { timeout: 2500 })
      return () => (w.cancelIdleCallback ?? clearTimeout)(id as number)
    }
    const t = setTimeout(() => setReady(true), 1200)
    return () => clearTimeout(t)
  }, [])
  return ready ? <>{children}</> : null
}

const ACCENT = "#8B5CF6"
const ACCENT_BTN = "#7C3AED" // deeper accent for white-on-fill (WCAG AA: 5.7:1)
const ACCENT_TEXT = "#a78bfa" // lighter accent for small text on dark surfaces
const BG = "#060606"
const SURFACE = "#0d0d0d"
const LINE = "rgba(255,255,255,0.08)"
const MUTED = "rgba(255,255,255,0.62)"
const MONO = '"SFMono-Regular", ui-monospace, "JetBrains Mono", Menlo, monospace'

// The real, confirmed native Bitcoin transaction the operator set threshold-signed.
const TXID = "d8d46e3068f5f11133eb0be5e45d1ba400b1148e2001155ee9ad57337cfba7a1"
const TX_URL = `https://mempool.space/testnet/tx/${TXID}`

const comparison = [
  ["What moves", "Asset locked, minted, redeemed across chains", "Nothing moves; a native signature is produced"],
  ["What the destination sees", "A wrapped IOU and a bridge contract", "An ordinary signature on its own curve"],
  ["Trust surface", "Bridge validators holding custody", "Bonded operators, slashed on-chain"],
  ["Failure mode", "A drained bridge, stranded wrapped assets", "A request that simply expires"],
]

// The signature moment — the real threshold-signing lifecycle, ground-truthed to
// engine/programs/distin/src/lib.rs. Two stages are OFF-CHAIN cryptography, two
// are ON-CHAIN coordination; the chain RECORDS the aggregate, it never recomputes
// it. Each stage names the actual instruction or library that does the work.
const flow = [
  {
    k: "01",
    where: "on-chain",
    op: "create_signing_request",
    title: "Post the intent",
    body: "A user writes one 32-byte signing intent to the Solana program: the destination VM, the message hash, a stake-weight threshold, and a slot deadline. The request account is the whole ask.",
  },
  {
    k: "02",
    where: "off-chain",
    op: "kobe · FROST / GG20 rounds",
    title: "Operators sign, apart",
    body: "Bonded operators run the real multi-round ceremony off-chain. FROST over Ed25519, GG20 over secp256k1. Each holds one Shamir share; the group key is never assembled in any single place.",
  },
  {
    k: "03",
    where: "on-chain",
    op: "submit_partial_signature",
    title: "Stake answers for them",
    body: "Each operator posts a participation receipt carrying its staked weight. The chain does no curve math; it counts distinct operators and staked weight against the threshold, inside the deadline.",
  },
  {
    k: "04",
    where: "on-chain",
    op: "aggregate_and_emit",
    title: "Record, then broadcast",
    body: "The coordinator combines the partials off-chain and posts the finished signature back. The program records it once the threshold is met and emits it; a relayer verifies and broadcasts on the destination chain.",
  },
]

// Coordination-latency contrast (concept.json / engine: 400ms slots make
// multi-round MPC near-real-time; a 12s chain compounds each round into minutes).
const latency = [
  { chain: "Solana", slot: "400ms slots", rounds: 3, perRoundMs: 400, label: "≈ 1.2s · interactive" },
  { chain: "L1 at 12s", slot: "12s blocks", rounds: 3, perRoundMs: 12000, label: "≈ 36s · unusable" },
  { chain: "L1 at 15s", slot: "15s blocks", rounds: 3, perRoundMs: 15000, label: "≈ 45s · unusable" },
]

const signsSpec = [
  { chain: "Ethereum", logo: "/chains/ethereum.png", scheme: "GG20 · secp256k1", note: "Threshold ECDSA, ecrecover to the group address" },
  { chain: "Bitcoin", logo: "/chains/bitcoin.png", scheme: "GG20 · secp256k1", note: "Native signature, verified against spec vectors" },
  { chain: "Tron", logo: "/chains/tron.png", scheme: "GG20 · secp256k1", note: "Same curve, same group key, no wrapping" },
  { chain: "Cosmos", logo: "/chains/cosmos.png", scheme: "FROST · Ed25519", note: "Schnorr threshold, accepted by ed25519-dalek" },
  { chain: "Aptos", logo: "/chains/aptos.png", scheme: "FROST · Ed25519", note: "One Solana account, a native Move signature" },
]

const faqs = [
  {
    q: "What is Unbridge, exactly?",
    a: "A control plane for cross-chain signing on Solana. Instead of bridging an asset, a quorum of bonded operators threshold-signs a native transaction for the destination chain. One Solana account, a real signature on every chain, no bridge in the path.",
  },
  {
    q: "How do I know the threshold signing is real?",
    a: "Run it. cargo test in engine/kobe produces a FROST Ed25519 signature an independent ed25519-dalek verifier accepts; go test in engine/kobe-ecdsa produces a GG20 secp256k1 signature go-ethereum ecrecovers to the group address, with Bitcoin and Tron verified against their own spec vectors. The group secret is never reconstructed.",
  },
  {
    q: "Is anything live yet?",
    a: "Yes. The Anchor program is deployed and live on Solana at 4xy9dYHfAzi7cAcX5JHxNR6EoMJ9PGfeQDMHx6YUQQM6, with the off-chain MPC, the on-chain coordination loop, and a networked operator set all built and signing. The crypto layer is independently verified by cargo test and go test, and the group secret is never reconstructed in one place.",
  },
]

const css = `
/* The whole composition reads best ~20% denser (the "80% browser zoom" look).
   Desktop only: on phones the base sizes are already right. */
html { zoom: 0.8; }
.hero-sec, .hero-inner { min-height: max(calc(100vh / 0.8), 720px); }
@media (max-width: 980px) {
  html { zoom: 1; }
  .hero-sec, .hero-inner { min-height: max(100vh, 640px); }
}

.wrap { max-width: 1360px; margin: 0 auto; padding: 0 48px; }
.wrap-wide { max-width: 1760px; margin: 0 auto; padding: 0 48px; }
.hero-top { display: flex; justify-content: space-between; align-items: flex-start; gap: 24px; }
.hero-foot { display: grid; grid-template-columns: 1fr 300px; align-items: end; gap: 64px; }

.metrics { display: grid; grid-template-columns: 1.5fr 1fr 1fr 1fr; }
.metric-cell { padding: 64px 44px 56px; position: relative; }

.sec-head { display: grid; grid-template-columns: 1fr 1fr; align-items: end; gap: 48px; }

.manifesto-grid { display: grid; grid-template-columns: 320px 1fr; gap: 80px; align-items: start; }

.cmp-row { display: grid; grid-template-columns: 1.3fr 1fr 1fr; }

.feature-row { display: grid; grid-template-columns: 7fr 5fr; gap: 72px; align-items: center; }
.feature-row.flip .feature-media { order: 2; }
.feature-row.flip .feature-copy { order: 1; }

/* Signature-moment flow: four stages on one rail, off-chain vs on-chain banded */
.flow-grid { display: grid; grid-template-columns: repeat(4, 1fr); border: 1px solid ${LINE}; }
.flow-stage { padding: 40px 34px 44px; border-right: 1px solid ${LINE}; position: relative; min-height: 460px; display: flex; flex-direction: column; }
.flow-stage:last-child { border-right: none; }
.flow-bands { display: grid; grid-template-columns: repeat(4, 1fr); margin-top: -1px; }
.flow-band { font-family: ${MONO}; font-size: 18px; letter-spacing: 0.04em; text-transform: uppercase; padding: 16px 34px; border-right: 1px solid ${LINE}; border-bottom: 1px solid ${LINE}; }
.flow-band:last-child { border-right: none; }

/* Feature compositions — each structurally different, NOT a repeated 2-col */
.f-bleed { position: relative; min-height: clamp(420px, 52vw, 640px); display: grid; grid-template-columns: 1.1fr 1fr; }
.f-split { display: grid; grid-template-columns: 1fr 1fr; border: 1px solid ${LINE}; }
.f-pinned { display: grid; grid-template-columns: 360px 1fr; gap: 64px; align-items: start; }

/* Latency comparison bars (code-drawn, no image) */
.lat-row { display: grid; grid-template-columns: 220px 1fr; align-items: center; gap: 28px; padding: 22px 0; }

.stats-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 0; }

.signs-head { display: grid; grid-template-columns: 1fr 1fr; align-items: end; gap: 48px; }
.signs-row { display: grid; grid-template-columns: 1.1fr 1fr 1.5fr; align-items: center; gap: 32px; }

/* Proof receipt — the real confirmed transaction shown as an on-chain ledger row */
.proof-receipt { display: grid; grid-template-columns: 1.5fr 1fr 1fr 1fr; border: 1px solid ${LINE}; text-decoration: none; transition: border-color .25s ease, background .25s ease; }
.proof-cell { padding: 24px 26px; border-right: 1px solid ${LINE}; }
.proof-cell:last-child { border-right: none; }
.proof-receipt:hover { border-color: rgba(139,92,246,0.5); background: rgba(139,92,246,0.05); }
.proof-k { font-family: ${MONO}; font-size: 18px; letter-spacing: 0.04em; text-transform: uppercase; color: ${MUTED}; display: inline-flex; align-items: center; gap: 8px; }
.proof-v { font-family: ${MONO}; font-size: 20px; color: #fff; margin-top: 13px; word-break: break-all; }
@keyframes pulse { 0%,100% { opacity: 1; box-shadow: 0 0 0 0 rgba(139,92,246,0.5); } 50% { opacity: .5; box-shadow: 0 0 0 7px rgba(139,92,246,0); } }
.pulse { animation: pulse 2s ease-in-out infinite; }
@media (prefers-reduced-motion: reduce) { .pulse { animation: none; } }

@media (max-width: 640px) {
  .nav { margin: 12px; padding: 10px 14px; }
  .nav-docs { display: none; }
  .nav-cta { padding: 11px 16px !important; font-size: 16px !important; }
  .nav-logo { height: 38px !important; }
  .nav-wordmark { font-size: 20px !important; }
  .proof-receipt { grid-template-columns: 1fr !important; }
  .proof-receipt { grid-template-columns: 1fr; }
}

@media (max-width: 980px) {
  .wrap, .wrap-wide { padding: 0 22px; }
  .hero-foot { grid-template-columns: 1fr; gap: 28px; }
  .metrics { grid-template-columns: repeat(2, 1fr); }
  .metric-cell { padding: 40px 26px; }
  .sec-head { grid-template-columns: 1fr; gap: 24px; }
  .manifesto-grid { grid-template-columns: 1fr; gap: 28px; }
  .cmp-row { grid-template-columns: 1fr; }
  .signs-head { grid-template-columns: 1fr; gap: 24px; }
  .signs-row { grid-template-columns: 1fr; gap: 12px; }
  .proof-receipt { grid-template-columns: 1fr 1fr; }
  .feature-row { grid-template-columns: 1fr; gap: 28px; }
  .feature-row.flip .feature-media { order: 0; }
  .feature-row.flip .feature-copy { order: 0; }
  .stats-grid { grid-template-columns: 1fr; }
  .flow-grid { grid-template-columns: 1fr; }
  .flow-stage { border-right: none; border-bottom: 1px solid ${LINE}; min-height: 0; }
  .flow-bands { grid-template-columns: 1fr; }
  .flow-band { border-right: none; }
  .f-bleed { grid-template-columns: 1fr; }
  .f-split { grid-template-columns: 1fr; }
  .f-pinned { grid-template-columns: 1fr; gap: 28px; }
  .lat-row { grid-template-columns: 1fr; gap: 10px; }
}
`

function Label({ children, color = MUTED }: { children: React.ReactNode; color?: string }) {
  return (
    <div
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 13,
        fontFamily: MONO,
        fontSize: 18,
        textTransform: "uppercase",
        letterSpacing: "0.09em",
        color,
      }}
    >
      <span style={{ width: 9, height: 9, background: ACCENT, borderRadius: "50%", flexShrink: 0 }} />
      {children}
    </div>
  )
}

function Index({ n }: { n: string }) {
  return (
    <span
      aria-hidden
      style={{
        fontFamily: MONO,
        fontSize: 18,
        letterSpacing: "0.12em",
        color: ACCENT,
      }}
    >
      {n}
    </span>
  )
}

function Counter({ to, suffix = "" }: { to: number; suffix?: string }) {
  const ref = useRef<HTMLSpanElement>(null)
  const inView = useInView(ref, { once: true, margin: "-80px" })
  const value = useMotionValue(0)
  const [display, setDisplay] = useState("0")

  useEffect(() => {
    if (!inView) return
    const controls = animate(value, to, {
      duration: 1.6,
      ease: "easeOut",
      onUpdate: (v) => setDisplay(Math.round(v).toLocaleString()),
    })
    return () => controls.stop()
  }, [inView, to, value])

  return (
    <span ref={ref}>
      {display}
      {suffix}
    </span>
  )
}

function Reveal({ children }: { children: React.ReactNode; delay?: number }) {
  return <div>{children}</div>
}


/* ── Share diagram: 3 distinct shares fold into one signature, group key absent.
   2-of-3 quorum, matching the protocol's distinct-operator threshold gate. */
function ShareDiagram() {
  return (
    <svg viewBox="0 0 420 150" role="img" aria-label="Three Shamir shares combine into one signature without ever forming the group key" style={{ width: "100%", height: "auto", display: "block" }}>
      <title>Shares combine without the group key</title>
      {[0, 1, 2].map((i) => {
        const y = 24 + i * 42
        return (
          <g key={i}>
            <rect x="2" y={y} width="120" height="28" fill="none" stroke={LINE} />
            <text x="14" y={y + 19} fontFamily={MONO} fontSize="14" fill="rgba(255,255,255,0.78)">share {i + 1} / 3</text>
            <line x1="122" y1={y + 14} x2="232" y2="75" stroke={ACCENT} strokeWidth="1" opacity="0.55" />
          </g>
        )
      })}
      {/* combine node */}
      <circle cx="244" cy="75" r="20" fill="rgba(139,92,246,0.14)" stroke={ACCENT} />
      <text x="244" y="79" textAnchor="middle" fontFamily={MONO} fontSize="13" fill="#c9b3ff">∑</text>
      <line x1="264" y1="75" x2="300" y2="75" stroke={ACCENT} strokeWidth="1" />
      {/* output signature */}
      <rect x="300" y="58" width="116" height="34" fill="rgba(139,92,246,0.1)" stroke={ACCENT} />
      <text x="358" y="79" textAnchor="middle" fontFamily={MONO} fontSize="14" fill="#fff">1 signature</text>
      {/* group key crossed out */}
      <text x="244" y="128" textAnchor="middle" fontFamily={MONO} fontSize="13" fill="rgba(255,255,255,0.4)">group key never assembled</text>
      <line x1="180" y1="123" x2="308" y2="123" stroke="rgba(255,255,255,0.4)" strokeWidth="1" />
    </svg>
  )
}

/* ── Program spec: what the on-chain Anchor program does vs delegates, exactly. */
function ProgramSpec() {
  const rows: [string, string][] = [
    ["opens", "32-byte signing intent + slot deadline"],
    ["gates", "distinct operators × staked weight ≥ threshold"],
    ["records", "the off-chain aggregate, bound to the request"],
    ["slashes", "a misbehaving bond into the slash pool"],
  ]
  return (
    <div style={{ borderTop: `1px solid ${LINE}` }}>
      {rows.map(([k, v]) => (
        <div key={k} style={{ display: "grid", gridTemplateColumns: "104px 1fr", gap: 16, padding: "15px 0", borderBottom: `1px solid ${LINE}`, alignItems: "baseline" }}>
          <span style={{ fontFamily: MONO, fontSize: 18, color: ACCENT_TEXT, letterSpacing: "0.03em" }}>{k}</span>
          <span style={{ fontSize: 19, color: MUTED, lineHeight: 1.45 }}>{v}</span>
        </div>
      ))}
    </div>
  )
}

/* ── Latency chart: coordination time = rounds × per-round latency, drawn in code.
   Bar lengths use a perceptual (square-root) scale so Solana stays visible while
   the slower chains still read as dramatically longer; each carries its real
   "Nx slower" multiplier against the Solana baseline. */
function LatencyChart() {
  const base = latency[0].rounds * latency[0].perRoundMs
  const totals = latency.map((l) => l.rounds * l.perRoundMs)
  const maxSqrt = Math.sqrt(Math.max(...totals))
  return (
    <div>
      {latency.map((l, i) => {
        const total = l.rounds * l.perRoundMs
        const pct = (Math.sqrt(total) / maxSqrt) * 100
        const fast = i === 0
        const mult = Math.round(total / base)
        return (
          <div key={l.chain} className="lat-row">
            <div>
              <div style={{ fontSize: 22, fontWeight: 700, letterSpacing: "-0.01em" }}>{l.chain}</div>
              <div style={{ fontFamily: MONO, fontSize: 18, color: MUTED, marginTop: 4 }}>{l.slot}</div>
            </div>
            <div>
              <div style={{ position: "relative", height: 34, background: "rgba(255,255,255,0.04)", border: `1px solid ${LINE}` }}>
                <div
                  style={{
                    position: "absolute",
                    left: 0,
                    top: 0,
                    bottom: 0,
                    width: `${Math.max(pct, 6)}%`,
                    background: fast ? ACCENT : "rgba(139,92,246,0.2)",
                    borderRight: `2px solid ${ACCENT}`,
                  }}
                />
                {!fast && (
                  <span
                    style={{
                      position: "absolute",
                      right: 14,
                      top: "50%",
                      transform: "translateY(-50%)",
                      fontFamily: MONO,
                      fontSize: 18,
                      color: "#fff",
                      letterSpacing: "0.02em",
                    }}
                  >
                    {mult}× slower
                  </span>
                )}
              </div>
              <div style={{ fontFamily: MONO, fontSize: 18, color: fast ? ACCENT_TEXT : MUTED, marginTop: 8, letterSpacing: "0.02em" }}>
                {l.rounds} rounds · {l.label}
              </div>
            </div>
          </div>
        )
      })}
    </div>
  )
}

export default function Home() {
  const heroRef = useRef<HTMLElement>(null)
  const { scrollYProgress } = useScroll({ target: heroRef, offset: ["start start", "end start"] })
  const glowY = useTransform(scrollYProgress, [0, 1], [0, 180])
  const glowOpacity = useTransform(scrollYProgress, [0, 1], [0.55, 0])
  const heroTextY = useTransform(scrollYProgress, [0, 1], [0, -60])
  const [openFaq, setOpenFaq] = useState<number | null>(0)

  return (
    <main style={{ background: BG, color: "#fff", fontSize: 18, lineHeight: 1.5, width: "100%", overflowX: "hidden" }}>
      <style dangerouslySetInnerHTML={{ __html: css }} />

      {/* Fixed 3D background (deferred to idle; instant gradient poster underneath) */}
      {/* Fixed 3D background (deferred to idle; instant gradient poster underneath) */}
      <div
        style={{
          position: "fixed",
          inset: 0,
          zIndex: 0,
          background:
            "radial-gradient(120% 90% at 50% 110%, rgba(139,92,246,0.16) 0%, transparent 55%), #060606",
        }}
      >
        <DeferredMount>
          <BgScene />
        </DeferredMount>
      </div>
      <div
        style={{
          position: "fixed",
          inset: 0,
          zIndex: 0,
          pointerEvents: "none",
          background: "radial-gradient(ellipse 90% 80% at 30% 70%, #060606cc 0%, transparent 60%)",
        }}
      />

      <div style={{ position: "relative", zIndex: 1 }}>
      {/* Nav */}
      <nav
        className="nav"
        style={{
          position: "fixed",
          top: 0,
          left: 0,
          right: 0,
          zIndex: 50,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "18px 28px",
          margin: 20,
          border: `1px solid ${LINE}`,
          background: "rgba(6,6,6,0.66)",
          backdropFilter: "blur(14px)",
        }}
      >
        <a href="/" aria-label="Unbridge home" style={{ display: "inline-flex", alignItems: "center", gap: 14, textDecoration: "none" }}>
          <img src="/logo-white.png" alt="" className="nav-logo" style={{ height: 64, width: "auto", display: "block" }} />
          <span className="nav-wordmark" style={{ fontSize: 30, fontWeight: 800, letterSpacing: "-0.02em", color: "#fff" }}>Unbridge</span>
        </a>
        <div style={{ display: "flex", alignItems: "center", gap: 24 }}>
          <a href="/docs" className="nav-docs" style={{ color: MUTED, fontSize: 18, textDecoration: "none" }}>
            Docs
          </a>
          <a
            href="/app"
            className="nav-cta"
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 8,
              padding: "12px 22px",
              background: ACCENT_BTN,
              color: "#fff",
              fontSize: 18,
              fontWeight: 600,
              textDecoration: "none",
              whiteSpace: "nowrap",
            }}
          >
            Launch App
          </a>
        </div>
      </nav>

      {/* Hero */}
      <section ref={heroRef} className="hero-sec" style={{ position: "relative", overflow: "hidden" }}>
        {/* instant poster (matches the dark scene rest frame) under the deferred WebGL */}
        <div
          aria-hidden
          style={{
            position: "absolute",
            inset: 0,
            background:
              "radial-gradient(60% 55% at 72% 58%, rgba(139,92,246,0.22) 0%, transparent 60%), #060606",
          }}
        />
        {/* Ambient Unicorn scene, scoped to the hero (pauses when scrolled away) */}
        <div style={{ position: "absolute", inset: 0 }}>
          <DeferredMount>
            <UnicornBg />
          </DeferredMount>
        </div>
        <div
          aria-hidden
          style={{
            position: "absolute",
            inset: 0,
            pointerEvents: "none",
            // Keep the headline column legible without flattening the ambient
            // scene: a soft left-to-right scrim instead of a heavy radial wash.
            background:
              "linear-gradient(100deg, rgba(6,6,6,0.72) 0%, rgba(6,6,6,0.34) 34%, transparent 62%)",
          }}
        />
        <motion.div
          style={{
            position: "absolute",
            left: "4%",
            top: "44%",
            width: 680,
            height: 680,
            y: glowY,
            opacity: glowOpacity,
            background: `radial-gradient(circle, ${ACCENT}4d 0%, transparent 66%)`,
            pointerEvents: "none",
          }}
        />
        {/* Studio375 signature: giant outline wordmark bleeding off the left edge */}
        <div
          aria-hidden
          className="bleed-mark"
          style={{
            position: "absolute",
            left: "-6%",
            bottom: "-2%",
            zIndex: 1,
            fontSize: "clamp(180px, 30vw, 460px)",
            fontWeight: 800,
            lineHeight: 0.74,
            letterSpacing: "-0.06em",
            whiteSpace: "nowrap",
            color: "transparent",
            WebkitTextStroke: "1px rgba(255,255,255,0.05)",
            pointerEvents: "none",
            userSelect: "none",
          }}
        >
          unbridge
        </div>
        {/* bottom legibility gradient */}
        <div
          style={{
            position: "absolute",
            inset: 0,
            background: "linear-gradient(to top, rgba(6,6,6,0.94) 0%, rgba(6,6,6,0.22) 42%, transparent 66%)",
            pointerEvents: "none",
          }}
        />
        <div
          className="hero-inner"
          style={{
            position: "relative",
            zIndex: 10,
            display: "flex",
            flexDirection: "column",
            justifyContent: "space-between",
          }}
        >
          <div className="wrap-wide" style={{ paddingTop: 132 }}>
            <motion.div
              className="hero-top"
            >
              <span style={{ fontFamily: MONO, fontSize: 18, color: "rgba(255,255,255,0.85)", letterSpacing: "0.09em", textTransform: "uppercase" }}>
                One account, every chain
              </span>
            </motion.div>
          </div>

          <motion.div className="wrap-wide" style={{ paddingBottom: 72, y: heroTextY }}>
            <div className="hero-foot">
              <h1
                className="hero-h1"
                style={{
                  fontSize: "clamp(64px, 14vw, 232px)",
                  fontWeight: 800,
                  lineHeight: 0.86,
                  letterSpacing: "-0.05em",
                  margin: 0,
                }}
              >
                Unbridge
                <span
                  style={{
                    background: `linear-gradient(95deg, ${ACCENT}, #c9b3ff)`,
                    WebkitBackgroundClip: "text",
                    backgroundClip: "text",
                    color: "transparent",
                  }}
                >
                  .
                </span>
              </h1>
              <motion.div
                style={{ paddingBottom: 14, borderLeft: `1px solid ${LINE}`, paddingLeft: 28 }}
              >
                <p style={{ fontSize: 20, color: MUTED, margin: "0 0 22px", lineHeight: 1.55 }}>
                  A quorum of bonded operators threshold-signs a native transaction for any chain,
                  coordinated and slashed by a Solana program. No bridge, no wrapped asset, no
                  honeypot to drain.
                </p>
                <p style={{ fontSize: 19, color: "#fff", margin: "0 0 30px", fontWeight: 600, lineHeight: 1.5 }}>
                  Post your first signing intent in{" "}
                  <span style={{ color: ACCENT_TEXT }}>under two minutes</span>.
                </p>
                <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 18 }}>
                  <a
                    href="/app"
                    style={{
                      display: "inline-flex",
                      alignItems: "center",
                      gap: 10,
                      padding: "16px 34px",
                      background: ACCENT_BTN,
                      color: "#fff",
                      fontSize: 19,
                      fontWeight: 600,
                      textDecoration: "none",
                    }}
                  >
                    Launch App
                  </a>
                  <a
                    href="/docs"
                    style={{
                      display: "inline-flex",
                      alignItems: "center",
                      gap: 8,
                      fontSize: 19,
                      fontWeight: 600,
                      color: "#fff",
                      textDecoration: "none",
                      borderBottom: `1px solid ${ACCENT}`,
                      paddingBottom: 4,
                    }}
                  >
                    Verify it yourself
                    <ArrowRight size={18} color={ACCENT_TEXT} />
                  </a>
                </div>
              </motion.div>
            </div>
          </motion.div>
        </div>
      </section>

      {/* Proof receipt — the one artifact that settles the whole thesis */}
      <section style={{ borderTop: `1px solid ${LINE}`, background: "linear-gradient(180deg, rgba(139,92,246,0.06), transparent 70%)" }}>
        <div className="wrap-wide" style={{ padding: "52px 0 60px" }}>
          <div className="proof-k" style={{ color: ACCENT_TEXT }}>
            <span className="pulse" style={{ width: 9, height: 9, background: ACCENT, borderRadius: "50%", flexShrink: 0 }} />
            Signed and broadcast — the group key was never assembled
          </div>
          <p style={{ fontSize: "clamp(28px, 3.6vw, 52px)", fontWeight: 700, letterSpacing: "-0.035em", lineHeight: 1.06, margin: "24px 0 34px", maxWidth: 1000 }}>
            A Solana account signed a native{" "}
            <span style={{ color: ACCENT_TEXT }}>Bitcoin</span> transaction. It confirmed.
          </p>
          <a href={TX_URL} target="_blank" rel="noreferrer" className="proof-receipt">
            <div className="proof-cell">
              <span className="proof-k">
                Transaction <ArrowUpRight size={16} color={ACCENT_TEXT} />
              </span>
              <div className="proof-v" style={{ color: ACCENT_TEXT }}>{TXID.slice(0, 10)}…{TXID.slice(-8)}</div>
            </div>
            <div className="proof-cell">
              <span className="proof-k">Input</span>
              <div className="proof-v">group UTXO</div>
            </div>
            <div className="proof-cell">
              <span className="proof-k">Output</span>
              <div className="proof-v">recipient + change</div>
            </div>
            <div className="proof-cell">
              <span className="proof-k">Verified by</span>
              <div className="proof-v">Bitcoin consensus</div>
            </div>
          </a>
        </div>
      </section>

      {/* Metric band */}
      <section style={{ borderTop: `1px solid ${LINE}`, borderBottom: `1px solid ${LINE}`, background: SURFACE }}>
        <div className="metrics">
          {[
            { label: "Destination chains, one account", value: <Counter to={5} /> },
            { label: "Curves: FROST Ed25519, GG20 secp256k1", value: <Counter to={2} /> },
            { label: "Bridge contracts in the path", value: <Counter to={0} /> },
            { label: "Times the group secret is reconstructed", value: <Counter to={0} /> },
          ].map((m, i) => (
            <div
              key={i}
              className="metric-cell"
              style={{ borderRight: i < 3 ? `1px solid ${LINE}` : "none", background: i === 0 ? "rgba(139,92,246,0.06)" : "transparent" }}
            >
              <div
                style={{
                  fontSize: i === 0 ? "clamp(56px, 7.5vw, 112px)" : "clamp(44px, 5.5vw, 80px)",
                  fontWeight: 800,
                  letterSpacing: "-0.035em",
                  color: ACCENT,
                  lineHeight: 0.95,
                }}
              >
                {m.value}
              </div>
              <div style={{ marginTop: 18, fontFamily: MONO, fontSize: 18, color: MUTED, letterSpacing: "0.04em" }}>
                {m.label}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Manifesto — full-bleed editorial spread: the broken monolith carries the premise */}
      <section style={{ position: "relative", overflow: "hidden" }}>
        <img
          src="/feature_3.png"
          alt="A monolith split open along a violet seam, a city skyline behind it"
          style={{ position: "absolute", inset: 0, width: "100%", height: "100%", objectFit: "cover" }}
        />
        <div
          aria-hidden
          style={{
            position: "absolute",
            inset: 0,
            background:
              "linear-gradient(90deg, rgba(6,6,6,0.9) 0%, rgba(6,6,6,0.62) 52%, rgba(6,6,6,0.24) 100%)," +
              "linear-gradient(180deg, #060606 0%, transparent 18%, transparent 78%, #060606 100%)",
          }}
        />
        <div className="wrap" style={{ position: "relative", padding: "220px 48px" }}>
          <Reveal>
            <Label color="#fff">The premise</Label>
            <p
              style={{
                fontSize: "clamp(30px, 4vw, 58px)",
                fontWeight: 600,
                lineHeight: 1.22,
                letterSpacing: "-0.025em",
                margin: "34px 0 0",
                maxWidth: 960,
              }}
            >
              Every bridge is a contract holding custody, and the largest one is always the target.{" "}
              <span style={{ color: "#c9b3ff" }}>Unbridge holds nothing.</span> A quorum of operators
              signs natively for the destination chain, the group secret is never reconstructed, and
              the only thing you trust is a program you can read and a signature you can verify.
            </p>
          </Reveal>
        </div>
      </section>

      {/* Comparison */}
      <section style={{ padding: "170px 0 200px" }}>
        <div className="wrap">
          <Reveal>
            <div className="sec-head" style={{ marginBottom: 56 }}>
              <div>
                <div style={{ marginBottom: 22 }}>
                  <Index n="Side by side" />
                </div>
                <h2
                  style={{
                    fontSize: "clamp(44px, 7vw, 104px)",
                    fontWeight: 800,
                    letterSpacing: "-0.04em",
                    lineHeight: 0.94,
                    margin: 0,
                  }}
                >
                  Bridge
                  <br />
                  vs <span style={{ color: ACCENT }}>signature.</span>
                </h2>
              </div>
              <p style={{ fontSize: 20, color: MUTED, margin: 0, maxWidth: 420, justifySelf: "end" }}>
                A bridge parks your asset in a contract and hands you a claim on it. Unbridge leaves
                the asset where it is and signs for it directly on the chain that needs it.
              </p>
            </div>
          </Reveal>
          <div style={{ border: `1px solid ${LINE}`, background: SURFACE }}>
            <div className="cmp-row" style={{ borderBottom: `1px solid ${LINE}`, fontFamily: MONO, fontSize: 18, letterSpacing: "0.04em", textTransform: "uppercase" }}>
              <div style={{ padding: "26px 32px", color: MUTED }}>Dimension</div>
              <div style={{ padding: "26px 32px", color: MUTED, borderLeft: `1px solid ${LINE}` }}>
                Bridged DeFi
              </div>
              <div
                style={{
                  padding: "26px 32px",
                  color: ACCENT_TEXT,
                  borderLeft: `1px solid ${LINE}`,
                  background: "rgba(139,92,246,0.1)",
                }}
              >
                Unbridge
              </div>
            </div>
            {comparison.map((row, i) => (
              <Reveal key={i} delay={i * 0.05}>
                <div
                  className="cmp-row"
                  style={{ borderBottom: i < comparison.length - 1 ? `1px solid ${LINE}` : "none", fontSize: 20 }}
                >
                  <div style={{ padding: "30px 32px", fontWeight: 600 }}>{row[0]}</div>
                  <div style={{ padding: "30px 32px", color: MUTED, borderLeft: `1px solid ${LINE}` }}>
                    {row[1]}
                  </div>
                  <div
                    style={{
                      padding: "30px 32px",
                      borderLeft: `1px solid ${LINE}`,
                      background: "rgba(139,92,246,0.1)",
                      fontWeight: 600,
                    }}
                  >
                    {row[2]}
                  </div>
                </div>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      {/* What one account signs — Studio375 sparse multi-column spec list */}
      <section style={{ padding: "0 0 200px" }}>
        <div className="wrap">
          <Reveal>
            <div className="signs-head" style={{ marginBottom: 64 }}>
              <div>
                <div style={{ marginBottom: 22 }}>
                  <Index n="What one account signs" />
                </div>
                <h2
                  style={{
                    fontSize: "clamp(40px, 5.4vw, 84px)",
                    fontWeight: 800,
                    letterSpacing: "-0.04em",
                    lineHeight: 0.94,
                    margin: 0,
                  }}
                >
                  Five chains.
                  <br />
                  <span style={{ color: ACCENT }}>One key.</span>
                </h2>
              </div>
              <p style={{ fontSize: 20, color: MUTED, margin: 0, maxWidth: 420, justifySelf: "end" }}>
                Each destination receives a signature on its own curve, from the same Solana account.
                Two schemes, branched per VM family. Nothing is wrapped.
              </p>
            </div>
          </Reveal>
          <div style={{ borderTop: `1px solid ${LINE}` }}>
            {signsSpec.map((s, i) => (
              <Reveal key={s.chain} delay={i * 0.05}>
                <div
                  className="signs-row"
                  style={{ padding: "30px 4px", borderBottom: `1px solid ${LINE}` }}
                >
                  <div style={{ display: "inline-flex", alignItems: "center", gap: 16 }}>
                    <img
                      src={s.logo}
                      alt={`${s.chain} logo`}
                      width={28}
                      height={28}
                      loading="lazy"
                      decoding="async"
                      style={{ width: 28, height: 28, flex: "0 0 auto" }}
                    />
                    <span style={{ fontSize: 26, fontWeight: 700, letterSpacing: "-0.02em" }}>{s.chain}</span>
                  </div>
                  <div style={{ fontFamily: MONO, fontSize: 18, color: ACCENT_TEXT, letterSpacing: "0.03em" }}>
                    {s.scheme}
                  </div>
                  <div style={{ fontSize: 19, color: MUTED, lineHeight: 1.5 }}>{s.note}</div>
                </div>
              </Reveal>
            ))}
          </div>
        </div>

        {/* edge-to-edge closer: real terrain dissolving into the signing mesh */}
        <Reveal>
          <img
            src="/feature_4.png"
            alt="Real terrain dissolving into a violet network mesh"
            style={{
              display: "block",
              width: "100%",
              height: "clamp(340px, 40vw, 560px)",
              objectFit: "cover",
              marginTop: 120,
              borderTop: `1px solid ${LINE}`,
              borderBottom: `1px solid ${LINE}`,
            }}
          />
        </Reveal>
      </section>



      {/* FAQ */}
      <section style={{ padding: "200px 0 160px" }}>
        <div className="wrap">
          <div className="manifesto-grid">
            <Reveal>
              <div style={{ position: "sticky", top: 120 }}>
                <div style={{ marginBottom: 22 }}>
                  <Index n="Answers" />
                </div>
                <h2
                  style={{
                    fontSize: "clamp(40px, 4.2vw, 58px)",
                    fontWeight: 800,
                    letterSpacing: "-0.04em",
                    lineHeight: 0.95,
                    margin: 0,
                  }}
                >
                  Questions.
                </h2>
              </div>
            </Reveal>
            <Reveal delay={0.08}>
              <div style={{ borderTop: `1px solid ${LINE}` }}>
                {faqs.map((f, i) => {
                  const open = openFaq === i
                  return (
                    <div key={i} style={{ borderBottom: `1px solid ${LINE}` }}>
                      <button
                        onClick={() => setOpenFaq(open ? null : i)}
                        style={{
                          width: "100%",
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "space-between",
                          gap: 16,
                          padding: "34px 4px",
                          background: "transparent",
                          border: "none",
                          color: "#fff",
                          fontSize: "clamp(22px, 2.6vw, 32px)",
                          fontWeight: 600,
                          letterSpacing: "-0.015em",
                          textAlign: "left",
                          cursor: "pointer",
                        }}
                      >
                        {f.q}
                        {open ? <Minus size={26} color={ACCENT} /> : <Plus size={26} color={ACCENT} />}
                      </button>
                      <AnimatePresence initial={false}>
                        {open && (
                          <motion.div
                            initial={{ height: 0, opacity: 0 }}
                            animate={{ height: "auto", opacity: 1 }}
                            exit={{ height: 0, opacity: 0 }}
                            transition={{ duration: 0.3, ease: [0.22, 1, 0.36, 1] }}
                            style={{ overflow: "hidden" }}
                          >
                            <p style={{ margin: 0, padding: "0 4px 34px", fontSize: 20, color: MUTED, maxWidth: 640, lineHeight: 1.55 }}>
                              {f.a}
                            </p>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </div>
                  )
                })}
              </div>
            </Reveal>
          </div>
        </div>
      </section>

      {/* CTA */}
      <section style={{ position: "relative", padding: "220px 0 200px", overflow: "hidden", borderTop: `1px solid ${LINE}` }}>
        <video
          autoPlay
          muted
          loop
          playsInline
          style={{ position: "absolute", inset: 0, width: "100%", height: "100%", objectFit: "cover", opacity: 0.5 }}
        >
          <source src="/bg_video.mp4" type="video/mp4" />
        </video>
        {/* Keep the copy column (left) readable, but let the video show through
            the rest instead of drowning the whole section in flat near-black. */}
        <div
          style={{
            position: "absolute",
            inset: 0,
            background:
              "linear-gradient(90deg, rgba(6,6,6,0.8) 0%, rgba(6,6,6,0.58) 40%, rgba(6,6,6,0.32) 100%)",
          }}
        />
        <div className="wrap-wide" style={{ position: "relative" }}>
          <Reveal>
            <Label color="#fff">Get started</Label>
            <h2
              style={{
                fontSize: "clamp(56px, 11vw, 180px)",
                fontWeight: 800,
                letterSpacing: "-0.05em",
                lineHeight: 0.88,
                margin: "30px 0 0",
                maxWidth: 1300,
              }}
            >
              Sign on
              <br />
              any chain.
            </h2>
            <div style={{ display: "flex", flexWrap: "wrap", alignItems: "flex-end", justifyContent: "space-between", gap: 40, marginTop: 48 }}>
              <p style={{ fontSize: 21, color: MUTED, margin: 0, maxWidth: 520, lineHeight: 1.55 }}>
                Connect a wallet and post a signing intent. A bonded operator set threshold-signs a
                native transaction on the chain you choose. No bridge, no wrapped asset, no custodian
                holding your funds.
              </p>
              <a
                href="/app"
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 12,
                  padding: "20px 44px",
                  background: ACCENT_BTN,
                  color: "#fff",
                  fontSize: 21,
                  fontWeight: 600,
                  textDecoration: "none",
                }}
              >
                Launch App
              </a>
            </div>
          </Reveal>
        </div>
      </section>

      {/* Closing wordmark */}
      <section style={{ overflow: "hidden", padding: "48px 0 0", borderTop: `1px solid ${LINE}` }}>
        <div
          aria-hidden
          style={{
            fontSize: "clamp(96px, 27vw, 380px)",
            fontWeight: 800,
            letterSpacing: "-0.05em",
            lineHeight: 0.78,
            textAlign: "center",
            whiteSpace: "nowrap",
            color: "transparent",
            WebkitTextStroke: "1px rgba(255,255,255,0.16)",
            marginBottom: "-0.1em",
            userSelect: "none",
          }}
        >
          Unbridge
        </div>
      </section>

      {/* Footer */}
      <footer style={{ margin: 20, marginTop: 40, border: `1px solid ${LINE}`, padding: "44px 32px" }}>
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            alignItems: "center",
            justifyContent: "space-between",
            gap: 24,
          }}
        >
          <div>
            <div style={{ fontSize: 22, fontWeight: 800, letterSpacing: "0.02em" }}>Unbridge</div>
            <div style={{ marginTop: 8, fontSize: 18, color: MUTED }}>
              One Solana account. Every chain. No bridges.
            </div>
          </div>
          <div style={{ display: "flex", gap: 16 }}>
            {[
              { Icon: AtSign, label: "Contact" },
              { Icon: MessageCircle, label: "Community" },
              { Icon: Globe, label: "Website" },
            ].map(({ Icon, label }, i) => (
              <a
                key={i}
                href="/app"
                aria-label={label}
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  justifyContent: "center",
                  width: 48,
                  height: 48,
                  border: `1px solid ${LINE}`,
                  color: "#fff",
                }}
              >
                <Icon size={20} />
              </a>
            ))}
          </div>
        </div>
        <div style={{ marginTop: 28, paddingTop: 24, borderTop: `1px solid ${LINE}`, fontSize: 18, color: MUTED }}>
          © 2026 Unbridge. Built on Solana.
        </div>
      </footer>
      </div>

      <AmbientAudio />
    </main>
  )
}
