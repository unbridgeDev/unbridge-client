"use client"

import { useEffect, useRef, useState } from "react"

// Site BGM: a looping ambient track (public/bgm.mp3, Pixabay license), faded
// in/out. Off by default; the cookie banner's Accept (or the SOUND toggle) is
// the user gesture that unlocks playback.
const MONO = '"SFMono-Regular", ui-monospace, "JetBrains Mono", Menlo, monospace'

const TARGET_VOL = 0.55
const FADE_MS = 1800

export default function AmbientAudio() {
  const audio = useRef<HTMLAudioElement | null>(null)
  const fade = useRef<ReturnType<typeof setInterval> | null>(null)
  const [on, setOn] = useState(false)
  const [gate, setGate] = useState(false)

  function fadeTo(target: number, then?: () => void) {
    const a = audio.current!
    if (fade.current) clearInterval(fade.current)
    const step = (target - a.volume) / (FADE_MS / 50)
    fade.current = setInterval(() => {
      const next = a.volume + step
      if ((step > 0 && next >= target) || (step < 0 && next <= target)) {
        a.volume = target
        clearInterval(fade.current!)
        fade.current = null
        then?.()
      } else {
        a.volume = next
      }
    }, 50)
  }

  function toggle() {
    if (!audio.current) {
      audio.current = new Audio("/bgm.mp3")
      audio.current.loop = true
      audio.current.volume = 0
    }
    const a = audio.current
    if (on) {
      fadeTo(0, () => a.pause())
    } else {
      a.play().catch(() => {})
      fadeTo(TARGET_VOL)
    }
    setOn(!on)
  }

  // Consent card doubles as the autoplay-unlock gesture; ask once per session.
  useEffect(() => {
    if (!sessionStorage.getItem("distin_sound")) setGate(true)
  }, [])

  function choose(sound: boolean) {
    sessionStorage.setItem("distin_sound", sound ? "on" : "off")
    setGate(false)
    if (sound && !on) toggle()
  }

  useEffect(() => {
    return () => {
      if (fade.current) clearInterval(fade.current)
      audio.current?.pause()
    }
  }, [])

  return (
    <>
      {gate && (
        <div
          role="dialog"
          aria-label="Cookie consent"
          style={{
            position: "fixed",
            left: 0,
            right: 0,
            bottom: 0,
            zIndex: 70,
            background: "#ffffff",
            borderTop: "1px solid #e2e2e7",
            boxShadow: "0 -8px 28px rgba(0,0,0,0.18)",
            fontFamily:
              '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
          }}
        >
          <div
            style={{
              maxWidth: 1360,
              margin: "0 auto",
              padding: "22px 28px",
              display: "flex",
              flexWrap: "wrap",
              alignItems: "center",
              gap: "18px 40px",
            }}
          >
            <div style={{ flex: "1 1 520px", minWidth: 280 }}>
              <div style={{ fontSize: 18, fontWeight: 700, color: "#111114", marginBottom: 6 }}>
                We value your privacy
              </div>
              <p style={{ margin: 0, fontSize: 18, lineHeight: 1.5, color: "#55555e" }}>
                We use cookies and local storage to remember your preferences, keep your session
                running smoothly, and enhance your experience on this site. You can accept all
                cookies or reject non-essential ones.
              </p>
            </div>
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
              <button
                onClick={() => choose(false)}
                style={{
                  padding: "13px 24px",
                  background: "#ffffff",
                  color: "#3f3f46",
                  border: "1px solid #d4d4d8",
                  borderRadius: 6,
                  fontSize: 18,
                  fontWeight: 600,
                  cursor: "pointer",
                  fontFamily: "inherit",
                  whiteSpace: "nowrap",
                }}
              >
                Reject non-essential
              </button>
              <button
                onClick={() => choose(true)}
                style={{
                  padding: "13px 28px",
                  background: "#18181b",
                  color: "#ffffff",
                  border: "1px solid #18181b",
                  borderRadius: 6,
                  fontSize: 18,
                  fontWeight: 600,
                  cursor: "pointer",
                  fontFamily: "inherit",
                  whiteSpace: "nowrap",
                }}
              >
                Accept all cookies
              </button>
            </div>
          </div>
        </div>
      )}
      <button
        onClick={toggle}
        aria-label={on ? "Mute ambient sound" : "Play ambient sound"}
        aria-pressed={on}
        style={{
          position: "fixed",
          right: 24,
          bottom: 24,
          zIndex: 60,
          display: "inline-flex",
          alignItems: "center",
          gap: 12,
          padding: "13px 20px",
          border: `1px solid ${on ? "rgba(139,92,246,0.55)" : "rgba(255,255,255,0.14)"}`,
          background: "rgba(6,6,6,0.66)",
          backdropFilter: "blur(14px)",
          color: on ? "#c9b3ff" : "rgba(255,255,255,0.62)",
          fontFamily: MONO,
          fontSize: 18,
          letterSpacing: "0.07em",
          cursor: "pointer",
        }}
      >
        <span aria-hidden style={{ display: "inline-flex", alignItems: "flex-end", gap: 2.5, height: 16 }}>
          {[0, 1, 2, 3].map((i) => (
            <span
              key={i}
              style={{
                width: 3,
                background: on ? "#8B5CF6" : "rgba(255,255,255,0.35)",
                height: on ? undefined : 4,
                animation: on ? `eq 1.${3 + i * 2}s ease-in-out ${i * 0.17}s infinite` : "none",
              }}
            />
          ))}
        </span>
        SOUND {on ? "ON" : "OFF"}
        <style>{`
          @keyframes eq { 0%,100% { height: 4px; } 50% { height: 16px; } }
          @media (prefers-reduced-motion: reduce) { @keyframes eq { 0%,100% { height: 8px; } } }
        `}</style>
      </button>
    </>
  )
}
