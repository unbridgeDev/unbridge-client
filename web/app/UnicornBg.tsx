"use client"

import { useEffect, useRef } from "react"

// Unicorn Studio ambient scene (recolored to the Distin palette), rendered as a
// fixed full-bleed background. The runtime is loaded once from jsDelivr and the
// exported scene JSON is self-hosted under /public.
const RUNTIME =
  "https://cdn.jsdelivr.net/gh/hiunicornstudio/unicornstudio.js@v2.2.6/dist/unicornStudio.umd.js"

export default function UnicornBg() {
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    let scene: { destroy: () => void; paused?: boolean } | null = null
    let cancelled = false
    let io: IntersectionObserver | null = null

    function boot() {
      const US = (window as unknown as { UnicornStudio?: any }).UnicornStudio
      if (!US || !ref.current) return
      US.addScene({
        element: ref.current,
        filePath: "/starry_distin.json",
        fps: 60,
        scale: 1,
        dpi: 1.5,
        lazyLoad: false,
        interactivity: { mouse: { disabled: false } },
      })
        .then((s: { destroy: () => void; paused?: boolean }) => {
          if (cancelled) {
            s.destroy()
            return
          }
          scene = s
          // Scene lives only in the hero: stop rendering once it scrolls away.
          if (ref.current) {
            io = new IntersectionObserver(
              ([entry]) => {
                if (scene) scene.paused = !entry.isIntersecting
              },
              { threshold: 0 },
            )
            io.observe(ref.current)
          }
        })
        .catch((e: unknown) => console.error("[UnicornBg]", e))
    }

    if ((window as unknown as { UnicornStudio?: any }).UnicornStudio) {
      boot()
    } else {
      let s = document.querySelector<HTMLScriptElement>("script[data-unicorn]")
      if (!s) {
        s = document.createElement("script")
        s.src = RUNTIME
        s.async = true
        s.dataset.unicorn = "1"
        document.head.appendChild(s)
      }
      s.addEventListener("load", boot)
    }

    return () => {
      cancelled = true
      if (io) io.disconnect()
      if (scene) scene.destroy()
    }
  }, [])

  return <div ref={ref} style={{ position: "absolute", inset: 0 }} aria-hidden />
}
