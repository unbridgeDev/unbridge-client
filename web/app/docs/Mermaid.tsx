"use client"

import { useEffect, useId, useState } from "react"

// Lazily load + configure mermaid once, dark violet theme to match the docs.
let mermaidPromise: Promise<typeof import("mermaid").default> | null = null
function getMermaid() {
  if (!mermaidPromise) {
    mermaidPromise = import("mermaid").then((mod) => {
      const m = mod.default
      m.initialize({
        startOnLoad: false,
        securityLevel: "loose", // allow <br/> inside notes
        theme: "base",
        fontFamily: 'ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif',
        themeVariables: {
          darkMode: true,
          background: "#0c0c11",
          primaryColor: "#171226",
          primaryBorderColor: "#8B5CF6",
          primaryTextColor: "#eef2f6",
          secondaryColor: "#141018",
          tertiaryColor: "#141018",
          lineColor: "#8b7bc4",
          textColor: "#cdd6e4",
          actorBkg: "#171226",
          actorBorder: "#8B5CF6",
          actorTextColor: "#eef2f6",
          actorLineColor: "#5b4a86",
          signalColor: "#a78bfa",
          signalTextColor: "#cbd3dd",
          labelBoxBkgColor: "#171226",
          labelBoxBorderColor: "#8B5CF6",
          labelTextColor: "#eef2f6",
          loopTextColor: "#a78bfa",
          noteBkgColor: "#241b3a",
          noteBorderColor: "#8B5CF6",
          noteTextColor: "#e6e0f5",
          nodeBorder: "#8B5CF6",
          mainBkg: "#171226",
          clusterBkg: "#0f0c17",
          clusterBorder: "#3a2f57",
          edgeLabelBackground: "#0c0c11",
        },
      })
      return m
    })
  }
  return mermaidPromise
}

export default function Mermaid({ chart }: { chart: string }) {
  const id = "mmd-" + useId().replace(/:/g, "")
  const [svg, setSvg] = useState("")
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    let alive = true
    getMermaid()
      .then((m) => m.render(id, chart))
      .then(({ svg }) => { if (alive) setSvg(svg) })
      .catch((e) => { if (alive) setErr(String(e?.message ?? e)) })
    return () => { alive = false }
  }, [chart, id])

  if (err) return <pre className="mermaid-err">{chart}</pre>
  if (!svg) return <div className="mermaid-loading">Rendering diagram…</div>
  return <div className="mermaid-diagram" dangerouslySetInnerHTML={{ __html: svg }} />
}
