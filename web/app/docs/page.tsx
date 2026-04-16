"use client"

import { useState, useEffect, useMemo, useRef, useCallback } from "react"
import Link from "next/link"
import dynamic from "next/dynamic"
import ReactMarkdown from "react-markdown"
import remarkGfm from "remark-gfm"

const UnicornBg = dynamic(() => import("../UnicornBg"), { ssr: false })
const Mermaid = dynamic(() => import("./Mermaid"), { ssr: false })

const isMermaid = (cls: unknown) => typeof cls === "string" && cls.includes("language-mermaid")
import {
  BookOpen, Boxes, Workflow, ShieldCheck, Coins, Rocket, Blocks, Braces,
  TriangleAlert, MessageCircleQuestion, Search, ChevronRight, ArrowUpRight,
  CornerDownLeft, Hash, Menu, X,
} from "lucide-react"
import { DOCS_PAGES } from "./content"

const ACCENT = "#8B5CF6"
const ACCENT_TEXT = "#a78bfa"

// Sidebar grouping + a real icon per page (order here == page order).
const ICONS: Record<string, React.ComponentType<{ size?: number }>> = {
  index: BookOpen, architecture: Boxes, "how-it-works": Workflow,
  security: ShieldCheck, economics: Coins, "getting-started": Rocket,
  integration: Blocks, "api-reference": Braces, errors: TriangleAlert,
  faq: MessageCircleQuestion,
}
const GROUPS = [
  { label: "Learn", slugs: ["index", "architecture", "how-it-works", "security", "economics"] },
  { label: "Build", slugs: ["getting-started", "integration", "api-reference", "errors", "faq"] },
]

const idxOf = (slug: string) => DOCS_PAGES.findIndex((p) => p.slug === slug)

function slugify(s: string): string {
  return s.toLowerCase().replace(/`/g, "").replace(/[^\w\s-]/g, "").trim().replace(/\s+/g, "-")
}

// Recursively pull plain text out of ReactMarkdown children (for heading ids).
function nodeText(node: React.ReactNode): string {
  if (node == null || node === false) return ""
  if (typeof node === "string" || typeof node === "number") return String(node)
  if (Array.isArray(node)) return node.map(nodeText).join("")
  const el = node as { props?: { children?: React.ReactNode } }
  if (el.props?.children) return nodeText(el.props.children)
  return ""
}

type Heading = { depth: number; text: string; id: string }

// Parse ## / ### headings out of a markdown body, skipping fenced code blocks.
function tocOf(body: string): Heading[] {
  const out: Heading[] = []
  let inFence = false
  for (const line of body.split("\n")) {
    if (line.trim().startsWith("```")) { inFence = !inFence; continue }
    if (inFence) continue
    const m = /^(#{2,3})\s+(.+?)\s*$/.exec(line)
    if (m) {
      const text = m[2].replace(/`/g, "").replace(/\*\*/g, "").trim()
      out.push({ depth: m[1].length, text, id: slugify(text) })
    }
  }
  return out
}

function stripMd(body: string): string {
  return body.replace(/```[\s\S]*?```/g, " ").replace(/[#>*`|_\-]/g, " ").replace(/\s+/g, " ")
}

type Result = { pi: number; title: string; sub: string | null; id: string | null }

export default function DocsPage() {
  const [active, setActive] = useState(0)
  const [searchOpen, setSearchOpen] = useState(false)
  const [query, setQuery] = useState("")
  const [sel, setSel] = useState(0)
  const [activeId, setActiveId] = useState<string | null>(null)
  const [navOpen, setNavOpen] = useState(false)
  const page = DOCS_PAGES[active]
  const toc = useMemo(() => tocOf(page.body), [page.body])
  const searchRef = useRef<HTMLInputElement>(null)

  const index = useMemo(
    () => DOCS_PAGES.map((p, pi) => ({ pi, title: p.title, headings: tocOf(p.body), text: stripMd(p.body).toLowerCase() })),
    [],
  )

  const results = useMemo<Result[]>(() => {
    const q = query.trim().toLowerCase()
    if (!q) return DOCS_PAGES.map((p, pi) => ({ pi, title: p.title, sub: null, id: null }))
    const out: Result[] = []
    for (const e of index) {
      const titleHit = e.title.toLowerCase().includes(q)
      if (titleHit) out.push({ pi: e.pi, title: e.title, sub: null, id: null })
      for (const h of e.headings) if (h.text.toLowerCase().includes(q)) out.push({ pi: e.pi, title: e.title, sub: h.text, id: h.id })
      if (!titleHit && !e.headings.some((h) => h.text.toLowerCase().includes(q)) && e.text.includes(q)) {
        const i = e.text.indexOf(q)
        out.push({ pi: e.pi, title: e.title, sub: "…" + e.text.slice(Math.max(0, i - 28), i + 44).trim() + "…", id: null })
      }
    }
    return out.slice(0, 14)
  }, [query, index])

  const openPage = useCallback((pi: number, id: string | null) => {
    setActive(pi)
    setSearchOpen(false)
    setQuery("")
    setNavOpen(false)
    setTimeout(() => {
      if (id) document.getElementById(id)?.scrollIntoView({ block: "start" })
      else window.scrollTo(0, 0)
    }, 60)
  }, [])

  // Cmd/Ctrl+K to open search; Esc to close.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setSearchOpen((v) => !v) }
      if (e.key === "Escape") setSearchOpen(false)
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [])

  useEffect(() => { if (searchOpen) { setSel(0); setTimeout(() => searchRef.current?.focus(), 30) } }, [searchOpen])
  useEffect(() => setSel(0), [query])

  // Scrollspy for the "On this page" rail: highlight the last heading scrolled past.
  useEffect(() => {
    const ids = toc.map((h) => h.id)
    if (!ids.length) { setActiveId(null); return }
    const onScroll = () => {
      let cur = ids[0]
      for (const id of ids) {
        const el = document.getElementById(id)
        if (el && el.getBoundingClientRect().top <= 110) cur = id
      }
      setActiveId(cur)
    }
    onScroll()
    window.addEventListener("scroll", onScroll, { passive: true })
    return () => window.removeEventListener("scroll", onScroll)
  }, [active]) // eslint-disable-line react-hooks/exhaustive-deps

  const H = (depth: 1 | 2 | 3) => {
    const Tag = `h${depth}` as "h1" | "h2" | "h3"
    return ({ children }: { children?: React.ReactNode }) => <Tag id={slugify(nodeText(children))}>{children}</Tag>
  }

  return (
    <div className="docs-root">

      <header className="docs-header">
        <div className="docs-header-in">
          <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
            <button className="docs-burger" aria-label="Menu" onClick={() => setNavOpen((v) => !v)}>
              {navOpen ? <X size={20} /> : <Menu size={20} />}
            </button>
            <Link href="/" style={{ display: "inline-flex", alignItems: "center", gap: 9, textDecoration: "none" }}>
              <img src="/logo-white.png" alt="Unbridge" style={{ height: 22, width: "auto", display: "block" }} />
              <span style={{ fontWeight: 700, fontSize: 17, color: "#fff" }}>Unbridge</span>
              <span className="docs-tag">Docs</span>
            </Link>
          </div>
          <button className="docs-search-btn" onClick={() => setSearchOpen(true)}>
            <Search size={16} />
            <span>Search documentation</span>
            <kbd>⌘K</kbd>
          </button>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <a href="https://github.com/unbridgeDev/unbridge" target="_blank" rel="noreferrer" className="docs-ghost">GitHub</a>
            <a href="/app" className="docs-launch">Launch App <ArrowUpRight size={15} /></a>
          </div>
        </div>
      </header>

      <div className="docs-body">
        <aside className={`docs-nav ${navOpen ? "open" : ""}`}>
          <div className="docs-nav-bg" aria-hidden>
            <UnicornBg />
            <div className="docs-nav-veil" />
          </div>
          <div className="docs-nav-inner">
          <button className="docs-search-btn mobile" onClick={() => setSearchOpen(true)}>
            <Search size={16} /><span>Search</span><kbd>⌘K</kbd>
          </button>
          {GROUPS.map((g) => (
            <div key={g.label} className="docs-nav-group">
              <div className="docs-nav-label">{g.label}</div>
              {g.slugs.map((slug) => {
                const pi = idxOf(slug)
                if (pi < 0) return null
                const Icon = ICONS[slug] ?? BookOpen
                const on = pi === active
                return (
                  <button key={slug} className={`docs-nav-item ${on ? "on" : ""}`} onClick={() => openPage(pi, null)}>
                    <Icon size={17} />
                    <span>{DOCS_PAGES[pi].title}</span>
                  </button>
                )
              })}
            </div>
          ))}
          </div>
        </aside>

        {navOpen && <div className="docs-scrim" onClick={() => setNavOpen(false)} />}

        <main className="docs-main">
          <div className="docs-crumbs">
            <span>Docs</span>
            <ChevronRight size={14} />
            <span style={{ color: "#fff" }}>{page.title}</span>
          </div>
          <article className="docs-prose">
            <ReactMarkdown
              remarkPlugins={[remarkGfm]}
              components={{
                h1: H(1), h2: H(2), h3: H(3),
                code({ className, children, ...rest }) {
                  if (isMermaid(className)) return <Mermaid chart={String(children).trim()} />
                  return <code className={className} {...rest}>{children}</code>
                },
                pre({ children }) {
                  const child = Array.isArray(children) ? children[0] : children
                  const cls = (child as { props?: { className?: unknown } })?.props?.className
                  if (isMermaid(cls)) return <>{children}</>
                  return <pre>{children}</pre>
                },
              }}
            >
              {page.body}
            </ReactMarkdown>
          </article>

          <nav className="docs-pager">
            {active > 0 ? (
              <button className="docs-pager-btn prev" onClick={() => openPage(active - 1, null)}>
                <span className="docs-pager-dir">Previous</span>
                <span className="docs-pager-title">{DOCS_PAGES[active - 1].title}</span>
              </button>
            ) : <span />}
            {active < DOCS_PAGES.length - 1 ? (
              <button className="docs-pager-btn next" onClick={() => openPage(active + 1, null)}>
                <span className="docs-pager-dir">Next</span>
                <span className="docs-pager-title">{DOCS_PAGES[active + 1].title}</span>
              </button>
            ) : <span />}
          </nav>
        </main>

        <aside className="docs-toc">
          {toc.length > 0 && (
            <>
              <div className="docs-toc-label"><Hash size={13} /> On this page</div>
              {toc.map((h) => (
                <a
                  key={h.id}
                  href={`#${h.id}`}
                  className={`docs-toc-item ${activeId === h.id ? "on" : ""}`}
                  style={{ paddingLeft: h.depth === 3 ? 22 : 10 }}
                  onClick={(e) => { e.preventDefault(); document.getElementById(h.id)?.scrollIntoView({ block: "start" }) }}
                >
                  {h.text}
                </a>
              ))}
            </>
          )}
        </aside>
      </div>

      {searchOpen && (
        <div className="docs-search-overlay" onClick={() => setSearchOpen(false)}>
          <div className="docs-search-panel" onClick={(e) => e.stopPropagation()}>
            <div className="docs-search-in">
              <Search size={18} color={ACCENT_TEXT} />
              <input
                ref={searchRef}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search the docs"
                onKeyDown={(e) => {
                  if (e.key === "ArrowDown") { e.preventDefault(); setSel((s) => Math.min(s + 1, results.length - 1)) }
                  if (e.key === "ArrowUp") { e.preventDefault(); setSel((s) => Math.max(s - 1, 0)) }
                  if (e.key === "Enter" && results[sel]) openPage(results[sel].pi, results[sel].id)
                }}
              />
              <kbd>Esc</kbd>
            </div>
            <div className="docs-search-results">
              {results.length === 0 && <div className="docs-search-empty">No results for “{query}”.</div>}
              {results.map((r, i) => {
                const Icon = ICONS[DOCS_PAGES[r.pi].slug] ?? BookOpen
                return (
                  <button
                    key={i}
                    className={`docs-search-row ${i === sel ? "on" : ""}`}
                    onMouseEnter={() => setSel(i)}
                    onClick={() => openPage(r.pi, r.id)}
                  >
                    <Icon size={17} />
                    <span className="docs-search-text">
                      <span className="t">{r.title}</span>
                      {r.sub && <span className="s">{r.sub}</span>}
                    </span>
                    <CornerDownLeft size={15} className="docs-search-enter" />
                  </button>
                )
              })}
            </div>
          </div>
        </div>
      )}

      <style>{docsCss}</style>
    </div>
  )
}

const docsCss = `
.docs-root { min-height: 100vh; background: #060606;
  color: #eef2f6; font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }

/* ambient scene: confined to the menu rail, moody at the top, dark toward the items */
.docs-nav-bg { position: absolute; inset: 0; z-index: 0; pointer-events: none; }
.docs-nav-veil { position: absolute; inset: 0; background:
  linear-gradient(180deg, rgba(8,6,14,0.45) 0%, rgba(8,6,14,0.74) 52%, rgba(8,6,14,0.92) 100%); }
.docs-nav-inner { position: relative; z-index: 1; }

/* header */
.docs-header { position: sticky; top: 0; z-index: 40; background: rgba(6,6,6,0.72);
  backdrop-filter: blur(14px); border-bottom: 1px solid rgba(255,255,255,0.08); }
.docs-header-in { max-width: 1600px; margin: 0 auto; height: 62px; padding: 0 22px;
  display: flex; align-items: center; justify-content: space-between; gap: 20px; }
.docs-tag { font-size: 12px; font-weight: 700; letter-spacing: 0.04em; color: ${ACCENT_TEXT};
  border: 1px solid rgba(139,92,246,0.4); border-radius: 6px; padding: 2px 7px; }
.docs-burger { display: none; background: none; border: none; color: #fff; cursor: pointer; padding: 4px; }
.docs-search-btn { flex: 0 1 420px; display: flex; align-items: center; gap: 10px;
  height: 38px; padding: 0 12px; border-radius: 9px; border: 1px solid rgba(255,255,255,0.1);
  background: rgba(255,255,255,0.03); color: rgba(255,255,255,0.5); font-size: 15px; cursor: pointer; }
.docs-search-btn:hover { border-color: rgba(139,92,246,0.5); color: rgba(255,255,255,0.72); }
.docs-search-btn span { flex: 1; text-align: left; }
.docs-search-btn kbd, .docs-search-in kbd { font-family: inherit; font-size: 12px; font-weight: 600;
  color: rgba(255,255,255,0.55); background: rgba(255,255,255,0.07); border: 1px solid rgba(255,255,255,0.1);
  border-radius: 5px; padding: 2px 6px; }
.docs-search-btn.mobile { display: none; }
.docs-ghost { font-size: 15px; color: rgba(255,255,255,0.66); text-decoration: none; padding: 8px 12px; }
.docs-ghost:hover { color: #fff; }
.docs-launch { display: inline-flex; align-items: center; gap: 6px; font-size: 15px; font-weight: 600;
  color: #fff; text-decoration: none; background: #7C3AED; padding: 9px 15px; border-radius: 9px; }
.docs-launch:hover { background: #6d28d9; }

/* layout */
.docs-body { position: relative; z-index: 1; max-width: 1600px; margin: 0 auto; display: grid;
  grid-template-columns: 264px minmax(0,1fr) 232px; gap: 0; align-items: start; }
.docs-nav { position: sticky; top: 62px; height: calc(100vh - 62px); overflow: hidden auto;
  padding: 26px 16px 40px; border-right: 1px solid rgba(255,255,255,0.06); background: #08060e; }
.docs-nav-group { margin-bottom: 26px; }
.docs-nav-label { font-size: 12px; font-weight: 700; letter-spacing: 0.09em; text-transform: uppercase;
  color: rgba(255,255,255,0.4); padding: 0 10px 10px; }
.docs-nav-item { width: 100%; display: flex; align-items: center; gap: 11px; padding: 8px 10px;
  border: none; background: none; color: rgba(255,255,255,0.66); font-size: 15px; font-family: inherit;
  cursor: pointer; border-radius: 8px; text-align: left; line-height: 1.3; }
.docs-nav-item svg { flex: 0 0 auto; color: rgba(255,255,255,0.42); }
.docs-nav-item:hover { background: rgba(255,255,255,0.04); color: #fff; }
.docs-nav-item.on { background: rgba(139,92,246,0.14); color: #fff; }
.docs-nav-item.on svg { color: ${ACCENT_TEXT}; }

.docs-main { min-width: 0; padding: 40px 56px 100px; }
.docs-crumbs { display: flex; align-items: center; gap: 7px; font-size: 14px;
  color: rgba(255,255,255,0.45); margin-bottom: 26px; }

.docs-toc { position: sticky; top: 62px; height: calc(100vh - 62px); overflow-y: auto; padding: 34px 20px; }
.docs-toc-label { display: flex; align-items: center; gap: 7px; font-size: 12px; font-weight: 700;
  letter-spacing: 0.06em; text-transform: uppercase; color: rgba(255,255,255,0.4); margin-bottom: 14px; }
.docs-toc-item { display: block; padding: 6px 10px; font-size: 14px; line-height: 1.35;
  color: rgba(255,255,255,0.55); text-decoration: none; border-left: 2px solid transparent; }
.docs-toc-item:hover { color: #fff; }
.docs-toc-item.on { color: ${ACCENT_TEXT}; border-left-color: ${ACCENT}; }

/* prose */
.docs-prose { max-width: 760px; font-size: 17px; }
.docs-prose > :first-child { margin-top: 0; }
.docs-prose h1 { font-size: 40px; font-weight: 800; letter-spacing: -0.03em; line-height: 1.1; margin: 0 0 20px; scroll-margin-top: 84px; }
.docs-prose h2 { font-size: 26px; font-weight: 700; letter-spacing: -0.02em; margin: 52px 0 16px;
  padding-top: 14px; border-top: 1px solid rgba(255,255,255,0.07); scroll-margin-top: 84px; }
.docs-prose h3 { font-size: 20px; font-weight: 650; margin: 32px 0 12px; color: #fff; scroll-margin-top: 84px; }
.docs-prose p { font-size: 17px; line-height: 1.75; color: rgba(255,255,255,0.76); margin: 0 0 18px; }
.docs-prose a { color: ${ACCENT_TEXT}; text-decoration: none; border-bottom: 1px solid rgba(167,139,250,0.35); }
.docs-prose a:hover { border-bottom-color: ${ACCENT_TEXT}; }
.docs-prose strong { color: #fff; font-weight: 700; }
.docs-prose ul, .docs-prose ol { margin: 0 0 18px; padding-left: 4px; }
.docs-prose li { font-size: 17px; line-height: 1.7; color: rgba(255,255,255,0.76); margin: 0 0 9px 22px; }
.docs-prose ul li { list-style: none; position: relative; }
.docs-prose ul li::before { content: ""; position: absolute; left: -18px; top: 12px; width: 6px; height: 6px;
  border-radius: 50%; background: ${ACCENT}; }
.docs-prose ol li { list-style: decimal; }
.docs-prose code { font-family: "SFMono-Regular", ui-monospace, Menlo, monospace; font-size: 14.5px;
  background: rgba(139,92,246,0.12); color: #d6c8ff; padding: 2px 6px; border-radius: 6px; }
.docs-prose pre { background: #0c0c11; border: 1px solid rgba(255,255,255,0.09); border-radius: 12px;
  padding: 18px 20px; overflow-x: auto; margin: 0 0 22px; }
.docs-prose pre code { background: none; color: #cdd6e4; padding: 0; font-size: 14px; line-height: 1.65; }
.docs-prose blockquote { margin: 0 0 20px; padding: 14px 18px; border: 1px solid rgba(139,92,246,0.28);
  border-left: 3px solid ${ACCENT}; border-radius: 0 10px 10px 0; background: rgba(139,92,246,0.06);
  color: rgba(255,255,255,0.82); font-size: 16px; }
.docs-prose blockquote p { margin: 0; color: inherit; }
.docs-prose table { border-collapse: collapse; width: 100%; margin: 0 0 22px; font-size: 15px; display: block; overflow-x: auto; }
.docs-prose th, .docs-prose td { border: 1px solid rgba(255,255,255,0.1); padding: 10px 14px; text-align: left; }
.docs-prose th { background: rgba(255,255,255,0.04); font-weight: 700; color: #fff; }
.docs-prose td { color: rgba(255,255,255,0.72); }
.docs-prose hr { border: none; border-top: 1px solid rgba(255,255,255,0.08); margin: 40px 0; }
.docs-prose img { max-width: 100%; height: auto; display: block; margin: 0 0 24px;
  border: 1px solid rgba(255,255,255,0.09); border-radius: 14px; }

/* mermaid diagrams */
.mermaid-diagram { margin: 0 0 24px; padding: 22px; background: #0c0c11;
  border: 1px solid rgba(255,255,255,0.09); border-radius: 14px; overflow-x: auto; text-align: center; }
.mermaid-diagram svg { max-width: 100%; height: auto; }
.mermaid-loading { margin: 0 0 24px; padding: 30px; background: #0c0c11; border: 1px solid rgba(255,255,255,0.09);
  border-radius: 14px; color: rgba(255,255,255,0.4); font-size: 14px; text-align: center; }
.mermaid-err { background: #17090c; border: 1px solid rgba(255,90,90,0.3); border-radius: 12px;
  padding: 16px; color: #ffb4b4; font-size: 13px; white-space: pre-wrap; }

/* pager */
.docs-pager { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 64px;
  padding-top: 32px; border-top: 1px solid rgba(255,255,255,0.08); max-width: 760px; }
.docs-pager-btn { display: flex; flex-direction: column; gap: 5px; padding: 16px 18px;
  border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; background: rgba(255,255,255,0.02);
  cursor: pointer; font-family: inherit; }
.docs-pager-btn.next { align-items: flex-end; text-align: right; }
.docs-pager-btn:hover { border-color: rgba(139,92,246,0.5); background: rgba(139,92,246,0.05); }
.docs-pager-dir { font-size: 13px; color: rgba(255,255,255,0.45); }
.docs-pager-title { font-size: 16px; font-weight: 650; color: #fff; }

/* search modal */
.docs-search-overlay { position: fixed; inset: 0; z-index: 60; background: rgba(4,4,6,0.66);
  backdrop-filter: blur(4px); display: flex; align-items: flex-start; justify-content: center; padding: 12vh 20px 20px; }
.docs-search-panel { width: 100%; max-width: 620px; background: #0f0f14;
  border: 1px solid rgba(255,255,255,0.12); border-radius: 16px; overflow: hidden;
  box-shadow: 0 24px 70px rgba(0,0,0,0.6); }
.docs-search-in { display: flex; align-items: center; gap: 12px; padding: 16px 18px;
  border-bottom: 1px solid rgba(255,255,255,0.08); }
.docs-search-in input { flex: 1; background: none; border: none; outline: none; color: #fff;
  font-size: 18px; font-family: inherit; }
.docs-search-in input::placeholder { color: rgba(255,255,255,0.38); }
.docs-search-results { max-height: 52vh; overflow-y: auto; padding: 8px; }
.docs-search-empty { padding: 26px 14px; text-align: center; color: rgba(255,255,255,0.45); font-size: 15px; }
.docs-search-row { width: 100%; display: flex; align-items: center; gap: 13px; padding: 11px 14px;
  border: none; background: none; border-radius: 10px; cursor: pointer; text-align: left; font-family: inherit; }
.docs-search-row svg:first-child { flex: 0 0 auto; color: rgba(255,255,255,0.5); }
.docs-search-row.on { background: rgba(139,92,246,0.16); }
.docs-search-row.on svg:first-child { color: ${ACCENT_TEXT}; }
.docs-search-text { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 2px; }
.docs-search-text .t { font-size: 15.5px; font-weight: 600; color: #fff; }
.docs-search-text .s { font-size: 13.5px; color: rgba(255,255,255,0.5); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.docs-search-enter { color: rgba(255,255,255,0.3); flex: 0 0 auto; opacity: 0; }
.docs-search-row.on .docs-search-enter { opacity: 1; }

.docs-scrim { display: none; }

@media (max-width: 1180px) {
  .docs-body { grid-template-columns: 244px minmax(0,1fr); }
  .docs-toc { display: none; }
  .docs-main { padding: 36px 40px 90px; }
}
@media (max-width: 860px) {
  .docs-header .docs-search-btn { display: none; }
  .docs-burger { display: inline-flex; }
  .docs-ghost { display: none; }
  .docs-search-btn.mobile { display: flex; width: 100%; margin-bottom: 22px; }
  .docs-body { display: block; }
  .docs-nav { position: fixed; top: 62px; left: 0; bottom: 0; width: 280px; z-index: 45;
    background: #0a0a0e; transform: translateX(-100%); transition: transform 0.22s ease; }
  .docs-nav.open { transform: translateX(0); }
  .docs-scrim { display: block; position: fixed; inset: 62px 0 0; z-index: 44; background: rgba(0,0,0,0.5); }
  .docs-main { padding: 28px 22px 80px; }
  .docs-pager { grid-template-columns: 1fr; }
  .docs-tag { display: none; }
  .docs-launch { white-space: nowrap; padding: 8px 13px; font-size: 14px; }
  .docs-header-in { gap: 12px; padding: 0 16px; }
}`
