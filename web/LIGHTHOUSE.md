# Lighthouse

Landing (/) — desktop:

- performance: 91/100
- accessibility: 100/100
- best-practices: 100/100
- seo: 100/100

Docs (/docs) — desktop:

- accessibility: 96/100
- best-practices: 100/100
- seo: 100/100

Perf note: FCP, TBT, CLS, Speed Index are all excellent; the heavy R3F hero is
deferred to requestIdleCallback over an instant gradient poster, and the LCP
headline entrance is a CSS keyframe (not framer), so it paints on the first
frame. Pinning the html/body background to #060606 (the site is dark-only)
removed a white-flash on overscroll and helped paint stability. Reaching a
higher performance number would require porting the remaining framer-motion
animations (Counter / Reveal / FAQ / the scroll-driven flow rail and latency
bars) to CSS; per the brief the animations are NOT degraded to chase the number.
