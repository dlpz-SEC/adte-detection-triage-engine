# ADTE — Lessons

Durable, reusable rules distilled from sessions. One entry per lesson, dated, with a one-line rule.

---

### 2026-06-21 — Bundling React with esbuild needs an explicit NODE_ENV define

**Rule:** When bundling React/ReactDOM with esbuild for the browser, always pass
`define: { "process.env.NODE_ENV": '"production"' }` (or `"development"`). Without it the browser has
no `process`, and React's event delegation **fails silently** — components render but no `onClick`/
state updates ever fire (handlers are attached, just never invoked). It looks like a dead UI with no
console error.

**How it surfaced:** the standalone `docs/blueprint.html` rendered all 9 layers but every click did
nothing. Diagnosis was slowed because `preview_console_logs` showed stale `reading 'x'` errors from a
prior broken build; the real signal came from an injected `window.onerror` catcher (0 errors after the
define) and from calling a node's `__reactProps$…onClick` directly (worked) vs. a real click (didn't).

**Corollary (preview harness):** for a clean-error check, inject a `window.onerror` catcher and read it
after reload — don't trust `preview_console_logs` (cumulative, survives reloads). `preview_screenshot`
can hang on heavy single-file React pages; verify via `preview_eval` DOM/geometry assertions instead.
