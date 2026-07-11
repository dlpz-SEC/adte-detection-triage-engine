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

---

### 2026-07-09 — Module-level singletons + `load_dotenv` defeat per-test env isolation

**Rule:** A conftest that only *pops* env vars (e.g. `ADTE_ABUSEIPDB_KEY`) does NOT guarantee mock
mode. Two things reload real values mid-suite: (1) the first `import adte.server` in any test runs
module-level `load_dotenv()`, repopulating keys from a local `.env`; (2) a module-level singleton
(`_get_aggregator()`) freezes whatever mode it was first built in. Result: a new test file sorted
early alphabetically can flip the whole suite into LIVE threat-intel mode — real API calls, 15s VT
sleeps, non-deterministic results poisoning mock-expecting tests. **Fix:** in the autouse fixture,
after popping keys, also **reset the singleton** to a keyless instance
(`threat_intel._aggregator = ThreatIntelAggregator()`). Any test-order flake that appears only in the
*full* run but not in isolation → suspect a shared module-level singleton or a `.env` reload, not the
new test.

---

### 2026-07-09 — flask-limiter counters span the whole pytest process

**Rule:** flask-limiter's in-memory counters are process-global and cumulative across test files, so
adding tests that POST to a rate-limited route can push *later* files' tests over the limit → spurious
429s. Disable it in the autouse fixture via `server.limiter.enabled = False` — **not**
`app.config["RATELIMIT_ENABLED"] = False` (flask-limiter 3.x reads that only at init, so a runtime set
is ignored). Same class of bug as the singleton above: a failure that only shows in the full-suite run.

---

### 2026-07-09 — Name-reference dead-code scans lie on decorator-heavy code

**Rule:** An AST scan for "functions never referenced by name" flags every Flask route handler,
`before_request`/`after_request` hook, error handler, and pydantic `model_validator` as dead — they're
invoked by decorators/framework, never by name. On this codebase it produced 14 candidates, all false
positives. Trust `ruff --select F401,F811,F841` (imports/redefs/unused-locals) for real dead code;
treat name-reference scans as a hint list to hand-verify, never an auto-delete list.

---

### 2026-07-10 — Module-level state breaks silently under gunicorn --workers N

**Rule:** Any module-level mutable state (a sessions dict, a cache, a counter) is PER-PROCESS.
With `gunicorn --workers 2`, a login stored in worker A's dict is invisible to worker B, so
~half of authenticated requests randomly 401 "Session expired" while `/api/auth-check`
(landing on the right worker) still says logged in. The tell is *intermittent* auth/state
flakiness in production that never reproduces locally (dev server = 1 process). Fix: move the
state to a store all workers share (SQLite table beside the audit log here; Redis at scale) —
and store session tokens hashed, so a DB read can't hijack sessions. Verify with a true
cross-process test: two separate interpreters sharing the DB file, login in one, authenticate
in the other. Locks (`threading.Lock`) do NOT help — they only serialize threads inside one
process.

---

### 2026-07-10 — `load_dotenv(override=True)` at import beats pre-set test env vars

**Rule:** `adte.server` calls `load_dotenv(..., override=True)` at module import, so any env var
you set BEFORE `import adte.server` (test keys, quota overrides) gets silently replaced by the
`.env` value — the tell is "Invalid API key" for a key you just set. In standalone test scripts,
set env vars AFTER the import (conftest's autouse fixture already runs post-import, which is why
pytest never hits this).

---

### 2026-07-10 — Verifying an auth-gated deploy without credentials

**Rule:** When a deploy's only behavioral change is behind login (401 fires before body parsing),
two unauthenticated signals still prove the new build is serving: (1) **new-route probe** — POST
the newly added path; 404 = old build, 401 = new build (the route now exists and answered with
its auth gate); (2) **bundle grep** — `curl .../bundle.js | grep <new code marker>` for frontend
changes. Used together they confirm a Railway deploy end-to-end with zero key handling.
