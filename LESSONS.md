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

---

### 2026-07-11 — A workflow's own result summary can miscount agents that errored out

**Rule:** When an adversarial-review (or any fan-out) Workflow hits the session token limit or a
mid-response API drop, individual agents fail — but the script's post-processing may bucket a
finding whose *verifier* died as "refuted" (verdict absent → not `refuted === false`), silently
discarding real findings. The tell: the `<failures>` list names `find:*`/`verify:*` agents and
`agents_error > 0`. Don't trust the confirmed/refuted tally when agents errored. Distinguish
`unverified` (verdict null) from `refuted` (verdict.refuted === true) in the script, and re-run
the dead dimensions in a follow-up workflow before believing "0 confirmed." Round 1 of the
Phase-30 review lost 2 finder dimensions + 6 verifiers this way; round 2 surfaced 7 more real
findings the truncated round would have implied didn't exist.

---

### 2026-07-12 — Add an aggravator signal additively, not by share-renormalization

**Rule:** When adding a new signal to a weighted 0-100 scorer where the signal is meant to
only *raise* risk (an aggravator — correlation context, reputation, etc.), add its points on
top (`risk = min(100, core + points)`), do NOT grow the denominator and renormalize
(`risk = raw*100/(100+W)`). Share-renormalization is **non-monotonic**: a low-scoring new
signal drops the denominator's fill-ratio, so a strong core score goes DOWN when the signal
fires weakly. Phase 31's first design did exactly this and downgraded the Wazuh skip case
78→67 (high→medium) on a single correlated sibling — correlation *lowering* a verdict.
Additive uplift is monotonic by construction, keeps the existing weights' meaning intact, and
(bonus) leaves the core scoring block literally untouched, shrinking a change-controlled diff.
Reserve share-normalization for signals that can legitimately pull a score in either direction.

---

### 2026-07-12 — Self-exclusion must extend to every derived/cached aggregate, not just the direct query

**Rule:** When a computation deliberately excludes an entity from itself (a re-triaged alert
must not count as its own correlation "sibling"), auditing the direct row query is not enough —
any *pre-aggregated* value read alongside it was computed over the FULL set and silently
re-includes the excluded entity. Phase 31's peek self-excluded the incident from
sibling_count/tactics/max-risk (per-row `WHERE incident_id != ?`) but read `kill_chain_detected`
from the case-level stored blob, which was computed over all members including this one → a
re-triaged member could self-award the +5 kill-chain bonus off its own tactics. Fix: recompute
the aggregate over the self-excluded set, don't read the cached whole-set value. The tell: a
finding says "field X honors the exclusion but field Y (an aggregate/rollup) doesn't."

---

### 2026-07-13 — An optional feature's new output keys must be conditional, or byte-parity dies

**Rule:** When bolting an optional feature onto an existing *serialized* contract (an API response,
an evidence blob, an audit row) while promising "inactive input ⇒ unchanged output", every new key
must be gated on that feature's data actually existing. An unconditional key breaks parity even
when the feature never fires — `{"files": []}` or `{"file_reputation": {}}` is a *different*
serialization from no key at all, so every existing payload's hash changes and the "byte-identical"
claim is false. Phase 32 added file evidence to `_build_evidence()`; emitting the two new keys
unconditionally would have silently broken all four golden examples while the signal itself was
provably inert. The same discipline already holds implicitly for rationale/signal_summary entries
(only registered signals appear) — make it explicit for evidence and any dict you serialize.

Generalises past scoring: the parity contract is over the **serialized bytes**, not over the
feature's logic. "The code path can't run" is necessary but not sufficient — grep for every dict
literal the output is built from. The cheap enforcement is the one that caught nothing here only
because it was designed in up front: hash the full normalized output of known inputs at a rollback
tag, re-hash after each change-controlled batch, and pin the values in a permanent golden test.

---

### 2026-07-13 — React does not sanitize `href`; allowlist scheme AND host for any URL from alert data

**Rule:** React escapes text children, so it is easy to assume rendering untrusted data is safe. It
is not: `href`/`src` are **not** sanitized, so `<a href={untrusted}>` with a `javascript:` URI is
executable on click, and any `https://` URI is a phishing navigation wearing your UI's chrome.
Phase 32 rendered `data.virustotal.permalink` — a field an attacker fully controls, since malware
metadata *is* attacker-authored — straight into an `<a href>` labelled "VirusTotal report". Fix at
the sink: `new URL(raw)`, require `protocol === 'https:'`, require the hostname to be on an
allowlist, render nothing on mismatch or parse failure. Better still, **derive** the URL from an
already-validated field (the hash) instead of accepting the source's string at all.

Two traps this exposed. (1) **CSP is a backstop, not the control.** Here `script-src` without
`'unsafe-inline'` happened to block the `javascript:` escalation — so the bug graded phishing, not
stored XSS. That is luck, and it silently becomes stored XSS the day someone adds `'unsafe-inline'`
for a chart library. (2) **In a security tool, "the SIEM is trusted" is wrong** — the whole payload
describes what an adversary did, and the triage endpoint accepts analyst-pasted JSON. Treat every
alert field as hostile input, and audit the *attack surface* before shipping, not after: functional
tests and byte-parity proofs both passed while this sink was wide open.

---

### 2026-07-16 — Reproducing a mechanism is not confirming a diagnosis

**Rule:** Before fixing a reported symptom, **observe the failing path itself** — one probe of the
actual request beats any amount of plausible theory. A reproduction proves a mechanism *exists*; it
does not prove that mechanism *produced this symptom*. Both can be true at once, and the coherence
of the story is what makes the error invisible.

The queue rendered zeros. The theory: intel keys set → VirusTotal sleeps 15 s/lookup → ~10 IPs →
~150 s → gunicorn `--timeout 60` kills the worker. It was mechanically real — measured 15.0 s per
lookup — so it got fixed and shipped, and the dashboard **still showed zeros**. The actual cause was
a plain `401`: sessions are wiped by every redeploy, and the UI mistranslated auth failure into
"WAZUH UNAVAILABLE". A single `curl /api/queue` would have shown `{"error":"Authentication
required"}` in seconds, before any code was written. The throttle fix was worth keeping — it closed
a real DoS — which is precisely the trap: **a fix that is independently correct feels like
confirmation.** The tell is that the symptom survives the fix; treat that as "the diagnosis was
wrong," not "there must be a second bug."

Corollary for HTTP clients: **a non-2xx response with a JSON body defeats the naive fetch chain.**
`.then(r => r.json())` parses a 401 body happily, `.catch()` never fires (it is not a network
error), and the destructured fields come back `undefined` — so downstream code sees "empty data" and
any `else` branch will confidently narrate a cause it never established. Check `r.status` (or
`r.ok`) before `.json()`, and never let a fallback branch assert *why* data is missing unless it
actually knows.

---

### 2026-07-16 — Document the environment a quoted output value depends on, or it reads as a bug forever

**Rule:** Any concrete value pinned in docs (an example score, a benchmark, a sample response) that
varies with configuration must state the configuration it was captured under. Otherwise every reader
who reproduces it under different config files it as a defect — including your future self.

The README quoted the high-risk example as **79**; the test suite golden-pinned it at **99**. It sat
on the follow-up list for two sessions as a confirmed "doc bug". It was neither: with live
threat-intel keys the fixture's IP is not flagged (0 pts → 79), while the mock feed pins
`198.51.100.23` as known C2 (+20 → 99). Both numbers were correct; only the missing "captured with
mock intel / no API keys" caption was wrong. Prefer quoting the value a **fresh clone with no
credentials** reproduces (that is what a reader gets, and what CI pins), then note the variance.
