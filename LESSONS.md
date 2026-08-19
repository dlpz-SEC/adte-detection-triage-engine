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

---

### 2026-07-22 — A subagent's negative finding is only as wide as the scope you gave it

**Rule:** When a verification/search agent reports something is **absent** ("no support for this
claim", "no such usage", "unsupported"), the finding is bounded by the files that agent could see —
never promote a scoped negative to a global one. Confirm the negative against the full corpus
before acting on it, especially when the claim could legitimately live in a sibling repo/module the
agent wasn't given.

A resume-accuracy agent scoped to the ADTE repo declared the "KQL" and "GitHub Actions CI" bullets
**unsupported** — and it was right *about ADTE*. But both are real in other portfolio repos
(`detection-as-code` has the CI workflow; the SQL threat-hunting lab has 7 `.kql` files). Acting on
the agent's negative would have deleted true, defensible resume claims. A positive finding ("here it
is, at file:line") is self-validating; a negative one carries the search boundary as an invisible
premise. This is the same failure mode as the 2026-07-16 diagnosis lesson — an internally-coherent
result that is wrong because of what was outside the frame.

---

### 2026-07-22 — Probe the live auth surface before writing "click here to try it"

**Rule:** Before documenting a deployed demo as interactive ("click here and run it"), probe the
live auth surface anonymously first — hit the actual endpoints a first-time visitor would, un-keyed,
and see what returns 200 vs 401/403. Write the invitation to match what an anonymous visitor can
*actually* do, not what you (an authenticated operator) can do.

The first README pass this session promised a working triage demo that the login wall blocked. A
live probe (anonymous `POST /api/triage` → **401**) showed only the SPA shell and `/api/examples`
are open to an anonymous visitor; running triage needs a key. The fix was both to correct the copy
*and* to hand the recruiter a passkey inline — but the copy would have shipped a broken promise if
the live surface hadn't been probed. Deployed auth posture is empirical; never infer it from the
code you remember writing.

---

### 2026-07-22 — String/quoting syntax must match the TOOL you're calling, not the host OS

**Rule:** This box exposes two shells — the Bash tool (POSIX sh) and the PowerShell tool. Multi-line
strings, here-docs, and quoting must use the syntax of the *tool you're invoking*, not the syntax of
the underlying OS. On Windows it is tempting to reach for PowerShell idioms in the Bash tool; they
mangle silently.

The first commit this session used a PowerShell here-string (`@'…'@`) as a `git commit -m` body
*inside the Bash tool*. Bash doesn't parse `@'…'@`, so the message came out mangled; it had to be
repaired with `git commit --amend` before the push. For a Bash-tool multi-line commit message use a
heredoc (`git commit -m "$(cat <<'EOF' … EOF)"`) or repeated `-m` flags; reserve `@'…'@` for the
PowerShell tool. The OS is Windows either way — the deciding factor is which tool the call routes
through.

---

### 2026-08-16 — Verify a subagent's proposed FIX against the tests, not just its finding

**Rule:** An adversarial/review workflow hands you plausible findings AND plausible remediations,
and a proposed fix carries the same "internally-coherent yet wrong" risk as a finding. Before
shipping any agent-proposed fix — especially to a golden-pinned or correlation subsystem — trace it
against the real test suite and the demo showcase. A fix that reads as free hardening can be a
regression; a positive fix is not self-validating.

Triaging ADTE's Phase-32 findings, the agents' F5 remediation (gate hash-correlation on per-event
maliciousness) looked like clean, no-waiver hardening. Checked against the suite it would have
fragmented the legitimate 554→87105→553 FIM malware trio (`tests/test_file_integration.py:185-193`
pins the three events to one case): only the VT-conviction event carries a maliciousness signal, so
a benign vendor-patch false positive and a real multi-event malware incident are indistinguishable
at the individual-event level — the gate cannot separate them without a regression. Same failure
family as the 2026-07-22 negative-finding lesson, now extended to *proposed fixes*: run the agent's
fix against the tests before you believe it.

---

### 2026-08-16 — Anchor validation regexes with \A/\Z, never ^/$

**Rule:** In Python, `$` matches *before a trailing newline*, so `re.match(r"^...$", "value\n")`
accepts input a strict validator must reject. Any security-relevant format validator (GUIDs, IDs
interpolated into URLs/paths, allowlist patterns) must anchor with `\Z` (or use `re.fullmatch`),
never `$`.

Caught by the new Sentinel adapter's own test suite: the GUID path-injection guard used `^...$`
and a GUID plus `\n` sailed through (`re.match` + `$` → matched before the newline). One character
of injection surface on values interpolated into fixed-host URLs. Fixed to `\Z`; the parametrized
malformed-input test now pins it. Write the trailing-newline case into every validator's tests —
it is the canonical bypass for `$`-anchored patterns.

---

### 2026-08-16 — An empty workflow result with errored agents is not a clean pass

**Rule:** A multi-agent workflow that returns a well-formed empty result (`0 findings, 0 refuted`)
while its `<failures>`/`agents_error` count is non-zero has performed **zero** review — the empty
result is the absence of reviewers, not the absence of defects. Check the failure/agents_done
counts BEFORE interpreting any aggregate result; if the agents died (session limit, timeout),
either re-run or do the review inline yourself, and salvage the dead agents' partial transcripts
for leads.

The Sentinel-adapter review workflow returned `{confirmed: [], refutedCount: 0}` — structurally a
perfect pass — because all 3 finder agents hit the session usage limit and errored before
returning. Treated as a pass it would have skipped review entirely. Sibling of the 2026-07-22
subagent-scope lesson (a negative finding is only as wide as the scope that RAN — here, zero) and
Phase 31's verify-agents-died miscount; this variant is specifically about aggregate emptiness
masking total reviewer failure.

---

### 2026-08-18 — Read the governing plan file before advising inside its scope

**Rule:** When a plan file governs the work, grep it for the decision *before* recommending
anything in its domain. A plan that records an option as considered-and-rejected outranks fresh
reasoning, and a requirement written in the plan is not optional context to re-derive from first
principles.

Spent several turns recommending a standalone Entra ID P2 trial as the cheaper, more surgical
alternative to Microsoft 365 E5. The child plan already said, at line 20–21: *"M365 E5 30-day
trial for Entra P1/P2 (**not the standalone Entra P2 trial this session recommended**)"* — the
exact option, already weighed and overruled, with my prior recommendation named in the rejection.
Same file, same session: I specified `incident creation ON` for the analytics rule but omitted
`alert grouping ON`, which line 141 states outright (*"incident creation ON + alert grouping ON
or `SecurityIncident` stays empty"*) — an omission that would have produced firing alerts, an
empty incident table, and an hour spent debugging the adapter over a rule setting. One root
cause behind both: advising in the plan's domain without opening the plan. The reasoning felt
sound each time; the plan had already been there and disagreed.

---

### 2026-08-18 — When enforcing a plan constraint, check whether its rationale is still live

**Rule:** A constraint's letter can keep matching after its purpose is spent. Before invoking
"the plan says don't," name what the rule protects and check whether that thing is still
protectable. Over-correcting into rigid compliance after being caught improvising is a second
failure, not a return to safety.

After being corrected for running week-6 work (A1 live wiring) during week 1, I told David to
stop and revert to housekeeping, citing the plan's week-1 "no clocks started" rule. But that
rule exists to prevent *deploying the Sentinel workspace* — which had already happened before
the session began. The 31-day clock was burning regardless of anything done that evening,
~19 spare workspace trials remained, and finishing the work retired precisely the week-6
blow-up scenario the plan's own risk table names ("adapter blocked on live shape surprises").
David pushed back and was correct. Swinging from improvising past the plan to reciting it was
two errors, not one correction followed by compliance.

---

### 2026-08-18 — In Azure/Sentinel, "Connected" is plumbing status, not evidence of data

**Rule:** A connector showing **Connected** means the wiring is attached — not that a licence
entitles the data, nor that any has arrived. Verify presence by querying, never by reading a
status column:
`union withsource=TableName * | where TimeGenerated > ago(24h) | summarize Count=count() by TableName | sort by Count desc`
Also check the blade's active filters before concluding content is missing.

`law-sc200-sentinel` displayed **7 connectors, 7 Connected** — Defender for Endpoint, Defender
for Identity, Defender for Cloud Apps, Entra ID Protection among them — on a workspace with zero
ingestion and $0.00 cost. Every one was licence-gated and dry: the tenant held only Microsoft
Entra ID **Free** and **Office 365** E5 (not Microsoft 365 E5), so none of those products were
entitled. Seven green rows read convincingly as "set up." Separately, the Data connectors blade
defaulted to a `Status: Connected` filter that hid every unconfigured connector, making the
catalogue look nearly empty when it was merely filtered.

---

### 2026-08-18 — An Azure budget alert is not a spending cap

**Rule:** Azure Cost Management **budgets only notify** at their thresholds; spend continues
straight past them. The control that actually halts ingestion is the Log Analytics workspace
**daily cap** (workspace → Usage and estimated costs → Daily cap). Different blade, different
mechanism. Setting the budget and believing you are capped is the dangerous state — a smoke
detector is not a sprinkler.

Surfaced while standing up the Sentinel lab on an **Azure Plan** (MCA pay-as-you-go) subscription
— which, unlike an Azure Free subscription, carries no free-credit buffer, so consumption bills
directly to the payment profile. Both controls are cheap; only one of them stops anything.

---

### 2026-08-18 — Split "not generated" from "not delivered" before debugging a telemetry pipeline

**Rule:** When expected data is missing at a SIEM or log destination, the first move is to confirm
the events exist **at the source**, not to keep inspecting the destination. Every pipeline has a
source-side view independent of the delivery path — Azure's Monitor → Activity log, Wazuh's own
alert log, the Windows event channel. Checking it splits one unknown into two, and the two have
entirely different fixes.

Spent a long stretch of the Sentinel wiring session querying `AzureActivity` in Log Analytics,
getting zero, waiting, generating another event, and querying again — without once opening
**Monitor → Activity log**, the portal view of those same events *before* they enter the export
path. Three plausible causes (nothing generated / not exported / not yet ingested) stayed
collapsed into a single symptom the entire time, so every action taken was a guess across all
three. Companion trap from the same night: **diagnostic settings are not retroactive** and take
10–15 minutes to activate, so any event fired inside that window is lost permanently — establish
that before concluding a setting is misconfigured.

---

### 2026-08-18 — A bare `summarize` always returns one row; row count is not record count

**Rule:** `summarize Records = count()` with no `by` clause emits exactly one row even over an
empty table. A results pane reading **"1 – 1 of 1"** therefore means one *summary* row was
produced, not that one record exists. Read the value in the cell, never the row counter; a null in
a companion `min()`/`max()` column is the corroborating tell that the input was empty. When an
unambiguous answer matters more than a guaranteed row, use `TableName | count` — one column, one
number, nothing to misread.

Caused a wrong read during the Sentinel wiring session: `AzureActivity | summarize
Records=count(), Earliest=min(TimeGenerated)` returned `Records 0` with a blank `Earliest`, and
the "1 – 1 of 1" footer was taken as evidence that data had arrived. Building the analytics rule
on that reading would have produced a rule that silently never fires — the most expensive failure
available at that step, because it is indistinguishable from "still waiting for the schedule."

---

### 2026-08-18 — `python -m package.module` with no `__main__` guard is a silent no-op that exits 0

**Rule:** Zero output plus exit 0 from `python -m <pkg>.<module>` can mean the module was merely
imported and nothing ran — a missing `if __name__ == "__main__":` guard produces a perfect false
pass. Before trusting any CLI invocation's clean exit, confirm the entry point actually executes
(`python -m <pkg>` via `__main__.py`, or the console script). The tell: a command that should
always print *something* (an error, a usage line, a result) printing nothing at all.

The prior session's Handoff recorded the smoke test as `python -m adte.cli --source sentinel`.
That command exits 0 silently — `adte/cli.py` has no main guard; the real entry points are
`python -m adte triage ...` (via `adte/__main__.py`) and the `adte` console script. Run as
written, it would have been read as "adapter authenticated fine, workspace just empty" while the
client secret was in fact invalid — a false pass stacked directly on top of the real bug.

---

### 2026-08-18 — A mocked-HTTP test suite cannot validate a hardcoded cloud audience; smoke live before claiming an adapter works

**Rule:** Any hardcoded external endpoint, token audience, or scope string is unverifiable by
tests that mock the transport — 70 green adapter tests said nothing about whether the string was
one Azure would accept. Until an adapter has made one real call, "tested" means "the code around
the constants is tested." Budget a live smoke as part of shipping, and when a supposedly
identical request succeeds where another fails, **diff the two requests field by field** before
reaching for temporal explanations — a deterministic failure on repeat rules out propagation,
caching, and "wait longer."

The Sentinel adapter shipped with `_SCOPE = "https://api.loganalytics.azure.com/.default"`;
David's tenant does not hold that resource principal (`AADSTS500011`), while the classic
`api.loganalytics.io` audience works and both query hosts accept its tokens. The first live 400
was misread as new-secret propagation delay; the second, identical 400 disproved that, and the
actual difference was that the working probe had used the `.io` scope all along. Fixed under
waiver (one constant, commit `666e755`) after proving the full path live: token → workspace
query via the adapter's own KQL → 200 with 0 rows.

---

### 2026-08-18 — Azure client secret: the Value is shown once; a GUID in a secret field means the wrong column was copied

**Rule:** An Azure app-registration client secret has two columns: **Value** (~40 chars, mixed
symbols, usually contains `~`) is the credential; **Secret ID** (a 36-char GUID) is a label that
authenticates nothing. The Value is retrievable only at creation — no later blade shows it, so a
suspected-bad stored secret is never "checked in the portal," it is replaced (10 seconds, new
secret, delete the old). Diagnostics: a stored "secret" that is 36 chars with hyphens IS the
Secret ID; other lengths suggest a truncated paste; `AADSTS7000215` is the token endpoint saying
exactly this.

The `.env` from the prior session held an 18-character fragment — flagged on length alone at
session start, confirmed by `AADSTS7000215`, whose message literally warns about the
Value/Secret-ID mix-up. Fixed by minting a new secret and copying the Value column.

---

### 2026-08-18 — Two identical failed UI actions mean switch strategy; for Azure config, Cloud Shell + `az rest` beats driving the portal

**Rule:** When the same UI action fails twice the same way (click lands, page doesn't change;
URL navigation bounces back), the third identical attempt is already a loop — stop and change
layer, don't change coordinates. For Azure specifically, the reliable escape hatch is
**shell.azure.com + `az rest`**: pre-authenticated as the signed-in user, no local install, no
storage account in ephemeral mode, and one PUT with an explicit JSON body both creates the
resource and **echoes back the server-stored state** — configuration and verification in a
single step, immune to portal blade redirects, SPA click interception, and licensing-gated UI.

Driving the Defender portal to Sentinel → Configuration → Analytics, the direct URL
(`/sentinel/analytics`) redirected to Settings → SIEM workspaces every time, and clicking the
nav item showed its tooltip but never navigated. Five-plus attempts (coordinates, refs, SPA
click, full-load URL, re-expanding the collapsed tree) burned ~15 minutes; the user called out
the loop — "you weren't going to figure it out" — and was right. The pivot took one paste: a
scheduled analytics rule with incident creation, alert grouping, entity mappings, and ATT&CK
tags landed via a single `az rest --method PUT`, and the echoed JSON proved every field. The
incident fired five minutes later. Portal UI is for humans; the management plane is for
automation — start at the API when the task is "create a resource with exact settings."
