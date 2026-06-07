# ADTE — Project Progress & Build History

A detailed, chronological account of every major decision, feature, and fix made across the lifetime of this project.

---

## Project Overview

**ADTE (Autonomous Detection & Triage Engine)** is a deterministic, source-agnostic security incident triage engine. It ingests alerts from multiple SIEM sources, normalises them into a common schema, scores across five weighted signals, and produces a structured verdict with per-signal rationale and a recommended action. ADTE recommends, it does not act: it performs no automated containment, and every medium/high verdict is flagged for human review. (Historical note: earlier phases described a six-layer execution-gate model; that unwired execution layer was removed in Phase 23 — see below.)

The engine is not a black box. Every verdict can be fully explained: which signals fired, why, at what confidence, and what the recommended containment action is. Human review is explicitly required for medium and high risk verdicts.

---

## Phase 0 — Initial Commit: Core Engine

**Scope:** Built the complete triage pipeline from scratch.

### Architecture decisions

The fundamental design constraint was **determinism**: the same input must always produce the same output. This ruled out any approach where LLM output influenced the verdict, risk score, or recommended action. The LLM was later added as a display-only narrative layer, explicitly forbidden from feeding back into scoring.

The data model was built around a `NormalizedIncident` Pydantic schema — a source-agnostic representation that any SIEM adapter could produce. The Sentinel adapter was the first implementation, converting Microsoft Sentinel incident JSON into `NormalizedIncident` via `from_sentinel()`.

### Five weighted signals

Signal weights were chosen to reflect real-world detection engineering priorities, not arbitrary values:

| Signal | Weight | Rationale |
|--------|--------|-----------|
| Impossible Travel | 30 | Physically impossible movement is the strongest single indicator of stolen credentials |
| MFA Fatigue | 25 | T1621 push-spray is a well-documented modern credential attack pattern |
| IP Reputation | 20 | Strong signal but NAT/shared infrastructure creates false positives |
| Device Novelty | 15 | First-seen device is moderate signal — not sufficient alone |
| Login Hour Anomaly | 10 | Weakest standalone; adds value as corroboration |

Weights sum to 100. The risk score is the raw weighted sum, clamped to `[0, 100]`.

### Six-layer safety gate system

All automated execution is fail-closed by default. Gates are evaluated in sequence — all six must pass before any action is taken:

1. **Kill Switch** (`ADTE_KILL_SWITCH=true`) — halts everything, no exceptions
2. **Dry Run** (`ADTE_DRY_RUN=true`, default on) — logs actions without executing
3. **Execution Enabled** (`ADTE_EXECUTION_ENABLED=true`) — explicit opt-in required
4. **Tenant Allowlist** — incident tenant must be in `ADTE_TENANT_ALLOWLIST`
5. **User/Severity Gate** — user in allowlist OR severity High/Critical
6. **Action Allowlist** — action type must be in `ADTE_ACTION_ALLOWLIST`

The default configuration blocks all execution. A user must explicitly set at minimum `ADTE_DRY_RUN=false` and `ADTE_EXECUTION_ENABLED=true` to allow any action.

### Verdict thresholds

| Risk Score | Verdict | Action |
|-----------|---------|--------|
| ≥ 70 | `high_risk` | Disable account, revoke sessions, escalate to Tier-2 |
| 30–69 | `medium_risk` | Escalate for analyst review within SLA |
| < 30 | `low_risk` | Auto-close, update baseline |

### Initial test suite

8 test files covering: geo scoring (haversine, travel speed, impossible travel threshold), signal computation, decision policy, safety gate evaluation, LLM assist, engine integration, Wazuh adapter. All tests use deterministic fixtures with no mocking of internal logic.

**Baseline: 161 tests passing.**

---

## Phase 1 — Wazuh Indexer Adapter

**Scope:** Live alert ingestion from a local Wazuh instance (OpenSearch at port 9200).

### Why Wazuh

The initial Sentinel adapter used mock data. Wazuh provides a real, locally-hostable SIEM with an OpenSearch-compatible REST API, making it possible to demonstrate genuine live alert ingestion without Azure credentials.

### Technical implementation

Because Wazuh is locally-hosted infrastructure (requires a running VM), this integration is not publicly demo-able. It is demonstrated through screenshots and the adapter code. This is the intended contrast with the Phase 2 cloud threat intel APIs — AbuseIPDB, VirusTotal, and OTX are free-tier cloud services that any reviewer can configure with their own keys and run live.

The `WazuhAdapter` class connects to the Wazuh Indexer via HTTP Basic Auth, queries the `wazuh-alerts-4.x-*` index using an OpenSearch `POST /_search` body with a timestamp range filter, and paginates through results at 500 records per page.

Wazuh alerts have a fundamentally different structure to Sentinel incidents:

- **No geolocation data** — Wazuh processes host-based and network events but does not enrich with lat/lon coordinates.
- **No MFA events** — Wazuh never records MFA challenge/response sequences.
- **Agent-centric** — the primary entity is the host agent (name, ID, IP), not a user identity.

This required a key architectural change to the scoring engine.

### Signal skip and weight redistribution

When signals cannot be evaluated (no data), naively scoring them as zero would compress the scoring range. If impossible travel (30 pts) and MFA fatigue (25 pts) are both unavailable, the maximum reachable score would be:

```
round(45 raw_pts × 100 / 70 available) = 64  →  medium_risk ceiling, high_risk unreachable
```

The fix: track skipped signals in `_skipped_signals: set[str]` and redistribute their combined weight proportionally across the evaluable signals at scoring time:

```
available_weight = 100 - skipped_weight
risk_score = round(raw_sum * 100 / available_weight)
```

With both signals skipped, effective redistribution becomes `100/45`:
- IP (20) + device (15) fire → `round(35 × 100/45) = 78` → `high_risk` ✓
- IP alone → `round(20 × 100/45) = 44` → `medium_risk` ✓

### CLI additions

`--source wazuh` added to the `triage` command, alongside `--hours` (look-back window) and `--limit` (alert cap with truncation warning). The `--source mock` path is unchanged — existing Sentinel JSON files continue to work identically.

---

## Phase 2 — Multi-Source Threat Intelligence

**Scope:** Replace the deterministic mock threat intel lookup with real live API clients.

### Providers integrated

| Provider | Env Var | Notes |
|----------|---------|-------|
| AbuseIPDB | `ADTE_ABUSEIPDB_KEY` | Confidence score, categories, abuse reports |
| VirusTotal | `ADTE_VT_API_KEY` | Detection ratio across AV engines; 15s inter-request delay for public key rate limits |
| AlienVault OTX | `ADTE_OTX_KEY` | Pulse-based tagging; anonymous access allowed without a key |

### Aggregation logic

When multiple sources are configured, results are merged:

- **Confidence**: averaged across all sources that respond without error.
- **`is_malicious`**: `True` if any source flags the IP, or if average confidence ≥ 0.5.
- **Tags**: merged and deduplicated across all sources.
- **Source field**: comma-joined provider names (e.g. `"abuseipdb,virustotal,otx"`).
- **Fallback**: if all configured sources return errors, the mock lookup is used and a warning is logged.
- **Private IPs**: RFC 1918 ranges (`127.x`, `10.x`, `172.16.x`, `192.168.x`) are short-circuited without any API call.

### Mock fallback

The deterministic mock (`adte/intel/_mock.py`) remains fully intact. When no API keys are set, the engine silently uses the mock — making offline testing, CI, and local development work identically to a fully-keyed production environment.

---

## Phase 3 — LLM Narrative Summaries

**Scope:** Add Claude-powered narrative summaries as an advisory display layer.

### Design constraint: advisory only

The LLM output is structurally isolated from the decision pipeline. It cannot affect `verdict`, `risk_score`, `confidence`, or `recommended_action`. These are computed deterministically before the LLM is called. The LLM receives only the verdict and rationale list — never raw evidence, actions, or safety configuration.

The system prompt explicitly instructs the model not to contradict the verdict: *"narrative: summarise the verdict and key signals; do NOT contradict or override the verdict."*

### Implementation

The Anthropic SDK (`anthropic` Python package) is used with `claude-opus-4-5`. The system prompt is cached with `cache_control: {"type": "ephemeral"}` to reduce latency and cost on repeated calls within the same session.

The `_call_claude()` function returns `None` on any failure. `generate_summary()` transparently falls back to `_build_deterministic_summary()` when no API key is configured or when the API call fails. Callers cannot distinguish which path ran — they receive the same dict shape either way.

### Output fields

The `report` section of the triage output is augmented with:
- `one_paragraph_summary` — plain-English incident narrative
- `mitre_tactics` — list of MITRE ATT&CK tactic names
- `mitre_techniques` — list of `{id, name}` objects
- `nist_phases` — applicable NIST CSF 2.0 category codes
- `confidence_note` — advisory note on MITRE mapping confidence

### MITRE mapping

`adte/intel/mitre_mapper.py` reads `examples/mitre_technique_map.yaml` to map signal names to MITRE technique IDs and tactic names. This powers both the LLM fallback path (deterministic mapping) and the MITRE/NIST view in the web UI.

---

## Phase 4 — Web Interface (Flask + React SPA)

**Scope:** Full multi-view web interface for analyst use.

### Backend: Flask server (`adte/server.py`)

Five REST endpoints:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `GET /` | — | Serves `frontend/index.html` |
| `GET /health` | — | Liveness probe: `{"status": "ok"}` |
| `GET /api/examples` | — | Returns 3 pre-converted `NormalizedIncident` JSON objects |
| `POST /api/triage` | JSON body | Runs full triage pipeline, returns complete output dict |
| `GET /api/queue` | — | Triage-scored alert queue (Wazuh live or example fallback) |
| `GET /api/intel?ip=` | — | IP threat intel lookup via `check_threat_intel` |
| `GET /api/config` | — | Sanitised safety gate env var values |

### Frontend: Single-file React SPA (`frontend/index.html`, 1,653 lines)

No build step. Babel standalone transpiles JSX in the browser. React 18 loaded from CDN. All state managed in a single `App` component with local state in each view component.

Eight fully functional sidebar views:

#### Alert Input (Triage)
The main two-panel layout. Left panel: JSON textarea with Load Example (cycles through 3 scenarios) and Run Triage button. Right panel: live verdict display with VerdictBadge, ScoreBar, signal grid, MITRE panel, and ActionBanner. Loading skeleton animates while the triage request is in flight.

#### Alert Queue
Fetches `/api/queue` on mount and every 60 seconds. Displays a sortable table: TIME | INCIDENT ID | USER | SOURCE IP | RISK (mini bar + number) | VERDICT (colored badge) | STATUS. Clicking a row pre-populates the triage textarea and auto-runs triage after an 80ms state-settle delay.

#### Signal Breakdown
Five stacked cards, one per signal. Each card shows: signal name, weight badge, description paragraph, live score (large mono number + bar) when a triage result exists, full detail text, and a footer row with MITRE technique, NIST category, and example trigger. Gracefully shows reference data without a result.

#### MITRE / NIST
Two-panel layout. Left: detected tactic badges, technique rows with detecting signal attribution, and a 10-tactic coverage matrix (filled/hollow dots). Right: NIST CSF 2.0 DETECT function header, fired category rows, full function strip with DETECT highlighted, and a footer note on ADTE's coverage scope.

#### Threat Intel
IP lookup input with Enter-key support. Results panel: large mono IP, MALICIOUS/CLEAN verdict badge, confidence bar, source (with "Multiple sources aggregated" note for comma-joined sources), tag pills. Maintains a 5-entry lookup history that can be re-clicked to restore results.

#### IP Reputation
Extracts IP addresses from the last triage result's `ip_reputation` signal detail using regex. Displays a table with IP, mini confidence bar, and tags parsed from the detail text. Falls back to a prose block if no IPs can be extracted. Shows `NoResultBanner` when no triage has been run.

#### Safety Gates
Fetches `/api/config` on mount. Renders a 2×3 grid of gate cards, each showing: gate number badge, gate name, live status badge (SAFE/TRIGGERED/ACTIVE/BLOCKED/CONFIGURED/OPEN), description, condition, action, and env var name in monospace. Status color logic: Kill Switch red=TRIGGERED, Dry Run amber=ACTIVE, Execution green=ENABLED, allowlists green=CONFIGURED when non-empty.

#### Signal Weights
Fully static. SVG donut chart (200×200, viewBox "0 0 200 200") with five colored segments and a "100 POINTS" center label. Legend with mini inline bars. Full weights table: SIGNAL | WEIGHT | MAX SCORE | DETECTION METHOD | MITRE MAPPING. Weight redistribution example table showing the three surviving signals when device_novelty (15) and login_hour (10) are removed, with original/redistributed/change columns.

---

## Phase 5 — Security Audit & Remediation

**Scope:** Structured security review of the full codebase; all findings fixed.

### Audit methodology

Static analysis plus manual code review, covering: entry points, trust boundaries, data flows, insecure defaults, dangerous API patterns, supply chain, and a git diff review of the Wazuh adapter commit.

### Findings and fixes

#### HIGH severity

**H-1: SSL verification disabled by default (`wazuh.py`)**

The `WazuhAdapter.__init__` parameter `verify_ssl` defaulted to `False`. The `from_env()` factory never overrode it, so every production connection to the Wazuh Indexer silently skipped TLS certificate validation.

*Fix:* Default changed to `True`. `from_env()` now reads `ADTE_WAZUH_VERIFY_SSL` — setting it to `false` opts out for local self-signed setups. The default is now secure; the insecure path requires explicit action.

**H-2: Global `urllib3.disable_warnings()` at module import (`wazuh.py`)**

A single `urllib3.disable_warnings(InsecureRequestWarning)` call at module level silenced TLS warnings for the entire Python process — not just for Wazuh connections. Any other HTTP client (e.g. the threat intel clients) would also have its TLS warnings suppressed as a side effect.

*Fix:* Module-level call removed entirely. Warning suppression is now scoped using `warnings.catch_warnings()` as a context manager around the specific `session.post()` call, and only when `verify_ssl=False`.

#### MEDIUM severity

**M-1: Prompt injection surface in LLM prompt construction (`llm_assist.py`)**

Wazuh alert fields — including `rule.description`, device names, and agent identifiers — flow through the engine's signal computation into the `detail` field of each rationale entry, which is then interpolated via f-string into the LLM prompt. A malicious Wazuh alert rule description could attempt to inject instructions into the prompt.

*Fix:* All `detail` strings are truncated to 300 characters before being placed in the prompt. Impact was already limited (LLM output is advisory-only and never feeds back into the verdict), but the truncation provides a concrete bound.

**M-2: No HTTP timeout on Wazuh Indexer requests (`wazuh.py`)**

`requests.Session` has no default timeout. If the Wazuh Indexer accepted the connection but stalled on sending data, the CLI would hang indefinitely with no recovery path.

*Fix:* `timeout=30` added to all `session.post()` calls. A hung indexer now raises `requests.exceptions.Timeout` after 30 seconds.

**M-3: Silent exception swallowing in LLM client (`llm_assist.py`)**

The `_call_claude()` function caught `Exception` broadly and returned `None` without any logging. This silenced ImportErrors, network failures, API authentication failures, rate limit errors, and malformed responses — all without any trace in the log.

*Fix:* `_log.warning("LLM call failed — falling back to deterministic summary: %s", exc)` added before the `return None`. Failures are now visible in logs while the fallback behaviour is unchanged.

**M-4: MFA fatigue capitulation check — ordering bug for Wazuh (`engine.py`)**

> *Historical note: field names below are pre-OCSF-migration. Today the engine reads
> `auth_status == "success"`/`"failure"` over `type == "authentication"` events; see the OCSF
> schema migration entry in the build sequence.*

The fatigue capitulation check used `denied[0]` to find the first MFA denial and checked whether any success followed it:

```python
any(e.mfa_result == "Success" for e in events if e.timestamp > denied[0].timestamp)
```

For Sentinel incidents, events are in chronological order, so `denied[0]` is the oldest denial — the logic is correct. For Wazuh incidents, the OpenSearch query uses `"sort": [{"@timestamp": {"order": "desc"}}]`, so `denied[0]` is the *newest* denial. The capitulation check would require a success *after* the newest denial, which is effectively impossible — making the fatigue signal always miss the capitulation flag for Wazuh-sourced incidents.

*Fix:* Replaced `denied[0]` with `min(e.timestamp for e in denied)` — the earliest denial timestamp regardless of list ordering. Also added an explicit guard for the empty `denied` list to prevent `ValueError` from `min()` on an empty sequence.

**M-5: `requests` missing from `pyproject.toml` (`pyproject.toml`)**

`adte/adapters/wazuh.py` imports `requests` directly, but the package was only declared in `requirements.txt` (since removed), not in `pyproject.toml`'s `dependencies`. Installing the package via `pip install adte-detection-triage-engine` would succeed but fail at runtime when the Wazuh adapter was imported.

*Fix:* `requests>=2.32.4` added to `pyproject.toml` dependencies.

**M-6: Broad `except Exception` in CLI exposes internal schema details (`cli.py`)**

Both `_load_incident()` and `_load_normalized_incident()` caught all exceptions and included `{exc}` directly in the user-visible error message. Pydantic `ValidationError` messages include full field paths and internal model names, which could reveal implementation details to a user running the CLI.

*Fix:* Catches `ValidationError`, `TypeError`, and `KeyError` with a sanitised generic message ("incident does not match expected schema — check that all required fields are present"). A bare `except Exception` fallback handles truly unexpected errors with a generic message that includes no exception content.

#### LOW severity

**L-1: ZeroDivisionError if all signals skipped (`engine.py`)**

The weight redistribution formula `raw_sum * 100 / available_weight` had no guard for `available_weight == 0`. While the current signal set makes this unreachable (each signal returns a result even when skipped), there was no explicit protection against future signals being added without proper fallback handling.

*Fix:* Explicit `if available_weight <= 0: self._risk_score = 0` guard added before the division.

**L-2: Malformed FP registry entries silently dropped (`sigma_fp_registry.py`)**

YAML entries missing the `pattern_type` key were silently skipped via `if not ptype: continue`. A misconfigured FP registry entry (typo in the key name, malformed structure) would be ignored without any indication, potentially causing expected IP ranges to not be registered.

*Fix:* `_log.warning("FP registry entry missing 'pattern_type' — skipping: %r", item)` added before the `continue`.

**L-3: Ambiguous CIDR notation silently normalised (`sigma_fp_registry.py`)**

`IPv4Network(cidr, strict=False)` accepts CIDRs with host bits set (e.g. `10.0.0.1/24` is treated as `10.0.0.0/24`) without any indication that the input was wrong. This masks configuration mistakes in the FP registry.

*Fix:* Tries `strict=True` first. On `ValueError` (host bits set), normalises with `strict=False` and logs a `WARNING` identifying the original value, the pattern type, and the normalised result.

---

## Phase 6 — Alert Queue Enhancements & Critical Bug Fix

**Scope:** Made the Alert Queue view a full replacement for the CLI `--source wazuh` command, and fixed a silent bug that prevented Wazuh data from ever reaching the frontend.

### Bug: `WazuhAdapter()` called without arguments in `/api/queue`

**Root cause:** `server.py` line 175 called `WazuhAdapter()` with no arguments. `WazuhAdapter.__init__` requires three positional parameters (`url`, `user`, `password`) with no defaults. This raised a `TypeError` at construction time, which was immediately caught by the surrounding `except Exception:` block and silently swallowed — causing every `/api/queue` request to fall back to the three bundled mock incidents regardless of whether Wazuh credentials were configured.

**Symptom:** Alert Queue always showed `"source": "mock"` and the same three example incidents even when the Wazuh Indexer was running and had live alerts.

**Diagnosis path:**
1. Confirmed the OpenSearch filter uses `gte` (not `gt`) — no off-by-one on `min_level`.
2. Confirmed `min_level` default is `1` in `server.py` and the frontend sends it correctly.
3. Confirmed the frontend `URLSearchParams` key name matches the server's `request.args.get("min_level")`.
4. Found `WazuhAdapter()` called with no args → `TypeError` → silent fallback.

**Fix:** One word changed on one line:
```python
# Before (broken):
incidents = WazuhAdapter().fetch_incidents(hours=hours, limit=limit, min_level=min_level)

# After (correct):
incidents = WazuhAdapter.from_env().fetch_incidents(hours=hours, limit=limit, min_level=min_level)
```

`from_env()` reads `ADTE_WAZUH_HOST`, `ADTE_WAZUH_USER`, and `ADTE_WAZUH_PASS` from the environment. If credentials are absent it raises `EnvironmentError`, which is caught and falls back to mock — the same intended behaviour, but now only when credentials are genuinely missing.

### `/api/queue` backend: query param support and structured response

The endpoint previously had hardcoded `hours=24, limit=50` and returned a bare JSON array.

**Changes:**
- Reads `hours`, `limit`, and `min_level` from query string with `_clamp()` validation:
  - `hours`: default 24, range 1–168
  - `limit`: default 50, range 1–500
  - `min_level`: default 1, range 1–15
- Passes all three through to `WazuhAdapter.from_env().fetch_incidents()`
- Tracks whether Wazuh or the mock fallback was used in a `data_source` variable
- Response shape changed from a bare array to a structured object:
  ```json
  {
    "source": "wazuh",
    "params": {"hours": 24, "limit": 50, "min_level": 1},
    "rows": [...]
  }
  ```

The `source` field enables the frontend to distinguish live data from the fallback without inspecting row contents.

### Alert Queue frontend: live controls

The `QueueView` component was expanded from a static auto-refresh table into an interactive query panel.

**Controls bar (above the table):**
- **Hours** — number input, 1–168, default 24. Controls the Wazuh look-back window.
- **Limit** — number input, 1–500, default 50. Caps total alerts retrieved.
- **Min Level** — number input, 1–15, default 1. Minimum Wazuh `rule.level` filter (mirrors the CLI `--min-level` flag).
- **Refresh** button — re-fetches with current input values; disabled and shows "Loading…" while a request is in flight.
- **Source badge** — `WAZUH LIVE` (green) when data came from the live adapter; `MOCK FALLBACK` (amber) when falling back to examples.
- **Last-fetched timestamp** — right-aligned, shows the clock time of the most recent successful fetch.

**State model:** `hours`, `limit`, `minLevel` are independent `useState` values. The `load(h, lim, ml)` callback accepts them as parameters (not via closure) so the auto-refresh interval always uses the values at the time of the interval callback, not stale closure values. The `useEffect` dependency array is intentionally empty (`[]`) — the interval is set up once on mount; the Refresh button calls `load` directly with current state.

**Response parsing update:** Frontend now reads `data.rows` and `data.source` from the structured response object instead of treating the response as a direct array.

**Empty state messages** are now context-aware:
- If `source === 'mock'`: "No example incidents available"
- Otherwise: "No alerts in queue — check Wazuh connection or widen the time window"

---

## Phase 7 — Alert Router (Slack / Stdout Notification)

**Scope:** Standalone polling script that bridges the triage queue to operator notification channels.

### Problem

The engine produces high-risk verdicts but had no mechanism to push them anywhere in real time. An analyst would have to manually poll the web UI or run the CLI. The alert router closes this gap without modifying any existing code.

### Implementation (`scripts/alert_router.py`)

Polls `GET /api/queue?hours=1&limit=100&min_level=1` every N seconds (default 60). For each new `high_risk` row not previously seen, it issues a follow-up `POST /api/triage` with the row's `incident_json` to retrieve the full triage result — necessary because the queue response does not include `confidence` or `recommended_action`, both required fields in the alert message.

Deduplication uses an in-memory `set[str]` of seen incident IDs. The set resets on process restart — by design, to avoid persisting state in a standalone script.

**Alert message format (plain text, no emojis):**

```
HIGH RISK ALERT
Incident:         <incident_id>
User:             <user>
Source IP:        <source_ip>
Risk Score:       <risk_score>/100
Confidence:       <confidence>%
Top Signal:       <top_signal>
Recommended:      <recommended_action>
```

`top_signal` is derived from `max(rationale, key=lambda r: r["score"])["signal"]` — the highest-scoring signal from the full rationale list, not the pre-computed queue string.

**Routing:**
- If `ADTE_SLACK_WEBHOOK` is set: `POST {"text": message}` to the webhook URL with a 5-second timeout.
- If unset: message printed to stdout. The startup banner announces which path is active.

**Error handling:** All three network calls (queue poll, triage enrichment, Slack POST) are independently wrapped in try/except. Any single failure logs a warning and the loop continues — the script never crashes on transient network errors.

**CLI:**
```
python scripts/alert_router.py [--url URL] [--interval N]
```

### Documentation (`docs/ALERT_ROUTING.md`)

Covers: how it works, prerequisites, usage, env vars, Slack app setup (create app → activate incoming webhooks → copy URL), example alert output, stdout fallback behaviour.

### Test impact

No new tests added (would require mocking `requests`). Existing 161 tests all pass unchanged.

---

## Phase 8 — Auto-Ticket Pipeline (Linear + Trello)

**Scope:** Automatic ticket creation for high-risk and medium-risk verdicts detected by the alert router.

### Design

`scripts/ticket_client.py` provides a single `create_ticket(verdict)` dispatcher that never raises.  It tries providers in priority order:

1. **Linear** — when `ADTE_LINEAR_API_KEY` is set, POSTs a `issueCreate` GraphQL mutation to `https://api.linear.app/graphql`.  Returns the issue URL on success.
2. **Trello** — when `ADTE_TRELLO_API_KEY` is set, POSTs to `https://api.trello.com/1/cards`.  Returns the card URL (checks both `url` and `shortUrl` fields).
3. **Neither configured** — returns `None` silently.  No log output, no effect on the caller.

If both keys are set, Linear is tried first.  If Linear fails (HTTP error or network error), Trello is tried as a fallback.

### Ticket content

Title format: `[HIGH_RISK] INC-001 — alice@example.com`

Body fields: verdict, risk score, confidence, recommended action, top signal with detail text (from `max(rationale, key=score)` when the full triage result is available, or the pre-computed `top_signal` string from a queue row), and timestamp.  Both the full triage result shape and the queue row shape are handled — field extraction is defensive throughout.

### Alert router integration

The `run_loop` in `scripts/alert_router.py` was minimally extended:

- **`high_risk`**: after `route_alert` (Slack/stdout), calls `create_ticket(detail or row)`.  Uses the full triage result when available so the ticket includes `confidence` and `recommended_action`.
- **`medium_risk`**: now processed by the loop (previously ignored); calls `create_ticket(row)` directly — no second triage fetch.
- Both verdict types share the same `seen_ids` deduplication set.
- Ticket failure (`None` return) logs a warning and never interrupts Slack routing or the next poll cycle.

### Test suite (`tests/test_ticket_client.py`)

13 new tests using `unittest.mock.patch("requests.post")` — no real HTTP calls:

| Test | Covers |
|------|--------|
| Linear success | Returns URL from `data.issueCreate.issue.url` |
| Linear HTTP error | Returns `None` on non-200 status |
| Linear missing API key | Returns `None` without calling `requests.post` |
| Linear missing team ID | Returns `None` without calling `requests.post` |
| Linear RequestException | Returns `None` on network error |
| Trello success | Returns URL from `shortUrl` field |
| Trello HTTP error | Returns `None` on non-200/201 status |
| Trello missing API key | Returns `None` without calling `requests.post` |
| Trello RequestException | Returns `None` on network error |
| Dispatcher: both keys | Tries Linear first, returns Linear URL |
| Dispatcher: no Linear key | Falls through to Trello |
| Dispatcher: Linear fails | Falls through to Trello |
| Dispatcher: neither key | Returns `None` without any HTTP call |

**New test total: 174 tests passing.**

---

## Phase 9 — SQLite Verdict Audit Log

**Goal:** Persist every triage verdict to a local SQLite database so analysts and operators have a durable, queryable audit trail. Surface it via a new `/api/verdicts` endpoint.

### What was built

**`adte/store/audit_log.py`** — new module, three public functions:

| Function | Behaviour |
|----------|-----------|
| `init_db(path)` | Creates `verdicts` table with `CREATE TABLE IF NOT EXISTS` — idempotent, safe to call at startup |
| `log_verdict(output, db_path)` | Inserts one row from a triage output dict; `mitre_techniques` stored as JSON string; `logged_at` set to current UTC time |
| `query_verdicts(db_path, verdict_filter, limit)` | Returns rows as dicts, newest first; optional verdict filter and row cap |

All three functions use `check_same_thread=False` and swallow all exceptions with `_log.warning()` so audit failures never affect the triage response pipeline.

**Schema:**

```
verdicts (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id        TEXT NOT NULL,
    verdict            TEXT NOT NULL,
    risk_score         REAL NOT NULL,
    confidence         REAL,
    recommended_action TEXT,
    mitre_techniques   TEXT,       -- JSON array string
    nist_phase         TEXT,
    source             TEXT,
    timestamp          TEXT,
    logged_at          TEXT NOT NULL
)
```

**`adte/server.py`** changes:
- `DB_PATH = Path(os.getenv("ADTE_AUDIT_DB", "adte_audit.db"))` constant added
- `init_db(DB_PATH)` called at module load after `app = Flask(__name__)`
- `/api/triage` calls `log_verdict(output, DB_PATH)` before returning
- New `/api/verdicts` endpoint: accepts `verdict` and `limit` query params, returns `{"verdicts": [...], "count": N}`

### Tests (`tests/test_audit_log.py`) — 10 new tests

| Test | Covers |
|------|--------|
| `test_init_db_creates_file_and_table` | DB file and table created on first call |
| `test_init_db_is_idempotent` | Calling twice does not raise or duplicate |
| `test_log_verdict_inserts_row_with_all_fields` | All fields persisted correctly |
| `test_log_verdict_missing_optional_fields_default_to_none` | Optional fields default to NULL |
| `test_log_verdict_corrupt_db_path_logs_warning_without_raising` | Bad file → warning, no raise |
| `test_query_verdicts_returns_rows_newest_first` | ORDER BY id DESC |
| `test_query_verdicts_filters_by_verdict` | `verdict_filter` param |
| `test_query_verdicts_limit_caps_results` | `limit` param |
| `test_query_verdicts_nonexistent_db_returns_empty` | Missing file → `[]` |
| `test_mitre_techniques_round_trips_through_json` | JSON string stored and parseable |

**New test total: 198 tests passing.**

---

## Phase 10 — Analyst Feedback Loop

**Goal:** Let analysts label triage verdicts as false positive (FP) or true positive (TP) via API and UI. FP labels automatically promote the flagged IP into the FP registry so future triage runs suppress it.

### What was built

**`adte/store/audit_log.py`** — extended:

| Addition | Behaviour |
|----------|-----------|
| `feedback` table in `init_db` | `CHECK(label IN ('fp','tp'))` constraint; created alongside `verdicts` at startup |
| `log_feedback(incident_id, label, ip, db_path)` | Inserts one row; `submitted_at` UTC at insert time; never raises |
| `query_feedback(db_path, incident_id)` | Returns rows newest-first; optional filter by incident; never raises |

**`adte/intel/sigma_fp_registry.py`** — `add_fp_entry(ip, comment, registry_path) -> bool`:
- Appends a new `analyst_feedback` entry to the YAML registry
- Host IPs normalised to `/32` CIDR
- `threading.Lock` serialises concurrent writes (callers queue, not last-write-wins)
- Verifies YAML is still parseable via `FPRegistry.load()` after write
- Returns `True` on success, `False` on any failure; never raises

**`adte/server.py`** — `POST /api/feedback`:
- Validates `label` is `"fp"` or `"tp"` → 400 otherwise
- Calls `log_feedback` unconditionally
- If `label == "fp"` and `ip` present: calls `add_fp_entry`; result in `registry_updated` field
- Returns `{"status": "ok", "label", "incident_id", "registry_updated": bool}`

**`frontend/index.html`** — `FeedbackPanel` component:
- Rendered below the Recommended Action banner after every triage result
- Optional Source IP text field; FALSE POSITIVE (red) and TRUE POSITIVE (green) buttons
- Collapses to a confirmation line on success; shows inline error on failure

### Tests (`tests/test_feedback.py`) — 11 new tests

| Test | Covers |
|------|--------|
| `test_log_feedback_inserts_row_with_all_fields` | Full row persisted |
| `test_log_feedback_null_ip_stores_none` | NULL ip column |
| `test_log_feedback_invalid_db_path_logs_warning_without_raising` | Corrupt path → warning |
| `test_query_feedback_returns_rows_newest_first` | ORDER BY id DESC |
| `test_query_feedback_filtered_by_incident_id` | incident_id filter |
| `test_query_feedback_nonexistent_db_returns_empty` | Missing DB → `[]` |
| `test_add_fp_entry_appends_entry_and_returns_true` | YAML updated, returns True |
| `test_add_fp_entry_nonexistent_path_returns_false` | Missing file → False |
| `test_post_feedback_fp_with_ip_updates_registry` | Flask: registry_updated true |
| `test_post_feedback_tp_does_not_update_registry` | Flask: registry_updated false |
| `test_post_feedback_invalid_label_returns_400` | Flask: bad label → 400 |

**New test total: 209 tests passing.**

---

## Phase 11 — Frontend Audit Views + API Completions

**Goal:** Surface the audit log and feedback history in the UI. Add MITRE/NIST badges everywhere a verdict is shown. Complete the feedback API with GET and DELETE endpoints for both tables.

### Backend additions (`adte/server.py`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/feedback` | GET | Returns `{"feedback": [...], "count": N}`; optional `?incident_id=` filter |
| `/api/verdicts` | DELETE | Clears all rows from the `verdicts` table |
| `/api/feedback` | DELETE | Clears all rows from the `feedback` table |

**`adte/store/audit_log.py`** — two new functions:
- `clear_verdicts(db_path) -> bool` — `DELETE FROM verdicts`; returns True/False; never raises
- `clear_feedback(db_path) -> bool` — `DELETE FROM feedback`; returns True/False; never raises

### Frontend additions (`frontend/index.html`)

**`MitreBadges` component** — renders small blue pills for each ATT&CK technique ID and one amber pill for the NIST phase. Renders nothing when both fields are absent. Wired into:
- `TriageResult` — displayed between the score bar and the signal breakdown
- Alert Queue rows — displayed as a sub-row beneath each grid row (only when data present)

**Verdict History view** (sidebar: AUDIT → Verdict History):
- Fetches `GET /api/verdicts?limit=100` on mount
- Table columns: Timestamp, Incident ID, coloured Verdict badge, Risk Score, MITRE Techniques (comma-separated, blue), NIST Phase (amber)
- Verdict dropdown filter re-fetches on change
- **Clear All** button — browser confirm dialog → `DELETE /api/verdicts` → table empties in place; disabled when table is empty

**Feedback History view** (sidebar: AUDIT → Feedback History):
- Fetches `GET /api/feedback` on mount
- Table columns: Submitted At, Incident ID, Label badge (red=FALSE POS / green=TRUE POS), IP
- Incident ID text filter debounced 300 ms re-fetches on change
- **Clear All** button — browser confirm dialog → `DELETE /api/feedback` → table empties in place; disabled when table is empty

Both views have loading skeletons, empty states, and inline error messages. Neither can crash the UI.

---

## Phase 12 — Security Hardening (9-Task Patch)

**Scope:** Structured security remediation across authentication, injection defences, rate limiting, CORS, credential safety, and queue overflow protection.

### Task 1 — RBAC + API Key Authentication

All 12 Flask endpoints now require an `X-ADTE-Key` header matched against per-role environment variables.  A `require_role(minimum_role)` decorator enforces a four-level hierarchy: `readonly (0) < analyst (1) < senior_analyst (2) < admin (3)`.

The decorator short-circuits when `app.config["TESTING"] is True` so the existing test suite requires no modification — Flask test clients pass no auth headers by convention.

Role assignments:
- `readonly`: `GET /`, `/health`, `/api/examples`
- `analyst`: triage, queue, verdicts, feedback (GET/POST), intel
- `senior_analyst`: `/api/config`
- `admin`: `DELETE /api/verdicts`, `DELETE /api/feedback`

### Task 2 — FP Registry IP Validation

`add_fp_entry()` now validates the supplied IP or CIDR with `ipaddress.IPv4Address` / `ipaddress.IPv4Network` before acquiring the write lock.  Invalid inputs return `False` with a `WARNING` log and never touch the filesystem.

### Task 3 — LLM Prompt Injection Defence

`sanitize_alert_field(value, max_length=300)` strips control characters, collapses whitespace, truncates, and redacts common injection phrases (e.g. "ignore previous instructions", "SYSTEM: you are") via a compiled regex.  All alert-derived values in `_build_llm_prompt()` now pass through this function.

The system prompt was hardened with an explicit `SECURITY BOUNDARY` section.  The user-turn prompt wraps untrusted alert data between `--- BEGIN ALERT DATA ---` / `--- END ALERT DATA ---` delimiters.

### Task 4 — SQLite Injection Regression Tests

Four new tests in `tests/test_sql_injection.py` confirm that SQL metacharacters in `incident_id`, `label`, and filter parameters are handled as data by the parameterized `?` queries — the `verdicts` table is never dropped and filters cannot be widened to `OR '1'='1'`.

### Task 5 — API Key Masking

`/api/config` response now includes `api_keys` and `intel_keys` objects showing masked values (`xxxx****xxxx` format).  A `_mask_key(env_var)` helper ensures full key values are never returned in any API response.

### Task 6 — Rate Limiting

`flask-limiter>=3.5` added to dependencies.  `POST /api/triage` is limited to 10 requests/minute; `POST /api/feedback` to 30 requests/minute.  Exceeded limits return JSON `{"error": "Rate limit exceeded"}` with HTTP 429 via a registered error handler.

### Task 7 — CORS Lockdown

`flask-cors>=4.0` added to dependencies.  `CORS(app, origins=_CORS_ORIGINS)` is initialised at startup with origins read from the `ADTE_CORS_ORIGINS` environment variable (comma-separated; default: `http://localhost:5000`).

### Task 8 — Wazuh Credential Audit

Full audit confirmed: no credential values appear in any `_log.*` call in the Wazuh adapter.  A `__repr__` override was added that exposes only `url` and `user`, never `password`.

### Task 9 — Alert Router Queue Overflow

`MAX_QUEUE_SIZE = 1000` constant added to `scripts/alert_router.py`.  `run_loop()` checks `len(seen_ids) >= MAX_QUEUE_SIZE` before each poll; on overflow it evicts the oldest half and logs a `WARNING`.

### Documentation updates

- `docs/ARCHITECTURE.md` — new Security Controls section covering RBAC, rate limits, CORS, input validation, credential safety, and queue overflow
- `.env.example` — `ADTE_API_KEY_*` and `ADTE_CORS_ORIGINS` added
- `CLAUDE.md` — test count updated
- `README.md` — test count updated

**New test total: 213 tests passing** (4 new SQL injection regression tests added).

---

## Current State

### Test baseline
**213 tests passing** across 10 files: `test_engine`, `test_geo`, `test_intel`, `test_policy`, `test_safety`, `test_llm_assist`, `test_wazuh_adapter`, `test_feedback`, `test_mitre_mapper`, `test_sql_injection`.

### File inventory

```
adte/
  __init__.py, __main__.py
  cli.py              — Typer CLI: triage command, --source mock/wazuh/normalized
  config.py           — SafetyConfig: 6-gate evaluation
  decision_policy.py  — SIGNAL_WEIGHTS, classify_verdict, compute_confidence
  engine.py           — TriageEngine: enrich → score → decide → to_output
  models.py           — Pydantic schemas: NormalizedIncident, SignInMetadata, etc.
  report.py           — generate_report: narrative fields from LLM or deterministic path
  server.py           — Flask app: 12 endpoints, serves frontend/index.html
  adapters/
    sentinel.py       — Mock Sentinel adapter (response actions only)
    wazuh.py          — Live Wazuh Indexer adapter (OpenSearch _search API)
    entra_id.py       — Mock Entra ID adapter (disable account, revoke sessions)
  intel/
    _mock.py          — Deterministic mock threat intel (no API keys needed)
    abuseipdb.py      — AbuseIPDB live client
    virustotal.py     — VirusTotal live client (with 15s rate-limit delay)
    otx.py            — AlienVault OTX live client
    aggregator.py     — Multi-source result merger
    threat_intel.py   — Dispatcher: live → mock fallback
    mitre_mapper.py   — YAML-driven MITRE technique lookup + get_techniques(), get_nist_phase()
    sigma_fp_registry.py — Known-benign CIDR registry + add_fp_entry() write helper
  llm/
    __init__.py
    enrichment.py     — enrich_alert(): per-alert LLM enrichment (wired in llm_enrich())
  llm_assist.py       — generate_summary(): verdict narrative + MITRE/NIST annotation
  store/
    audit_log.py      — verdicts + feedback tables; log/query/clear for both; never raises
    user_history.py   — get_user_profile(): behavioural baseline per user
  utils/
    geo.py            — haversine_distance, calculate_travel_speed, is_impossible_travel

frontend/
  index.html          — Single-file React SPA (Babel standalone, no build step); 10 views

examples/
  incident_impossible_travel_mfa_fatigue.json   — HIGH RISK (score 79)
  incident_benign_vpn_travel.json               — LOW RISK (score 5)
  incident_needs_human_ambiguous.json           — MEDIUM RISK (score 43)
  fp_registry.yaml                              — Known-benign IP ranges
  mitre_technique_map.yaml                      — Signal → MITRE technique mapping

scripts/
  alert_router.py     — Polls /api/queue, routes high_risk to Slack/stdout + tickets; medium_risk to tickets
  ticket_client.py    — create_ticket() dispatcher: Linear → Trello → None

docs/
  ARCHITECTURE.md     — Pipeline diagram, module dependency map
  DECISIONS.md        — Signal weight rationale, threshold logic
  SAFETY.md           — Full gate logic and example scenarios
  EXTENSIONS.md       — Connecting to real Sentinel and Graph APIs
  EXAMPLE_WALKTHROUGH.md — All 3 scenarios with signal explanations
  ALERT_ROUTING.md    — Alert router setup, env vars, Slack webhook steps
  AUTO_TICKET.md      — Ticket pipeline setup, env vars, Linear and Trello steps
  PROJECT_PROGRESS.md — This file
```

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ADTE_WAZUH_HOST` | `https://localhost:9200` | Wazuh Indexer base URL |
| `ADTE_WAZUH_USER` | *(required)* | Wazuh API username |
| `ADTE_WAZUH_PASS` | *(required)* | Wazuh API password |
| `ADTE_WAZUH_VERIFY_SSL` | `true` | Set `false` for self-signed certs |
| `ADTE_ABUSEIPDB_KEY` | — | AbuseIPDB API key (mock fallback if unset) |
| `ADTE_VT_API_KEY` | — | VirusTotal API key (mock fallback if unset) |
| `ADTE_OTX_KEY` | — | AlienVault OTX key (anonymous access without key) |
| `ANTHROPIC_API_KEY` | — | Claude API key (deterministic fallback if unset) |
| `ADTE_KILL_SWITCH` | `false` | Halts all automated execution immediately |
| `ADTE_DRY_RUN` | `true` | Logs actions without executing (default on) |
| `ADTE_EXECUTION_ENABLED` | `false` | Must be `true` for any action to execute |
| `ADTE_TENANT_ALLOWLIST` | — | Comma-separated tenant IDs permitted for action |
| `ADTE_USER_ALLOWLIST` | — | Comma-separated users permitted for action |
| `ADTE_ACTION_ALLOWLIST` | `CLOSE_INCIDENT,POST_COMMENT` | Permitted action types |
| `ADTE_SLACK_WEBHOOK` | — | Slack incoming webhook URL for alert router (stdout if unset) |
| `ADTE_LINEAR_API_KEY` | — | Linear personal API key for ticket creation |
| `ADTE_LINEAR_TEAM_ID` | — | Linear team ID (required with Linear key) |
| `ADTE_TRELLO_API_KEY` | — | Trello Power-Up API key for ticket creation |
| `ADTE_TRELLO_TOKEN` | — | Trello user OAuth token (required with Trello key) |
| `ADTE_TRELLO_LIST_ID` | — | Trello list ID to add cards to (required with Trello key) |
| `ADTE_AUDIT_DB` | `adte_audit.db` | Path to the SQLite verdict audit database |
| `ADTE_FP_REGISTRY` | `examples/fp_registry.yaml` | Path to the FP CIDR registry YAML |
| `ADTE_API_KEY_ADMIN` | — | API key for admin role (X-ADTE-Key header) |
| `ADTE_API_KEY_SENIOR` | — | API key for senior_analyst role |
| `ADTE_API_KEY_ANALYST` | — | API key for analyst role |
| `ADTE_API_KEY_READONLY` | — | API key for readonly role |
| `ADTE_CORS_ORIGINS` | `http://localhost:5000` | Comma-separated CORS allowed origins |

---

## Phase 13 — `use_llm` Query Param on `/api/triage`

**Scope:** Wire the existing LLM narrative path through the server so analysts can opt in to Claude-powered summaries from the web UI.

### What was built

`generate_report()` in `report.py` already accepted `use_llm: bool`, and `TriageEngine.to_output()` already forwarded it — but the server always called `to_output()` with the default `use_llm=False`.

**`adte/server.py`** — one additional line in `POST /api/triage`:
```python
use_llm: bool = request.args.get("use_llm", "false").lower() == "true"
output = engine.enrich().score().decide().to_output(use_llm=use_llm)
```

When `use_llm=true` and `ANTHROPIC_API_KEY` is set server-side, `generate_summary()` calls Claude and the `report.one_paragraph_summary` and `report.confidence_note` fields contain live LLM output.  When the key is absent or the call fails, `_build_deterministic_summary()` is used transparently — the response shape is identical.

**`frontend/index.html`** — `runTriage` appends `?use_llm=true` when a `llmAvailable` boolean (fetched from `/api/config` on mount) is `true`.

The AI Summary panel header now shows a **CLAUDE** badge (accent blue) when the summary came from the live API, or a **DETERMINISTIC** badge (grey) when the template path was used.  The `confidence_note` field is displayed as an italic footer below the summary text.

**No new tests required** — the LLM path was already covered by `test_llm_assist.py` with the API key absent (deterministic fallback); the server change is a one-line read of a query param.

---

---

## Phase 14 — Frontend Auth Header Wiring

**Scope:** Propagate the ADTE RBAC bearer token stored in `localStorage` to every fetch call in the UI.

### Problem

Phase 12 added RBAC to all 12 server endpoints and stored the key in `localStorage` via the Settings view — but no frontend fetch call actually sent the key.  In secured mode (any `ADTE_API_KEY_*` env var set), every UI action except page load would receive a 401.

### What was built

A single `authHeaders()` helper was added to `frontend/index.html` immediately after `API_BASE`:

```js
const authHeaders = () => {
  const key = localStorage.getItem('adte_api_key') || '';
  return key ? { 'X-ADTE-Key': key } : {};
};
```

All 12 fetch calls (queue, triage, intel, verdicts GET/DELETE, feedback GET/POST/DELETE, config, examples, health) were updated to spread `authHeaders()` into their headers object.  When no key is stored (open/demo mode), `authHeaders()` returns `{}` — adding no header — so behaviour is unchanged.

**No test changes needed** — the server TESTING bypass already handles missing headers in the test suite.

---

## Phase 15 — Server-Side API Key Storage

**Scope:** Remove all third-party API keys from the browser.  `localStorage` was being used to store Anthropic and OpenAI keys — a security anti-pattern (XSS, browser extensions, DevTools access).

### Design principle

Third-party API keys (Anthropic, VirusTotal, OTX, AbuseIPDB) belong exclusively in server-side environment variables.  The frontend has no legitimate reason to hold or see them.  The only key that belongs in the browser is the ADTE RBAC bearer token (`adte_api_key`) — which authenticates to the ADTE server itself, not a third-party service.

### What was built

**`adte/server.py`** — `/api/config` response gained one new field:
```python
"llm_available": bool(os.environ.get("ANTHROPIC_API_KEY", "").strip()),
```
The key value is never sent — only a boolean capability flag.

**`frontend/index.html`** — three areas changed:

1. **`App` component** — `llmProvider` state and its localStorage useEffect removed; replaced with `llmAvailable` state (default `false`) populated by a `useEffect` that fetches `/api/config` once on mount.

2. **`runTriage`** — the three-line localStorage key check:
   ```js
   const provider = localStorage.getItem('adte_llm_provider') || 'anthropic';
   const hasKey = !!(localStorage.getItem('adte_anthropic_key') || '').trim();
   const useLlm = provider === 'anthropic' && hasKey;
   ```
   Replaced by a single line:
   ```js
   const useLlm = llmAvailable;
   ```

3. **`SettingsView`** — Anthropic key input, OpenAI key input, and provider toggle removed entirely.  Replaced with a read-only **LLM Summaries** panel showing an **AVAILABLE** (green) or **NOT CONFIGURED** (grey) status badge driven by the `llmAvailable` prop passed from `App`.

**`.env.example`** — now documents `ADTE_ABUSEIPDB_KEY`, `ADTE_VT_API_KEY`, `ADTE_OTX_KEY`, `ANTHROPIC_API_KEY` in a dedicated threat intel / LLM section.  `OPENAI_API_KEY` removed (OpenAI not implemented in the engine).

### After this change

`localStorage` held exactly one value at this point: `adte_api_key` (the ADTE bearer token).  No third-party API key ever touches the browser.

> **Updated in Phase 18-C:** The ADTE bearer token was subsequently moved from `localStorage` to `sessionStorage` so it auto-clears when the browser tab closes.  The no-third-party-key-in-browser invariant is unchanged.

**Test count unchanged: 213 passing.**

---

## Phase 16 — Persistent `.env` Loading (Zero-Config Startup)

**Scope:** Eliminate the manual env-var setup step required every PowerShell session. Wire `python-dotenv` (already a declared dependency) into both entry points so the `.env` file is loaded automatically on every `python -m adte.server` and `python -m adte triage` invocation.

### Problem

`python-dotenv` was listed in `pyproject.toml` but never called. Developers had to export all vars manually in every new PowerShell session or lose threat intel enrichment, RBAC, and LLM summaries silently — with no error, just silent mock/open-mode fallback.

### Changes

**`adte/server.py`** and **`adte/cli.py`** — added at module top, before any `os.environ` reads:

```python
from dotenv import load_dotenv
load_dotenv()  # loads .env from repo root before any os.environ reads
```

`load_dotenv()` is a no-op when `.env` does not exist and does not override vars already set in the shell, so CI, production, and existing PowerShell workflows are unaffected.

**`.env`** (gitignored, new file) — pre-structured template at repo root covering all vars: threat intel keys (`ADTE_ABUSEIPDB_KEY`, `ADTE_VT_API_KEY`, `ADTE_OTX_KEY`), `ANTHROPIC_API_KEY`, all four RBAC keys, Wazuh credentials, safety gates, and CORS origins. Fill in once; never commit.

### Security properties unchanged

- `.env` is in `.gitignore` — never committed, never pushed.
- Shell-set vars take precedence over `.env` (python-dotenv default behaviour) — CI/CD and production deployments are unaffected.
- No third-party key ever reaches the browser (established in Phase 15).
- Free-tier keys (AbuseIPDB, VirusTotal, OTX) are rate-limited by the providers; exposure risk is minimal, and ADTE's private-IP short-circuit prevents unnecessary calls.

**Test count unchanged: 213 passing.**

---

## Phase 17 — UI Polish: Logo Rebrand, Alert Input Layout, Agentic Analysis Placeholder

**Scope:** Three frontend-only changes with no backend impact and no test changes.

### Logo rebrand

The sidebar brand mark was replaced with a bar-constructed geometric eye — horizontal rectangular bars of varying widths forming an almond eye shape with a solid pupil block at center and faint scan tails extending left and right. Primary colour: `#c0392b` (crimson). The wordmark now reads **ADTE** (white, bold, monospace) with **DETECTION ENGINE** as a red subtitle below — matching the horizontal lockup defined in `adte_eye_bar_logo.svg`. In collapsed sidebar mode the wordmark hides and only the icon mark remains visible, consistent with how all other sidebar text is handled.

The previous logo (concentric circles, diamond cardinal accents, crosshair pupil, blue circuit traces) is retired. The new mark is purely geometric — no curves, no gradients, no strokes — aligning with SentinelOne-style flat bar construction.

### Alert Input layout

The generic cycling "Load Example" button was replaced by a **QUICK LOAD** section containing three individual scenario tiles:

| Tile | Badge |
|------|-------|
| Impossible travel + MFA fatigue | HIGH RISK |
| Ambiguous — needs human review | MEDIUM RISK |
| Benign VPN travel | LOW RISK |

Each tile loads its specific scenario directly (no cycling). The active tile highlights in accent blue. The textarea retains `flex: 1` so it expands to fill available height; `minHeight` was reduced from 320 to 200 px so the tiles are always visible without scrolling on standard viewport heights. The "Run Triage" button spans full width below the tiles. The entire left panel has `paddingBottom: 64` matching the global content wrapper clearance so nothing clips under the fixed query bar.

### Agentic Analysis placeholder

A new **AGENT** section was added to the sidebar nav with a lightbulb icon and an amber **IN PROGRESS** badge (hidden in collapsed mode). Clicking the item — or typing any query in the bottom query bar and pressing Enter or the send button — navigates to a new `AgentView`:

- Centered layout with a rounded icon container
- `AGENTIC ANALYSIS` heading + amber `IN PROGRESS` badge
- Description of planned capabilities
- Echo panel showing the submitted query (only rendered when a query was typed)
- Accent-bordered panel listing planned feature scope

The query bar itself now shows a blue `Claude` badge and an amber `COMING SOON` badge, with updated placeholder text: *"Ask ADTE... (agentic queries — not yet implemented)"*. On submit the input clears and the view switches to `AgentView`; the query bar is otherwise a no-op (no API call made).

**Test count unchanged: 213 passing.**

---

## Phase 18 — Reliability, Performance, and Signal Completeness

**Scope:** Four independent improvements across startup reliability, auth UX, backend speed, and example data accuracy. No test count changes — 213 tests still passing.

---

### 18-A — `load_dotenv` Startup Fix (`server.py`, `cli.py`)

**Problem:** `load_dotenv()` with no arguments searches upward from the current working directory. When the server is started from a path other than the repo root (e.g., from a shell opened inside `adte/`), it silently finds nothing — threat intel keys, RBAC keys, and all other `.env` values remain unset, causing the server to launch in open/mock mode with no error or warning.

**Fix:** Both entry points now use an absolute path resolved relative to the source file, with `override=True`:

```python
from pathlib import Path
from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=True)
```

`override=True` ensures the `.env` file wins over any stale shell vars set in a previous session. The path is always correct regardless of CWD.

**Startup logging added:** Immediately after `load_dotenv`, the server logs which threat intel keys loaded so missing keys are visible at startup rather than silently falling back to mock:

```
INFO ADTE startup — threat intel keys: AbuseIPDB=SET  VirusTotal=SET  OTX=SET
```

---

### 18-B — RBAC: Static Routes Made Public

**Problem:** After RBAC keys were generated in `.env`, `_any_keys_configured()` returned `True` and `@require_role("readonly")` was enforced on `GET /`, `/health`, and `/api/examples`. The frontend would not load at all without the `X-ADTE-Key` header set — making it impossible to reach the Settings view to enter the key in the first place.

**Fix:** `@require_role` was removed from the three static-serving routes. The intended behavior is: anyone can load the UI and browse examples; API data endpoints (triage, intel, queue, verdicts, feedback, config) enforce auth.

| Route | Before | After |
|-------|--------|-------|
| `GET /` | `require_role("readonly")` | Public |
| `GET /health` | `require_role("readonly")` | Public |
| `GET /api/examples` | `require_role("readonly")` | Public |
| `POST /api/triage` | `require_role("analyst")` | Unchanged |
| All other API routes | Unchanged | Unchanged |

---

### 18-C — Key Verification UX (`/api/auth-check` + Settings "Save & Verify")

**Problem:** Users entering the ADTE API key in Settings had no feedback whether the key was correct until they attempted a triage run and received "Invalid API key" in the result panel — with no indication of where the failure occurred.

**Root cause of persistent failures:** `handleSave` was storing `adteApiKey` state directly without calling `.trim()`. Pasting from a terminal or text editor typically appends a trailing newline (`\n`). The stored key `"351e…d406\n"` does not match the server's `"351e…d406"` → 401 on every request.

**Fixes:**

**Backend — `/api/auth-check` endpoint** (`server.py`):

```python
@app.route("/api/auth-check")
@require_role("readonly")
def auth_check() -> Any:
    api_key = request.headers.get("X-ADTE-Key", "")
    role = _resolve_role(api_key) if api_key else "open"
    return jsonify({"authenticated": True, "role": role or "open"}), 200
```

Returns the caller's resolved role without requiring a specific minimum. In open/demo mode (no keys configured) always returns `{"authenticated": true, "role": "open"}`.

**Frontend — Settings "Save & Verify"** (`frontend/index.html`):

- `handleSave` now calls `.trim()` before `sessionStorage.setItem()` and updates the input state to the trimmed value
- After saving, immediately calls `/api/auth-check` and updates the panel border and badge:
  - Green `KEY VALID · ADMIN` on success
  - Red `INVALID KEY` with a hint message on failure
  - Amber `VERIFYING…` while in flight
- On component mount, also verifies any existing stored key so the status is always current when you open Settings

**sessionStorage** (established in this phase): The ADTE key is stored in `sessionStorage` rather than `localStorage`. `sessionStorage` auto-clears when the browser tab/window is closed — appropriate for a bearer token that should not persist across sessions.

---

### 18-D — Parallel Threat Intel API Calls + Singleton Aggregator

**Problem:** The three threat intelligence client calls (AbuseIPDB, VirusTotal, OTX) were executed sequentially:

```python
# aggregator.py — before
raw_results = [client.check(ip) for client in self._clients]
```

Each call makes an HTTP request (typical latency 400ms–2s). Three sequential calls = 1.5–6 seconds of blocking time per enrichment step. On a triage request with multiple unique IPs, this compounded.

**Fix 1 — Parallel calls** (`adte/intel/aggregator.py`):

```python
with concurrent.futures.ThreadPoolExecutor(max_workers=len(self._clients)) as pool:
    futures = [pool.submit(client.check, ip) for client in self._clients]
raw_results = [f.result() for f in futures]
```

All three providers are queried simultaneously. Total time = `max(slowest_call)` instead of `sum(all_calls)`. Typical speedup: 3–5×.

**Fix 2 — Module-level singleton** (`adte/intel/threat_intel.py`):

```python
_aggregator: ThreatIntelAggregator | None = None
_aggregator_lock = threading.Lock()

def _get_aggregator() -> ThreatIntelAggregator:
    global _aggregator
    if _aggregator is None:
        with _aggregator_lock:
            if _aggregator is None:
                _aggregator = ThreatIntelAggregator.from_env()
    return _aggregator
```

Previously, `check_threat_intel()` called `ThreatIntelAggregator.from_env()` on every invocation — discarding the per-IP result cache and re-instantiating all clients on every triage request. The singleton persists both the client objects and the cache for the lifetime of the server process. Double-checked locking ensures thread safety under concurrent Flask requests.

---

### 18-E — High Risk Example: Device Novelty + Login Hour Signals

**Problem:** The `incident_impossible_travel_mfa_fatigue.json` quick-load example scored **55/100 → MEDIUM RISK** despite being labelled as the "High Risk" scenario.

**Root cause:** Two signals were contributing zero points due to incomplete example data:

| Signal | Issue | Points Lost |
|--------|-------|-------------|
| Device novelty (15 pts) | All Moscow events had `"device_id": ""` — engine only tracks non-empty device IDs, so only `dev-001` (Alice's known laptop) appeared. No novel devices detected. | 0/15 |
| Login hour anomaly (10 pts) | All 14 events fell at 14:30–15:09 UTC, within Alice's 08:00–18:00 baseline window. No after-hours activity. | 0/10 |

**Fix — example JSON only** (`examples/incident_impossible_travel_mfa_fatigue.json`):

The scenario was enriched to reflect how a real attack of this type actually unfolds:

1. **Device novelty:** Added `"device_id": "dev-MOSCOW-UNKNOWN"` to the Moscow sign-in event (ALR-9901) and all 12 MFA fatigue events (ALR-9902). `dev-MOSCOW-UNKNOWN` is not in Alice's known device inventory (`dev-001`, `dev-002`), so device novelty now fires at full weight.

2. **Login hour anomaly:** The MFA fatigue events were moved from 15:01–15:09 UTC to **19:01–19:09 UTC** — after Alice's 18:00 business-hours cutoff. The impossible travel event (New York 14:30 → Moscow 15:00) is unchanged. The 10-minute MFA window (8 minutes, 19:01–19:09) is intact. The narrative is now: initial breach at 15:00, then the attacker re-engages with a sustained MFA push campaign after business hours.

**Resulting score:**

| Signal | Before | After |
|--------|--------|-------|
| Impossible travel | 30/30 | 30/30 |
| MFA fatigue | 25/25 | 25/25 |
| IP reputation | 0/20 | 0/20 (real APIs return clean for documentation IPs) |
| Device novelty | 0/15 | **15/15** |
| Login hour anomaly | 0/10 | **8.6/10** |
| **Total** | **55 → MEDIUM** | **79 → HIGH RISK** ✓ |

---

## Phase 19 — Performance Hardening (Zero-Regression Optimisation Pass)

**Scope:** Eliminate unnecessary I/O, add database indexes, cap the LLM timeout, and ship production frontend assets. All 5 changes are pure performance improvements with no functionality change. Security controls left intentionally intact. **213 tests still passing.**

---

### Background: what was slow and why

A full read-only audit of the codebase identified 14 performance issues across the stack. Five were safe to fix immediately (no security trade-offs, no architectural changes). The remaining nine were either intentional security controls or require larger architectural decisions:

| Left intentionally slow | Reason |
|------------------------|--------|
| VirusTotal 15s rate-limit sleep | API ToS compliance — violating it bans the key and loses a threat intel source. The implementation is already smart (elapsed-time-aware, not a raw `time.sleep`). Requires a paid VT key to lower. |
| Synchronous audit log writes blocking the triage response | NIST 800-61 compliance — async writes risk dropped audit records on process crash. |
| 10s HTTP timeouts on all three intel providers | Security control against slow-loris-style upstream attacks and resource exhaustion. |

---

### Fix 1 — MitreMapper module-level singleton (`adte/intel/mitre_mapper.py`)

**Before:** `get_techniques()` called `MitreMapper.load()` on every invocation, reading and parsing `examples/mitre_technique_map.yaml` from disk each time. The YAML never changes at runtime.

**After:** A module-level `_singleton` variable with a `threading.Lock` (double-checked locking pattern) caches the first load for the lifetime of the process. `get_techniques()` now calls `_get_mapper()` instead of `MitreMapper.load()`. The YAML is parsed exactly once per process.

- Saves ~20ms per triage request (disk read + YAML parse eliminated)
- Thread-safe: concurrent Flask workers cannot race on initialization
- `MitreMapper.load()` classmethod is unchanged — direct callers (tests, `llm_assist.py`) are unaffected
- If the YAML file is missing, `_get_mapper()` returns `None` and `get_techniques()` returns `[]` — identical behaviour to the previous try/except path

**Note:** `llm_assist.py` already had its own `_mapper: MitreMapper = MitreMapper.load()` at module level (for the deterministic summary path). The new singleton in `mitre_mapper.py` is independent and specifically covers the `get_techniques()` call path used by the server route.

---

### Fix 2 — SQLite indexes on audit log tables (`adte/store/audit_log.py`)

**Before:** The `verdicts` and `feedback` tables had no indexes. `query_verdicts()` used `WHERE verdict = ?` and `query_feedback()` used `WHERE incident_id = ?` — both full table scans. Performance degrades linearly as the audit log grows.

**After:** Three indexes added via `CREATE INDEX IF NOT EXISTS` in `init_db()`:

```sql
CREATE INDEX IF NOT EXISTS idx_verdicts_verdict    ON verdicts(verdict);
CREATE INDEX IF NOT EXISTS idx_verdicts_incident_id ON verdicts(incident_id);
CREATE INDEX IF NOT EXISTS idx_feedback_incident_id ON feedback(incident_id);
```

`CREATE INDEX IF NOT EXISTS` is idempotent — safe to run against existing databases (the live `adte_audit.db` will pick up the indexes on next server start). No schema migration needed.

- Verdict History filter dropdown (`?verdict=high_risk`) now uses an index scan instead of a full table scan
- Feedback History filter by incident ID uses an index scan
- No effect on insert performance at current scale (SQLite index overhead is negligible for audit log volumes)

---

### Fix 3 — LLM API call timeout (`adte/llm_assist.py`)

**Before:** `client.messages.create()` had no `timeout=` argument. The Anthropic Python SDK default is 600 seconds (10 minutes). If the Claude API was degraded or unreachable, the Flask worker thread would hang for up to 10 minutes — fully blocked, unable to serve any other request.

**After:** `timeout=30.0` added to the `messages.create()` call.

- 30 seconds is generous for a 1024-token response and covers normal API latency
- On timeout, the SDK raises an exception; `_call_claude()` catches it (the broad `except Exception` was already there) and returns `None`, triggering the deterministic fallback path transparently
- The safety contract is unchanged: LLM output remains advisory-only regardless of which path runs
- Test suite unaffected: the mock `MagicMock` for `client.messages.create` accepts any keyword arguments

---

### Fix 4 — FPRegistry module-level cache with atomic invalidation (`adte/intel/sigma_fp_registry.py`)

**Before:** `FPRegistry.load()` was called inside the `/api/triage` route handler on every request, reading and parsing `fp_registry.yaml` from disk each time.

**Why it wasn't a simple singleton:** When an analyst submits FP feedback via `POST /api/feedback`, `add_fp_entry()` writes a new CIDR entry to the YAML file. A naïve module-level cache would make that update invisible until server restart.

**After:** A path-keyed `_registry_cache: dict[str, FPRegistry]` dictionary with its own `_registry_cache_lock`, separate from the existing write lock `_fp_write_lock`.

- `FPRegistry.load()` checks the cache first; populates it on miss
- `add_fp_entry()` invalidates the cache entry for the written path **inside the write lock**, atomically with the file write — so no window exists where stale cached data and fresh file content coexist
- The verification `FPRegistry.load(path)` call at the end of `add_fp_entry()` (which confirms the YAML is still parseable after the write) then repopulates the cache with the fresh data
- Analyst FP feedback still takes effect on the very next triage request — behaviour is identical to before
- Cache is keyed by resolved absolute path string, so temp-path tests remain fully isolated from each other

---

### Fix 5 — React production builds in frontend (`frontend/index.html`)

**Before:**
```html
<script src="https://unpkg.com/react@18/umd/react.development.js"></script>
<script src="https://unpkg.com/react-dom@18/umd/react-dom.development.js"></script>
```
Development builds include extra runtime warnings, developer tooling hooks, and detailed error overlays — roughly 2× the minified size.

**After:**
```html
<script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
<script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
```

- No behavioral change whatsoever — same React 18 API, same JSX compilation via Babel standalone, same Chart.js
- Roughly halves the React payload downloaded on initial page load
- Eliminates development-mode runtime overhead (prop-type checks, extra logging, etc.)

---

### What was not changed

- **VirusTotal `rate_limit_sleep`** — the 15-second inter-request delay is API ToS compliance. The implementation (elapsed-time-aware, not a dumb sleep) is already optimal for a public key.
- **Audit log writes on the triage hot path** — NIST 800-61 requires synchronous audit trail capture.
- **10-second HTTP timeouts on intel providers** — a security control, not a bug.
- **Babel standalone for JSX** — removing it requires a build toolchain (webpack/Vite), which is out of scope for this pass.
- **FPRegistry per-request load in non-default-path calls** — unchanged; only the common server path (default registry) benefits from the cache.

---

## Phase 20 — UI Navigation Consolidation

**Scope:** Reduce sidebar nav from 11 items to 9 by merging two pairs of functionally overlapping views. No backend changes. No test changes. 213 tests still passing.

### Combination 1 — Threat Intel + IP Reputation → single "Threat Intel" view

**Problem:** Two separate sidebar entries existed for what is effectively one workflow. "IP Reputation" displayed the `ip_reputation` signal extracted from the last triage result and provided a "click to look up in Threat Intel" affordance that navigated the user away to a separate view. The cross-view dependency created friction with no functional justification.

**Change:** `IpRepView` removed from routing. The `ip-reputation` nav entry removed. `IntelView` gains a conditional top section — rendered only when a triage result exists — that shows:
- `IP REPUTATION SIGNAL — LAST TRIAGE` section label
- Score bar and signal detail text (identical to the old IpRepView panel)
- IP table with clickable rows that populate the lookup input inline (no navigation needed)
- Horizontal divider separating the signal context from the manual lookup tool

The `IP Threat Intelligence` lookup form, result card, and 5-entry history panel are unchanged below the divider. When no triage has been run the signal section is absent and the view is a plain IP lookup tool — identical to the original `IntelView`.

**Nav change:** INTEL section reduced from 2 items (`threat-intel`, `ip-reputation`) to 1 (`threat-intel`).

### Combination 2 — Verdict History + Feedback History → "Audit Log"

**Problem:** Both views lived under the same `AUDIT` nav section, had near-identical structure (paginated table, filter input, Clear All button, loading skeleton, empty/error states), and represented the same concern — the persistent audit trail. Separate entries doubled the nav noise for no functional gain.

**Change:** A thin `AuditView` wrapper component was added. It renders a `VERDICTS / FEEDBACK` sub-tab strip at the top and delegates to the unmodified `VerdictHistoryView` or `FeedbackHistoryView` depending on the active tab. Neither sub-component was touched — all state, fetch logic, filter behaviour, and Clear All functionality remain identical.

**Nav change:** AUDIT section reduced from 2 items (`verdict-history`, `feedback-history`) to 1 (`audit-log` → `view:audit`). Header shows `Audit Log` when this view is active.

### Minor — Run Triage button: hourglass emoji removed

`⏳ Processing…` → `Processing…`. The emoji was inconsistent with the terminal/mono aesthetic of the rest of the UI.

### Summary

| Before | After |
|--------|-------|
| 11 sidebar nav items | 9 sidebar nav items |
| IP Rep — separate nav + view | IP Rep signal embedded as top section of Threat Intel |
| Verdict History + Feedback History — two AUDIT entries | Audit Log — one entry with VERDICTS / FEEDBACK sub-tabs |

**Test count unchanged: 213 passing.**

---

## Phase 21 — Critical Scenario, Cross-View IP Navigation, and Verdict History Redirects

**Scope:** Three frontend additions — a fourth quick-load example (CRITICAL, all five signals), clickable IP addresses across every threat-intel-adjacent view, and fully navigable Verdict History rows. No backend schema changes. Test count unchanged at 213.

---

### 21-A — CRITICAL Quick Load Tile

**Problem:** The Alert Input quick-load section had three scenarios. No example exercised all five signals simultaneously at maximum weight to demonstrate what a near-perfect-score incident looks like.

**New file — `examples/incident_account_takeover_tor_exfil.json`:**

- **INC-2025-0099:** CEO account (`eve@contoso.com`), Tokyo baseline 10:00–22:00 UTC
- **ALR-9950:** Normal Tokyo login at 14:00 UTC from `202.32.115.220` (known device `dev-004`), then attacker login from Tor exit relay `185.220.101.45` (Amsterdam, AS205100 F3 Netze e.V.) at 23:30 UTC on unknown Linux device `dev-TOR-UNKNOWN` — 9,356 km in 9.5 h, physically impossible
- **ALR-9951:** 12 consecutive MFA push denials (23:30–23:37 UTC) followed by one approval (23:38 UTC) — T1621 MFA fatigue capitulation; all from unregistered device behind Tor exit
- **Expected score (mock mode):** impossible_travel(30) + mfa_fatigue(25) + ip_reputation(20) + device_novelty(15) + login_hour_anomaly(~9) ≈ **99 → CRITICAL**

**Backend wiring (`server.py` — `_EXAMPLE_FILES`):**

```python
_EXAMPLE_FILES: dict[str, str] = {
    "critical":    "incident_account_takeover_tor_exfil.json",
    "high_risk":   "incident_impossible_travel_mfa_fatigue.json",
    "low_risk":    "incident_benign_vpn_travel.json",
    "medium_risk": "incident_needs_human_ambiguous.json",
}
```

**Frontend (`frontend/index.html`):**

- `EXAMPLE_KEYS` extended to `['critical', 'high_risk', 'medium_risk', 'low_risk']`
- `EXAMPLE_DISPLAY`, `EXAMPLE_DESCRIPTIONS`, `EXAMPLE_BADGE_CLASS` all updated with `critical` entries
- `exampleCursor % 3` → `% 4` in the two cycling-cursor references
- `badge-critical` (crimson) used — visually distinct from `badge-high` (orange)

---

### 21-B — Cross-View IP Navigation (Threat Intel Deep Links)

**Problem:** IP addresses appeared in three views — Alert Queue source IP column, IP Reputation address table, and Threat Intel Recent Lookups — but were inert text. Enriching a suspicious IP required manually copying it and navigating separately.

**Fix — `navigateToIntel(ip)` in App:**

```javascript
const navigateToIntel = useCallback((ip) => {
  setIntelIp(ip);
  setIntelResult(null);
  setIntelError(null);
  setActiveView('intel');
  setIntelAutoLookupTrigger(t => t + 1);
}, []);
```

`intelAutoLookupTrigger` is a counter watched by a `useEffect` in `IntelView`. When it increments, `handleLookup()` fires automatically — no extra click needed after navigation.

**Alert Queue (`QueueView`):**
- Source IP rendered in blue with dotted underline; `e.stopPropagation()` prevents the row-load from also firing
- Footer hint updated: `"… · Click IP to enrich · …"`

**IP Reputation view (`IpRepView`):**
- Each IP row clickable (cursor pointer, dotted underline) → `onGoIntel(ip)` → auto-lookup
- Hint added below table: `"Click any IP to look it up in Threat Intel"`

**Threat Intel Recent Lookups (`IntelView`):**
- `›` chevron added at end of each history row to signal interactivity
- IP address coloured red (malicious) or primary (clean) by threat status

---

### 21-C — Verdict History: Full Navigation Redirects

**Problem:** The Verdict History table was a static audit log. All cells were inert. Analysts reviewing past verdicts could not jump directly to the relevant analysis view.

**Design:** Each field type redirects to the most contextually relevant engine view. Redirects that depend on in-memory state are gated so they fall back gracefully when the incident is not loaded.

**Fix (`frontend/index.html` — `VerdictHistoryView`):**

Signature updated to `VerdictHistoryView({ result, onNav })`.

```javascript
const activeId = result?.incident_id;
// per row:
const isLoaded = activeId === row.incident_id;
const signalDest = isLoaded ? 'view:signals' : 'view:triage';
```

| Cell | Destination | Condition |
|------|-------------|-----------|
| **Incident ID** | Signal Breakdown | When this incident is the currently loaded result |
| **Incident ID** (shows `↩`) | Alert Input | When not the active result — prompts re-run |
| **Verdict badge** | Signal Breakdown or Alert Input | Same gate |
| **Risk score** | Signal Breakdown or Alert Input | Same gate |
| **MITRE technique badges** | MITRE / NIST view | Always — each T-code is a separate clickable badge |
| **NIST phase** | MITRE / NIST view | Always when value present |

Hint footer below the table explains all destinations. All interactive elements use `cursor: pointer` and `textDecoration: underline dotted` for visual consistency with the rest of the app.

---

## Phase 22 — Verdict Export Endpoint + Render CORS Config

**Scope:** Complete the audit-trail story with a downloadable export, and fix the Render
deployment's CORS configuration. Test count 252 → 260.

### 22-A — `GET /api/verdicts/export` (`adte/server.py`)

A new endpoint streams the verdict audit log as a downloadable file. It reuses the existing
`query_verdicts()` filters so the export matches what the Verdict History view shows.

- **Role:** `analyst` (same as `GET /api/verdicts`); **rate limit:** 10/minute
- **`format`** — `csv` (default) or `json`; invalid values return 400
- **`verdict`** — optional exact-match filter (e.g. `high_risk`)
- **`since`** — optional ISO 8601 lower bound on `logged_at`; invalid values return 400
- **`limit`** — default 1000, capped at 10000 (higher than the 500 cap on the paginated view
  because an export is a deliberate bulk pull)
- **CSV** is generated with the stdlib `csv.DictWriter` against an explicit column list
  (`_EXPORT_COLUMNS`) so the file layout is stable regardless of SQLite column order. Both
  formats return a `Content-Disposition: attachment` header with a UTC-timestamped filename
  (`adte_verdicts_YYYYMMDDTHHMMSSZ.csv`/`.json`).

No new dependencies — stdlib `csv` + `io`, and `Response` from Flask.

**Tests (`tests/test_verdict_export.py`) — 8 new:** default-format-is-csv, csv-contains-data,
json-format, format-case-insensitive, verdict-filter-passthrough, invalid-format-400,
invalid-since-400, empty-db-header-only-csv. The fixture mirrors `test_feedback.py`'s
test-client pattern (TESTING=True, DB_PATH monkeypatched to a tmp database seeded via
`log_verdict`).

### 22-B — `render.yaml` env var fixes

- **`ADTE_CORS_ORIGINS`** added as `sync: false`. The CORS layer in `server.py` denies all
  cross-origin requests when this is unset, so the deployed UI could not reach the API from
  the Render origin. The value must be set to the Render service URL in the dashboard.
- **`OPENAI_API_KEY`** removed — OpenAI is not implemented anywhere in the engine; the
  declaration was misleading noise.

### Investigated but intentionally not done — wiring `llm_enrich()`

`enrich_alert()` keys on a `rule_description` field that `NormalizedIncident` does not have,
so wiring `.llm_enrich()` into the pipeline as-is returns a constant mock blob
(`T0000`/`Unknown`/`Manual review required`) on every triage — misleading, and redundant with
the real `get_techniques(fired)` mapping the route already computes. Left `null` until
`enrich_alert()` is adapted to map actual `NormalizedIncident` fields. See `Handoff.md` §5.3.

---

## Phase 23 — Triage-Only Consolidation (Execution Layer Removed)

**Scope:** Resolve the long-standing tension between ADTE's documented "execution /
containment" arm and the fact that nothing ever wired it. Decision: commit to ADTE
being a **triage-only** engine — it ingests, scores, and *recommends*; it performs no
automated containment. Remove the dead enforcement code and resync all docs to match.
Test count 260 → **242**.

### What was removed

| Removed | Why |
|---------|-----|
| `adte/config.py` (`SafetyConfig` + `can_execute` + `log_blocked_action`) | `can_execute()` was never called at runtime — only by `test_safety.py`. The `SafetyConfig` built in `cli.py` was a dead local, discarded immediately. |
| `tests/test_safety.py` (18 tests) | Sole consumer of `can_execute`. 260 → 242. |
| `cli.py` `--execute` / `--dry-run` flags + mutual-exclusivity check | Only fed the discarded `SafetyConfig`; meaningless without an execution path. |
| Unused `SafetyConfig` import in `conftest.py`; now-unused `sys` import in `cli.py` | Dead imports surfaced by the above. |
| `openai`, `azure-identity`, `azure-monitor-query` (runtime), `pytest-asyncio` (dev) deps | `openai` never imported (Phase 15/22 already called it misleading); `azure-*` only appeared in deleted EXTENSIONS example code; no async code exists. |
| (Prior session) `adapters/sentinel.py`, `adapters/entra_id.py` | Mock-only action adapters, never imported — the only intended consumers of the execution layer. |

### What was kept (deliberately)

- **Displayed safety posture** — `engine._build_safety()` advisory flags
  (`human_review_required`, `automated_actions_permitted`) and the `/api/config`
  gate fields both read env vars directly, not `SafetyConfig`. They survive as
  *informational* output. `docs/SAFETY.md` now documents the `ADTE_KILL_SWITCH` /
  `ADTE_DRY_RUN` / etc. env vars as a **reserved configuration model for a future
  execution layer — not currently enforced**.
- **LLM enrichment scaffolding** — `llm/enrichment.py`, `TriageEngine.llm_enrich()`,
  and the top 8 `mitre_technique_map.yaml` entries are retained as planned future
  work (still unwired; `llm_enrichment` stays `null`).

### Docs resynced

`ARCHITECTURE.md` (removed Execute stage + 6-gate block + deleted adapters from the
module map), `SAFETY.md` (rewritten to the "recommend, never act" model), `EXTENSIONS.md`
(removed Sentinel/Graph/action-execution sections; kept signal + enrichment guides),
`README.md` (242/12 tests, 9 views, removed broken demo image, recommend-only framing,
execution layer moved to roadmap), `server.py` CSP docstring (matched the actual
locked-down policy).

> **Note on the DO-NOT-MODIFY rule and the 260-test gate:** this phase deliberately
> overrode both, on explicit user instruction. The 5-signal scoring logic in `engine.py`
> is untouched; only dead execution-layer code and its tests were removed.

---

## Open Items

- **`llm_enrich()` in server pipeline** — implemented and tested but intentionally not wired; `enrich_alert()` must first be adapted to map real `NormalizedIncident` fields (it currently keys on a non-existent `rule_description` and always returns a mock blob). `llm_enrichment` stays `null` until then. Retained as planned future work.
- **Automated containment / response-execution layer** — removed in Phase 23; ADTE is recommend-only. If revived, `docs/SAFETY.md` documents the reserved env-var gating contract it is expected to honour.
- **Real Sentinel REST API** — live ingestion from Azure Monitor / SecurityIncidents table is not implemented (ADTE accepts the Sentinel incident JSON *format* only).
- **Batch processing for mock source** — `--source mock` processes one file at a time; a `--batch` flag for a directory of incidents is not implemented.
- **SOAR-ready output** — the verdict JSON is structured but not yet validated against any SOAR platform's action schema.
