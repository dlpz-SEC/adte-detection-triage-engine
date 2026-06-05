# ADTE — Session Handoff Document

**Date:** 2026-06-05
**Branch:** `main`
**Last commit:** `bbe9d7c` — "Add Render deployment config and production hardening" (2026-05-07)
**Working tree:** dirty — Phase 22 work + this session's Tier 1 dead-code removal are **uncommitted**
**Test count:** **260 passing** across 13 test files (verified this session via `.venv/Scripts/python.exe -m pytest`)

> ⚠️ Nothing in this session has been committed. The user gates all commits/pushes
> explicitly (a push triggers a Render production deploy). Do **not** commit or push
> without a fresh green-light in the same session.

---

## 1. Project Goal

Build a portfolio-grade **Autonomous Detection & Triage Engine (ADTE)** that demonstrates
real SOC automation — not a toy. The engine must:

- Ingest alerts from real or realistic SIEM sources (**Wazuh live**, Sentinel **mock**).
- Score incidents **deterministically** across five weighted behavioral signals
  (the LLM never influences the verdict).
- Produce structured, auditable verdicts with per-signal rationale.
- Expose a full-featured analyst web UI.
- Enforce a six-layer safety-gate model that defaults to blocking all automated execution.
- Survive a structured security audit with documented finding/fix pairs.

It doubles as a detection-engineering portfolio artifact. Design decisions are documented
in `docs/PROJECT_PROGRESS.md` with rationale (signal-weight justifications, security audit
findings, performance trade-off tables).

**Standing constraints (from `CLAUDE.md`):**
- DO NOT MODIFY `adte/engine.py`, `adte/models.py`, `adte/scoring/`, or existing adapter code
  (this session deliberately overrode this for provably-dead code — see §6).
- Test count must stay at **260+**; pytest must pass after any change.
- Never inflate capability claims in docs — "if it's not shipped, it's not claimed."
- NIST 800-61 phase tagging + MITRE ATT&CK technique IDs are mandatory on detections.

---

## 2. Current State

### 2.1 What's running right now

- **The app is live locally:** `http://localhost:5000` (Flask dev server, launched via
  `.venv/Scripts/python.exe -m adte.server`, running as a **background process**).
- Port 5000 was free at launch (domainaudit, its usual owner, was not running).
- Server came up in **SECURED MODE** because it loaded `.env`, which contains
  `ADTE_API_KEY_*` RBAC keys. Consequence: read-only GETs work anonymously, but
  **write actions (Run Triage, feedback, deletes) require logging in** via Settings with
  an API key. Local dev keys live in `.env` (gitignored) — analyst role is enough to run
  triage; admin role for delete/clear. Do not paste those keys into committed files.
- Smoke-tested end-to-end this session: `/health` → ok; `/` serves the SPA;
  `/api/examples` returns all 4 scenarios; `POST /api/triage` with the analyst key returns
  `high_risk / risk 79 / confidence 83 / MITRE [T1078.004, T1621, T1078]` (expected).

### 2.2 Test suite

```
.venv/Scripts/python.exe -m pytest -q     # 260 passed, ~5s
```

13 files: `test_geo`, `test_intel`, `test_policy`, `test_engine`, `test_safety`,
`test_llm_assist`, `test_wazuh_adapter`, `test_feedback`, `test_mitre_mapper`,
`test_sql_injection`, `test_audit_log`, `test_ticket_client`, `test_verdict_export`.

**TESTING bypass:** `@require_role` is skipped when `app.config["TESTING"] is True`
(set in `conftest.py`), so Flask tests need no auth headers.

**Interpreter gotcha (cost time this session):** the machine's *global* `python` lacks
`flask_cors`, so any server-importing test ERRORs with `ModuleNotFoundError`. **Always use
`.venv/Scripts/python.exe`** to run the suite or import `adte.server`.

### 2.3 Uncommitted changes in the working tree (exact `git status`)

```
 D adte/adapters/entra_id.py        # deleted this session (Tier 1 dead code)
 D adte/adapters/sentinel.py        # deleted this session (Tier 1 dead code)
 M adte/decision_policy.py          # this session: removed unused _TOTAL_WEIGHT
 M adte/engine.py                   # this session: removed unused SignInMetadata import
 M adte/intel/mitre_mapper.py       # this session: removed unused get_all_tactics()
 M adte/server.py                   # Phase 22 (prior): verdict export endpoint
 M docs/PROJECT_PROGRESS.md         # Phase 22 (prior)
 M render.yaml                      # Phase 22 (prior): CORS sync:false, OPENAI removed
?? Handoff.md                       # this file
?? tests/test_verdict_export.py     # Phase 22 (prior): +8 tests
```

Two distinct bundles of uncommitted work are intermixed:
1. **Phase 22 (prior session):** verdict-export endpoint (`GET /api/verdicts/export?format=csv|json`),
   render.yaml CORS/OPENAI cleanup, +8 tests (252 → 260).
2. **This session:** Tier 1 dead-code removal (see §6).

---

## 3. Repository Map

```
adte-detection-triage-engine/
├── adte/                       # Python package (pip install .)
│   ├── server.py               # Flask app — 12 endpoints, RBAC, rate limiting, CORS, CSP
│   ├── engine.py               # TriageEngine — 5-signal pipeline (DO NOT MODIFY*)
│   ├── models.py               # Pydantic schemas incl. SentinelIncident (DO NOT MODIFY)
│   ├── cli.py                  # Typer CLI — `triage` command (mock/normalized/wazuh)
│   ├── config.py               # SafetyConfig — 6-gate can_execute() (see §7 — vestigial)
│   ├── decision_policy.py      # Signal weights, verdict thresholds, confidence formula
│   ├── report.py               # Narrative/display report fields (advisory only)
│   ├── adapters/
│   │   └── wazuh.py            # Live Wazuh Indexer adapter (OpenSearch _search), SSRF-hardened
│   │   # sentinel.py + entra_id.py DELETED this session (were never imported)
│   ├── intel/
│   │   ├── aggregator.py       # Multi-source merge, parallel ThreadPoolExecutor, per-IP cache
│   │   ├── threat_intel.py     # Dispatcher + process-lifetime singleton aggregator
│   │   ├── abuseipdb.py / virustotal.py / otx.py   # Live clients (VT has 15s rate-limit sleep)
│   │   ├── _mock.py            # Deterministic mock — no keys needed (CI/offline)
│   │   ├── mitre_mapper.py     # YAML-driven ATT&CK mapping, singleton
│   │   └── sigma_fp_registry.py # CIDR FP registry, path-keyed cache, atomic write
│   ├── llm/
│   │   ├── assist.py           # generate_summary() — Claude narrative + deterministic fallback
│   │   └── enrichment.py       # enrich_alert() — BUILT but NOT WIRED (dead at runtime; see §8)
│   ├── store/
│   │   ├── audit_log.py        # SQLite verdicts + feedback, indexes, SOFT-delete only
│   │   └── user_history.py     # Hardcoded mock user baselines (alice/bob); sparse default
│   ├── utils/geo.py            # Haversine, travel speed, impossible-travel threshold
│   └── data/mitre_technique_map.yaml   # signal→technique map (top 8 entries unused — see §8)
├── frontend/
│   ├── src/app.jsx             # React 18 source (~2,814 lines) — 9 sidebar views
│   ├── index.html              # HTML shell, dark/light theme, Chart.js from CDN
│   ├── bundle.js               # esbuild output (built 2026-05-07; NOT rebuilt this session)
│   └── package.json            # `npm run build` → esbuild minified bundle
├── scripts/
│   ├── alert_router.py         # Standalone: polls /api/queue → Slack + tickets (untested)
│   └── ticket_client.py        # Linear → Trello dispatcher (tested)
├── tests/                      # 13 files, 260 tests
├── examples/                   # 4 SentinelIncident-format scenarios + fp_registry.yaml
│   ├── incident_account_takeover_tor_exfil.json    # CRITICAL (~99, all 5 signals)
│   ├── incident_impossible_travel_mfa_fatigue.json # HIGH (79)
│   ├── incident_needs_human_ambiguous.json         # MEDIUM (43)
│   └── incident_benign_vpn_travel.json             # LOW (5)
├── docs/                       # ARCHITECTURE, SAFETY, DECISIONS, EXTENSIONS, walkthroughs
├── render.yaml                 # Render deploy config (committed; CORS value set in dashboard)
├── pyproject.toml              # deps (incl. unused openai/azure-* — see §9)
└── CLAUDE.md                   # Project conventions + DO-NOT-MODIFY rules

* engine.py was edited this session for a one-line dead-import removal only — no logic change.
```

---

## 4. How the Engine Works (quick reference)

Pipeline (fluent, chained, in `engine.py`):
`TriageEngine(incident, profile, fp_registry).enrich().score().decide().to_output()`

Five signals, weights sum to 100:

| Signal | Weight | ATT&CK |
|---|---|---|
| Impossible travel | 30 | T1078.004 |
| MFA fatigue | 25 | T1621 |
| IP reputation | 20 | T1071 |
| Device novelty | 15 | T1078 |
| Login-hour anomaly | 10 | — |

- **Source-agnostic trick:** Wazuh alerts have no geo/MFA, so those two signals are
  *skipped* and their 55 combined points are **proportionally redistributed** across the
  3 evaluable signals (`available_weight = 100 - skipped`), keeping the 0–100 range reachable.
- **Verdict:** `<30` low · `30–70` medium · `>70` high.
- **Confidence** = coverage × agreement × 100 (separate from risk).
- **LLM is advisory only** — receives only verdict + rationale, can't change the decision.

---

## 5. Things Changed This Session

1. **Deep-dive audit of the whole codebase** to separate live code from dead weight.
   Findings were tiered (T1 truly-dead → T5 notes). Full audit lives in the chat transcript;
   the actionable residue is §6–§9 below.
2. **Clarified the Sentinel question:** the April "rebrand" commit (`abb2c9f`) only changed
   *framing* to source-agnostic; it never removed the Sentinel **mock**. The live Sentinel
   REST API was never built (roadmap only). The Sentinel *mock* = the example-JSON format
   (`SentinelIncident` + `NormalizedIncident.from_sentinel()`) + (formerly) two unused action
   adapters.
3. **Removed Tier 1 dead code** (see §6).
4. **Launched the app locally** and verified the full triage path works (see §2.1).
5. **Performance review** — concluded the deterministic core is already fast and most wins
   are in (singletons, FP cache, SQLite indexes, queue TTL, prod React build). Remaining real
   levers are I/O-bound (see §10).

---

## 6. Tier 1 Dead-Code Removal (DONE this session, uncommitted)

All five items were provably unused (traced importers across `adte/`, `tests/`, `scripts/`;
empty `adapters/__init__.py`; no test coverage). Suite still **260 passed** after removal.

| Removed | Where | Why it was dead |
|---|---|---|
| `SentinelAdapter` (file deleted) | `adte/adapters/sentinel.py` | Never imported by server/cli/engine/tests — only docs |
| `EntraIDAdapter` (file deleted) | `adte/adapters/entra_id.py` | Same — zero importers |
| `MitreMapper.get_all_tactics()` | `adte/intel/mitre_mapper.py` | Defined, never called anywhere |
| `_TOTAL_WEIGHT` constant | `adte/decision_policy.py` | Computed, never referenced |
| unused `SignInMetadata` import | `adte/engine.py` | Imported, never used in file |

> Note: this overrode the `CLAUDE.md` DO-NOT-MODIFY rule for `engine.py` and adapter code,
> on the user's explicit instruction, because the changes alter no behavior and drop no tests.

---

## 7. Vestigial Runtime Path (flagged, NOT removed)

`SafetyConfig.can_execute()` (`adte/config.py`) + its ~15 `test_safety.py` tests are now the
only remaining trace of the original **execution/containment** design. The engine emits action
**name strings** (`"disable_account"`, etc.); **nothing calls `can_execute()` at runtime** now
that the two adapters are gone. Left in place because removing it would drop the test count and
it wasn't part of the Tier 1 scope. **Open decision:** keep as documented safety scaffolding, or
remove the whole execution layer (config gate + tests).

---

## 8. Built-but-Unwired (dead at runtime)

- **`llm/enrichment.py` (`enrich_alert`) + `TriageEngine.llm_enrich()`** — never called by
  server or CLI; `llm_enrichment` is always `null`. As-is it keys on a `rule_description`
  field `NormalizedIncident` doesn't have, so it would return a misleading constant blob
  (`T0000`/`Unknown`/`Manual review required`). Wiring requires adapting `enrich_alert()` to
  map real `NormalizedIncident` fields first.
- **Top 8 entries in `data/mitre_technique_map.yaml`** (`brute_force`, `lateral_movement`,
  `privilege_escalation`, `persistence`, `data_exfiltration`, `defense_evasion`, `discovery`,
  `command_execution`) — only reachable via rule-description lookup, which only happens in the
  unwired `enrich_alert`. The live path passes the 5 signal names, matching only the bottom 5
  entries. Aspirational/dead until enrichment is wired.

---

## 9. Stale Docs / Unused Deps (identified, NOT yet fixed)

**Stale docs:**
- `README.md:231` says "213 tests across 10 files" → actually **260 / 13**.
- `README.md:307` says "Full 10-view ... single-file React SPA" → actually **9 views**, **esbuild-bundled** (not single-file Babel).
- `README.md:109` references `docs/demo-placeholder.png` → **file does not exist** (broken image).
- `server.py:330` CSP comment claims "inline React/Babel ... until the frontend is compiled" → frontend **is** compiled; comment contradicts the actual locked-down CSP below it.
- README architecture diagram + `docs/ARCHITECTURE.md` still describe the now-DELETED Sentinel/Entra adapters and an `[Execute]` stage as if active.

**Unused dependencies (`pyproject.toml`):**
- `openai>=1.0` — never imported.
- `azure-identity>=1.15`, `azure-monitor-query>=1.3` — only in `docs/EXTENSIONS.md` example code.
- `pytest-asyncio` (dev) — no async code anywhere.

---

## 10. Performance Levers (analyzed, NOT implemented)

Core is already fast; only external I/O matters. In priority order:
1. **VirusTotal 15s rate-limit sleep** (`virustotal.py`) — largest live-mode latency; free-tier
   ToS constraint. Lever: make the delay conditional on a commercial key, or demote VT to
   best-effort with a short timeout so it never blocks the verdict.
2. **Serial IP enrichment** in `engine.enrich()` — providers are parallel per IP, but multiple
   IPs are checked sequentially. Real win for multi-IP Wazuh batches; marginal for 1–2-IP demos.
   (Touches frozen `engine.py`.)
3. **Response compression** (`flask-compress`) — the ~240 KB `bundle.js` is uncompressed;
   meaningful for the Render deployment, irrelevant on localhost.

Not worth it: per-request `ThreadPoolExecutor` churn (sub-ms), gunicorn worker tuning (concurrency, not latency).

---

## 11. What To Do Next (suggested, awaiting user direction)

**Immediate / low-risk:**
- [ ] Decide commit strategy for the two intermixed uncommitted bundles (Phase 22 vs. Tier 1
      cleanup). Likely two separate commits. **Needs explicit green-light before committing.**
- [ ] Sync stale docs (§9) — README test/view counts, broken image, stale CSP comment,
      source-agnostic framing in ARCHITECTURE.
- [ ] Prune unused deps (§9): drop `openai`, `azure-identity`, `azure-monitor-query`, `pytest-asyncio`.

**Open decisions for the user:**
- [ ] §7 — keep or remove the vestigial `can_execute`/SafetyConfig execution layer.
- [ ] §8 — wire `enrich_alert()` properly (adapt field mapping) or delete it + the 8 dead YAML entries.
- [ ] Sentinel mock — finish the "scrap," i.e. rename `SentinelIncident`/`from_sentinel` to a
      source-neutral name and drop the framing. NOTE: `models.py` is on the DO-NOT-MODIFY list and
      this touches CLI + server + examples — needs a plan + explicit go-ahead.

**Performance (if requested):**
- [ ] §10 #3 (compression) + #1 (conditional VT delay) for the Render demo.

**Roadmap (not started):** real Sentinel REST API, batch processing mode, KQL rule pack,
SOAR-ready JSON action output.

---

## 12. Things Tried That Failed / Cost Time

- **Ran `pytest` with the global Python** → 12 failed + 11 errored with
  `ModuleNotFoundError: No module named 'flask_cors'`. Root cause: wrong interpreter; global
  Python lacks the server deps. **Fix: always use `.venv/Scripts/python.exe`.** Non-server
  tests (225) passed on global; full 260 only via `.venv`.
- **`POST /api/triage` returned 401** on first try → server is in secured mode (`.env` has
  RBAC keys). Not a bug — write endpoints require an API key. Verified the analyst key
  authorizes triage successfully.

---

## 13. Environment & Run Commands

```bash
# Tests (ALWAYS use the venv interpreter)
.venv/Scripts/python.exe -m pytest -q

# Launch server (background); serves SPA + API on :5000
.venv/Scripts/python.exe -m adte.server      # http://localhost:5000

# CLI triage on an example
.venv/Scripts/python.exe -m adte triage \
  --input examples/incident_impossible_travel_mfa_fatigue.json --format pretty --explain

# Rebuild frontend (only if src/app.jsx changed — NOT changed this session)
cd frontend && npm install && npm run build
```

Key env vars: `ADTE_API_KEY_{ADMIN,SENIOR,ANALYST,READONLY}` (RBAC), `ADTE_WAZUH_HOST/USER/PASS`,
`ADTE_{ABUSEIPDB,VT,OTX}_KEY` (server-side only), `ANTHROPIC_API_KEY` (enables live LLM narrative),
`ADTE_KILL_SWITCH`/`ADTE_DRY_RUN`/`ADTE_EXECUTION_ENABLED` (safety gates),
`ADTE_CORS_ORIGINS` (must be set to the Render URL in the dashboard for external use).

**Deployment:** Render (`render.yaml`), NOT Railway. Build:
`pip install . && cd frontend && npm install && npm run build`. A push to `main` deploys to prod.
