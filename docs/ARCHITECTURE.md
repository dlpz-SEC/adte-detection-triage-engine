# Architecture

## Pipeline Overview

ADTE follows the **NIST SP 800-61 Rev. 2** incident response lifecycle, implementing the Detection & Analysis phase as a deterministic, auditable pipeline:

```
                          NIST 800-61: Detection & Analysis
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│   ┌─────────┐   ┌───────────┐   ┌─────────┐   ┌───────┐   ┌────────┐     │
│   │ INGEST  │──>│ NORMALIZE │──>│ ENRICH  │──>│ SCORE │──>│ DECIDE │     │
│   └─────────┘   └───────────┘   └─────────┘   └───────┘   └────┬───┘     │
│                                                                  │         │
│                                                                  v         │
│                                                            ┌────────┐      │
│                                                            │ REPORT │      │
│                                                            └────────┘      │
│                                                                            │
└─────────────────────────────────────────────────────────────────────────────┘

ADTE is a triage engine: it ends at a structured, explainable verdict and a
*recommended* human-review action. It does not execute containment itself —
acting on the verdict (disable account, revoke sessions, etc.) is left to the
analyst or a downstream SOAR/ticketing workflow.
```

## Pipeline Stages

### 1. Ingest

**Input:** Security incident/alert payload (JSON) — from Sentinel, Wazuh, or other adapters

The CLI reads a JSON file representing a security incident/alert with embedded entities and normalised events (OCSF-inspired: each event carries a `type`, `auth_status`, and `event_risk`; the incident carries a top-level `source`). In production, this would be replaced by a source-specific webhook or polling adapter (e.g. Sentinel, Wazuh Indexer).

**Module:** `adte/cli.py` (`_load_incident`)

### 2. Normalize

**Input:** `SentinelIncident` → **Output:** `NormalizedIncident`

Extracts the primary user (Account entity), rebuilds `SignInMetadata` from alert payloads, sorts events chronologically, and produces a flat, type-safe structure optimized for signal evaluation.

**Module:** `adte/models.py` (`NormalizedIncident.from_sentinel`)

### 3. Enrich

**Input:** `NormalizedIncident` → **Output:** Internal enrichment state

For every unique IP address in the incident:
- **Threat Intelligence** — query mock threat feeds for malicious/suspicious indicators (C2, Tor, scanners, mining pools, residential proxies)
- **FP Registry** — check against known-benign CIDR patterns (corporate VPN, SSO relays, cloud NAT, travel providers)

**Modules:** `adte/intel/threat_intel.py`, `adte/intel/sigma_fp_registry.py`

### 4. Score

**Input:** Enrichment state + User profile → **Output:** Per-signal scores + aggregate risk score

Evaluates six signal classes — five core signals plus one additive context signal — each returning a weighted score (0 to weight_max), a human-readable rationale string, and a per-signal confidence:

| Signal | Max Weight | Method |
|--------|-----------|--------|
| Impossible Travel | 30 | Haversine distance / time delta → speed (km/h) |
| MFA Fatigue | 25 | Sliding 10-min window denial count + capitulation detection |
| IP Reputation | 20 | Threat intel lookup with FP suppression |
| Device Novelty | 15 | Device ID comparison against user's known inventory |
| Login Hour Anomaly | 10 | Timestamp vs. user's baseline login-hour window |
| Cluster Context (additive) | +15 | Correlated-case sibling volume + kill-chain flag, from a read-only pre-scoring case-store peek |

The base risk score is `sum(core signal scores)` (with skipped-signal weight redistribution), clamped to [0, 100]. The additive `cluster_context` uplift (up to +15) is applied after that normalisation, with the final score capped at 100. When the incident has no correlated context the signal is **not applicable** — it never enters the signal set, and the output is byte-identical to the 5-signal engine.

**Modules:** `adte/engine.py` (signal methods), `adte/decision_policy.py` (weights, `ClusterContext`), `adte/utils/geo.py`, `adte/store/user_history.py`, `adte/store/case_store.py` (`peek_correlation_context` — the read-only correlated-context snapshot taken before scoring, server routes only)

### 5. Decide

**Input:** Risk score → **Output:** Verdict + recommended actions

Maps the aggregate risk score to a categorical verdict using fixed thresholds.
Each verdict carries a *recommended* action for the analyst — ADTE surfaces it,
it does not perform it:
- `risk_score < 30` → `low_risk` → recommend auto-close / update baseline
- `30 ≤ risk_score ≤ 70` → `medium_risk` → recommend analyst review
- `risk_score > 70` → `high_risk` → recommend disable account, revoke sessions, escalate P1

**Module:** `adte/engine.py` (`decide`), `adte/decision_policy.py` (`classify_verdict`)

### 6. Report

**Input:** Full decision output → **Output:** NIST 800-61 structured report

Compiles a structured report section with incident metadata, signal summary, safety flags, and optionally an LLM-generated narrative summary. The LLM integration is advisory only — it can never override the deterministic verdict.

**Modules:** `adte/report.py`, `adte/llm_assist.py`

The pipeline ends here. The verdict, per-signal rationale, and recommended
action are returned to the caller (CLI, web UI, or `/api/triage`); any
containment is performed by a human or downstream system, not by ADTE.

### 7. Correlate (server only)

Since Phase 31, correlation touches the pipeline at **two** points:

**(a) Pre-scoring peek (read-only).** Before the engine scores, `/api/triage`, each
`/api/triage/batch` element, and `/api/queue` call
`case_store.peek_correlation_context(incident, db_path)` — a strictly read-only
snapshot using the same join rules as ingest (shared source IP or user, 60-min
ingestion-time window), excluding the incident's own `incident_id` (a re-triage never
boosts itself; a singleton case yields no context). When siblings exist, the snapshot
is passed to the engine as the optional `cluster_context` kwarg and feeds the additive
6th signal (up to +15 — see stage 4). Fail-open: any store error yields no context,
never a failed triage. Two bounded races are documented in the peek's docstring: a
sibling worker can commit a member an instant after the peek (context missed —
self-heals on the next alert), and batch element N sees elements 1..N-1 (intra-batch
correlation, so batch order matters).

**(b) Post-verdict ingest.**

**Input:** Finalized triage output + incident → **Output:** `case` blob on the response

After the verdict is audit-logged, `/api/triage` and `/api/triage/batch` call
`case_store.ingest_alert()`, which joins the alert to an open **case** (or
creates one) when it shares a source IP or user with recent alerts inside a
rolling window (`CASE_WINDOW_MINUTES`, default 60). The case receives its own
score and verdict via `adte/case_policy.py`: base = worst member, plus capped
bonuses for alert volume, distinct-ATT&CK-tactic breadth, and a detected
kill-chain progression (a strictly ascending longest-increasing-subsequence
over member tactics in event-time order, ≥3 tactics across ≥2 alerts).

Design contract:

- **The ingest layer never rewrites a computed verdict** — it only attaches the
  `case` key (and a batch-level `cases` summary). Correlated context influences
  the per-alert score exclusively through the engine's additive `cluster_context`
  signal, fed by the pre-scoring peek; solo alerts remain byte-identical to the
  5-signal engine.
- **Fail-open** — any case-store error yields `"case": null`; a verdict is
  never blocked by correlation. Reads fail closed-empty.
- **Windowing clock is ingestion time** (arrival at ADTE), so replayed demo
  fixtures with historical event timestamps still correlate; member **event
  time** is stored separately and drives kill-chain ordering.
- **Cross-worker safe** — cases live in the shared SQLite file (same DB as the
  audit log and sessions); join-or-create runs inside a `BEGIN IMMEDIATE`
  transaction so two gunicorn workers cannot create duplicate cases. No
  module-level state (the sessions lesson, commit `731600d`).
- **Cases are derived data** — the `verdicts` table remains the forensic
  record; idle cases past `CASE_RETENTION_DAYS` are hard-pruned on ingest,
  while the admin clear (`DELETE /api/cases`) is a soft delete. On an
  ephemeral disk (Railway without a volume) a redeploy clears open cases,
  same as sessions.
- `/api/queue` deliberately does **not** ingest — it re-triages the same
  incidents on every poll and would multiply case membership. (It does run the
  read-only peek, so queue rows see correlated context in their scores.)

**Modules:** `adte/store/case_store.py` (persistence, matching,
`peek_correlation_context`),
`adte/case_policy.py` (constants, scoring, kill-chain detection — freely
editable, reads no incident fields). Endpoints: `GET /api/cases`,
`GET /api/cases/<case_id>`, `DELETE /api/cases` (admin).

## Module Dependency Map

```
cli.py
├── engine.py (TriageEngine)
│   ├── decision_policy.py (weights, thresholds, confidence)
│   ├── report.py (generate_report)
│   │   └── llm_assist.py (generate_summary)
│   ├── intel/
│   │   ├── threat_intel.py (check_threat_intel)
│   │   └── sigma_fp_registry.py (FPRegistry)
│   ├── store/
│   │   └── user_history.py (get_user_profile)
│   └── utils/
│       └── geo.py (haversine, travel speed, impossible travel)
├── models.py (all Pydantic models)
└── adapters/
    └── wazuh.py (WazuhAdapter — live OpenSearch ingestion)
```

## Data Flow

```
SentinelIncident (raw JSON)
    │
    ▼  NormalizedIncident.from_sentinel()
NormalizedIncident   (OCSF-inspired, source-agnostic; severity is engine-derived, NOT an input)
    │  - incident_id, user, source (azure_ad | wazuh | okta | generic)
    │  - events: list[SignInMetadata]
    │    - timestamp, ip_address, type, location, device_id, auth_status, event_risk
    │
    ▼  TriageEngine(incident, user_profile, fp_registry, cluster_context=…)
       (cluster_context: optional read-only ClusterContext snapshot from
        case_store.peek_correlation_context() — server routes only, None solo)
TriageEngine
    │
    ├── .enrich()
    │   ├── threat_intel_results: {ip: ThreatIntelResult}
    │   └── fp_matches: {ip: pattern_type | None}
    │
    ├── .score()
    │   ├── signals: {name: (score, rationale, confidence)}
    │   ├── risk_score: int (0-100)
    │   └── confidence: int (0-100)
    │
    ├── .decide()
    │   ├── verdict: "low_risk" | "medium_risk" | "high_risk"
    │   ├── recommended_action: str
    │   └── actions: list[str]
    │
    └── .to_output()
        │
        ▼
    Output Dict
    ├── verdict: str
    ├── source: str   (origin platform, carried from the incident)
    ├── risk_score: int
    ├── confidence: int
    ├── recommended_action: str
    ├── actions: list[str]
    ├── rationale: list[{signal, score, detail}]
    ├── evidence: {threat_intel, fp_matches, sign_in_count, ...}
    ├── safety: {human_review_required, automated_actions_permitted, ...}
    └── report: {nist_phase, incident_id, severity (engine-derived), signal_summary, ...}
```

> **Three distinct `source` fields** (do not conflate):
> 1. **`incident.source`** — origin-platform enum on the input (`azure_ad` | `wazuh` | `okta` |
>    `generic`); carried through to the verdict output and audit log. Defaults to `azure_ad` for
>    Sentinel-format payloads (`from_sentinel`) and `generic` for a directly-POSTed `NormalizedIncident`.
> 2. **`/api/queue` response `source`** — data provenance: `"wazuh"` (live adapter) vs `"mock"`
>    (bundled-example fallback). Means "where the queue got its rows", not the incident's platform.
> 3. **`evidence.threat_intel[ip].source`** — the threat-intel provider name(s) for an IP lookup.

## Security Controls

### Authentication & Authorization

All API endpoints are protected by a role-based access control (RBAC) system:

| Role | Level | Access |
|------|-------|--------|
| `readonly` | 0 | Static frontend, health check, examples |
| `analyst` | 1 | Triage, queue, verdicts, feedback, intel |
| `senior_analyst` | 2 | Configuration view |
| `admin` | 3 | DELETE endpoints (clear verdicts/feedback) |

Authentication is via `X-ADTE-Key` header matched against per-role environment variables (`ADTE_API_KEY_ADMIN`, `ADTE_API_KEY_SENIOR`, `ADTE_API_KEY_ANALYST`, `ADTE_API_KEY_READONLY`).

### Rate Limiting

- `POST /api/triage`: 10 requests/minute per IP
- `POST /api/feedback`: 30 requests/minute per IP
- `GET /api/verdicts/export`: 10 requests/minute per IP
- `GET /api/config`: 10 requests/minute per IP
- `GET /api/cases` and `GET /api/cases/<id>`: 60 requests/minute per IP
- `DELETE /api/cases`: 5 requests/minute per IP (admin)
- Returns JSON `{"error": "Rate limit exceeded"}` with HTTP 429

### CORS

Configured via the `ADTE_CORS_ORIGINS` environment variable (comma-separated origins). Defaults to **deny-all** when unset (the self-hosted UI is same-origin); set it to the frontend origin(s) when the UI is hosted separately.

### Input Validation

- **FP Registry:** Strict IP/CIDR validation via `ipaddress` module before any filesystem write.
- **LLM Prompts:** Alert-derived fields are sanitized (control characters stripped, injection patterns redacted, length-capped) before prompt assembly. System prompt includes a hard security boundary delimiter.
- **SQLite:** All queries use parameterized `?` placeholders. Regression tests verify SQL injection payloads are stored as data, not executed.

### Credential Safety

- API keys are never logged or returned in full — the `/api/config` endpoint masks keys to `xxxx****xxxx` format.
- Wazuh adapter's `__repr__` excludes the password field.
- No credential values appear in any `_log.*` call across the codebase.

### Queue Overflow Protection

The alert router (`scripts/alert_router.py`) caps the in-memory `seen_ids` set at `MAX_QUEUE_SIZE=1000`. When full, the oldest half is evicted with a WARNING log.

## Key Design Principles

1. **Determinism** — The same input always produces the same verdict. No randomness, no external state mutation during scoring.
2. **Explainability** — Every signal produces a human-readable rationale string. The output includes full evidence and signal breakdowns.
3. **Human-in-the-loop by default** — ADTE recommends, it does not act. Every medium/high verdict is flagged `human_review_required`; containment is always a human or downstream-system decision.
4. **Separation of concerns** — Ingestion, enrichment, scoring, and policy are isolated modules with clean interfaces.
5. **Auditability** — Every verdict is persisted to the SQLite audit log. The report section includes timestamps, signal scores, and NIST phase alignment.
