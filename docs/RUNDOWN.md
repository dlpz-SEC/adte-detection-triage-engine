# ADTE System Rundown

**Autonomous Detection & Triage Engine — Complete Technical Reference**

> For recruiters and David. Covers startup, authentication, roles, features, security model, and deployment path.

---

## Table of Contents

1. [Quick Start: Spinning Up ADTE](#1-quick-start-spinning-up-adte)
2. [RBAC: Role-Based Access Control & The ADTE_API_KEY_ADMIN System](#2-rbac-role-based-access-control--the-adte_api_key_admin-system)
3. [Four Tiers: readonly, analyst, senior_analyst, admin](#3-four-tiers-readonly-analyst-senior_analyst-admin)
4. [How ADTE Separates Work by User](#4-how-adte-separates-work-by-user)
5. [Recruiter Access: Live Deployment](#5-recruiter-access-live-deployment)
6. [Admin Access: Full Permissions & Development Workflow](#6-admin-access-full-permissions--development-workflow)
7. [ADTE Feature Map: What Each Part Does](#7-adte-feature-map-what-each-part-does)
8. [API Keys: Where They Live & Why](#8-api-keys-where-they-live--why)
9. [Detailed Permission Breakdown](#9-detailed-permission-breakdown)
10. [Recent Security Improvements: P12–P15 Summary](#10-recent-security-improvements-p12p15-summary)
11. [Taking ADTE Public: What's Needed](#11-taking-adte-public-whats-needed)
12. [Startup & Access Troubleshooting](#12-startup--access-troubleshooting)

---

## 1. Quick Start: Spinning Up ADTE

**Getting ADTE Running — Complete Startup Sequence**

### Prerequisites

```powershell
git clone https://github.com/dlpz-SEC/adte-detection-triage-engine.git
cd adte-detection-triage-engine
pip install -e ".[dev]"
```

### Step 1 — Set Required Env Vars

At minimum, set the admin API key. All others are optional (the engine falls back gracefully).

```powershell
# RBAC keys — set at least admin to enable auth
$env:ADTE_API_KEY_ADMIN   = "adte-admin-$(New-Guid)"   # generate once, save to Bitwarden
$env:ADTE_API_KEY_SENIOR  = "adte-senior-$(New-Guid)"
$env:ADTE_API_KEY_ANALYST = "adte-analyst-$(New-Guid)"
$env:ADTE_API_KEY_READONLY = "adte-readonly-$(New-Guid)"

# Threat intel (optional — mock fallback if unset)
$env:ADTE_ABUSEIPDB_KEY = "your-abuseipdb-key"
$env:ADTE_VT_API_KEY    = "your-virustotal-key"
$env:ADTE_OTX_KEY       = "your-otx-key"

# LLM narrative summaries (optional — deterministic template if unset)
$env:ANTHROPIC_API_KEY = "sk-ant-..."

# Wazuh live integration (only needed if Wazuh VM is running)
$env:ADTE_WAZUH_HOST = "https://192.168.127.129:9200"
$env:ADTE_WAZUH_USER = "wazuh-api-user"
$env:ADTE_WAZUH_PASS = "your-wazuh-password"
```

> **Note:** If no `ADTE_API_KEY_*` vars are set, ADTE runs in demo mode — read requests (GET/HEAD/OPTIONS) pass through without a key, but **every write (POST/PUT/DELETE/PATCH) returns 403 "Demo mode active"**. This keeps un-keyed browsing friction-free without ever allowing un-keyed triage or deletion.

### Step 2 — Start the Flask Server

```powershell
python -m adte.server
# Server starts on http://localhost:5000
```

### Step 3 — Open the UI

Navigate to [http://localhost:5000](http://localhost:5000) in a browser. The single-page app (React, esbuild-bundled: `frontend/src/app.jsx` → `frontend/bundle.js`) loads immediately.

### Step 4 — Log In with Your API Key

1. Open **Settings** (gear icon, top-right).
2. Paste the value of `ADTE_API_KEY_ADMIN` into the **ADTE API Key** field.
3. Click **Log In**. The browser exchanges the key for an **HttpOnly session cookie** via `POST /api/auth/login` — the raw key is never persisted browser-side. Sessions are SQLite-backed (tokens SHA-256-hashed at rest), expire after 8 hours, and are revoked on logout.

### Subsystem Status Checks

| Subsystem | How to Verify |
|-----------|---------------|
| Server alive | Header shows green dot; `/health` returns `{"status": "ok"}` |
| RBAC active | Settings panel shows "RBAC Active" badge when key is saved |
| Live SIEM source | Alert Queue shows **source: wazuh** or **source: sentinel** (ladder order); with no live adapter configured/reachable it falls back to **source: demo** — 8 seeded demo incidents (4 Sentinel identity examples + 4 raw Wazuh malware alerts), labeled DEMO MODE in the UI |
| Threat intel firing | Triage result shows `source: abuseipdb,virustotal,otx` instead of `source: mock` |
| LLM summaries active | Settings panel shows **LLM Summaries: AVAILABLE** badge; triage result includes `one_paragraph_summary` narrative |

### Generating Test Alerts (Wazuh VM)

To populate the alert queue with real Wazuh data, run an SSH brute-force loop on the Kali VM:

```bash
# On the Kali VM — generates rule.level 10+ authentication failure alerts
for i in $(seq 1 50); do sshpass -p wrongpassword ssh -o StrictHostKeyChecking=no testuser@target 2>/dev/null; done
```

Then refresh the Alert Queue view in the UI (or set **hours=1**, **limit=100**). The queue will populate with live Wazuh alerts triaged in real time.

---

## 2. RBAC: Role-Based Access Control & The ADTE_API_KEY_ADMIN System

**Authentication & Authorization**

### What ADTE_API_KEY_ADMIN Is

`ADTE_API_KEY_ADMIN` is a UUID-format bearer token. It is the master credential for ADTE's own server — not a third-party key. You generate it once at startup and it remains valid as long as the server is running with the same env var.

### Where It Comes From

```powershell
# Generate a new admin key
$env:ADTE_API_KEY_ADMIN = "adte-admin-$(New-Guid)"

# Print it so you can copy it to Bitwarden
Write-Host $env:ADTE_API_KEY_ADMIN
```

### How the Server Validates Keys

Every secured request must carry either the `adte_session` HttpOnly cookie (browser clients, set at login) or an `X-ADTE-Key` header (CLI / programmatic clients):

```
X-ADTE-Key: adte-admin-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

The `require_role` decorator on each endpoint does the following:

1. Checks if `app.config["TESTING"]` is set → if yes, bypass (test suite only).
2. Checks if any `ADTE_API_KEY_*` env var is configured → if none set, demo mode: GET/HEAD/OPTIONS pass through, every write returns **403 "Demo mode active"**.
3. Looks for the `adte_session` HttpOnly cookie first → resolves it to a role, or returns **401 "Session expired"**.
4. With no cookie, reads the `X-ADTE-Key` header → returns **401** if missing or if it matches no configured key.
5. Compares the caller's role level against the endpoint's minimum role → returns **403** if insufficient.

### How to Use It in the UI

1. In the Settings view (gear icon, top-right), paste the key value into the **ADTE API Key** password field.
2. Click **Log In**. `POST /api/auth/login` exchanges the key for an HttpOnly session cookie.
3. The `authHeaders()` helper in the frontend is now a **stub returning `{}`** — auth rides on the session cookie, which the browser attaches automatically (`credentials: 'include'`). JavaScript can never read the session token (HttpOnly), and no key header is injected client-side.

### Session Contract

The browser persists **no credential at all**. The raw API key exists only transiently in the login form; after **Log In** it is exchanged for an HttpOnly session cookie and discarded. Server-side, session tokens are SHA-256-hashed at rest in SQLite, expire after 8 hours, and are revoked on logout. No third-party API keys (AbuseIPDB, VirusTotal, Anthropic) ever touch the browser.

---

## 3. Four Tiers: readonly, analyst, senior_analyst, admin

**Role Hierarchy & Permissions Matrix**

Role levels are numeric — higher roles inherit all lower-role access:

| Role | Level | Env Var | Endpoints Accessible |
|------|-------|---------|----------------------|
| `readonly` | 0 | `ADTE_API_KEY_READONLY` | Public routes (`GET /`, `/health`, `/api/examples`) + `GET /api/auth-check` |
| `analyst` | 1 | `ADTE_API_KEY_ANALYST` | All readonly + triage (single + batch), queue, verdicts (+ export + stats), feedback, cases, intel |
| `senior_analyst` | 2 | `ADTE_API_KEY_SENIOR` | All analyst + `GET /api/config` |
| `admin` | 3 | `ADTE_API_KEY_ADMIN` | All endpoints + `DELETE /api/verdicts`, `DELETE /api/feedback`, `DELETE /api/cases` |

### All 24 Endpoints at a Glance

Regenerated from the `@app.route` decorators in `adte/server.py` (24 route handlers).

| # | Method | Path | Minimum Role | Rate Limit | Description |
|---|--------|------|-------------|-----------|-------------|
| 1 | GET | `/` | public | — | Serve the frontend SPA |
| 2 | GET | `/<path:filename>` | public | — | Serve static frontend assets (bundle.js, CSS, images) |
| 3 | GET | `/health` | public | — | Liveness probe (`{"status": "ok"}`) |
| 4 | GET | `/api/examples` | public | — | Load the 4 bundled example incidents as NormalizedIncident JSON |
| 5 | POST | `/api/triage` | analyst | 10/min | Run full triage pipeline on one incident (auto-detects canonical / raw Wazuh / raw Sentinel payload formats) |
| 6 | POST | `/api/triage/batch` | analyst | 5/min | Batch triage (25-alert cap, 45 s deadline, per-alert error isolation) |
| 7 | GET | `/api/queue` | analyst | 20/min | Live alert queue, triage-scored — source ladder wazuh → sentinel → demo |
| 8 | GET | `/api/verdicts` | analyst | 60/min | Audit log of past triage verdicts (filterable, newest first) |
| 9 | GET | `/api/verdicts/export` | analyst | 10/min | Download the verdict audit log as CSV or JSON |
| 10 | GET | `/api/stats/verdicts` | analyst | 10/min | Verdict distribution aggregated from the audit log |
| 11 | GET | `/api/stats/mitre` | analyst | 10/min | MITRE technique frequency aggregated from the audit log |
| 12 | GET | `/api/stats/feedback` | analyst | 10/min | FP/TP feedback ratio aggregated from the audit log |
| 13 | GET | `/api/feedback` | analyst | 60/min | Analyst FP/TP feedback history |
| 14 | POST | `/api/feedback` | analyst | 30/min | Submit FP/TP label; auto-promotes FP IPs to YAML registry |
| 15 | DELETE | `/api/verdicts` | admin | 5/min | Clear all verdict audit log rows |
| 16 | DELETE | `/api/feedback` | admin | 5/min | Clear all analyst feedback rows |
| 17 | GET | `/api/cases` | analyst | 60/min | List correlated alert cases |
| 18 | GET | `/api/cases/<case_id>` | analyst | 60/min | Case detail with member alerts |
| 19 | DELETE | `/api/cases` | admin | 5/min | Soft-delete all cases |
| 20 | GET | `/api/intel` | analyst | 30/min | Enrich a single IP against live threat intel sources |
| 21 | GET | `/api/auth-check` | readonly | — | Verify an API key and return the resolved role |
| 22 | POST | `/api/auth/login` | public | — | Exchange an API key for an HttpOnly session cookie |
| 23 | POST | `/api/auth/logout` | public | — | Revoke the current browser session |
| 24 | GET | `/api/config` | senior_analyst | 10/min | Read safety gate config + masked API key status + `llm_available` flag |

---

## 4. How ADTE Separates Work by User

**User Separation & Multi-User Scenarios**

### Key Assignment

Each user receives their own API key mapped to their role:

| Person | Role | Key Env Var |
|--------|------|-------------|
| David | `admin` | `ADTE_API_KEY_ADMIN` |
| Tier-2 supervisor | `senior_analyst` | `ADTE_API_KEY_SENIOR` |
| SOC Tier-1 analyst | `analyst` | `ADTE_API_KEY_ANALYST` |
| Auditor / recruiter | `readonly` | `ADTE_API_KEY_READONLY` |

The key determines what the user can see and do. Browser users log in once via Settings — `POST /api/auth/login` exchanges the key for an HttpOnly session cookie (SQLite-backed sessions, SHA-256-hashed tokens, 8 h TTL, revoked on logout). CLI and programmatic clients send `X-ADTE-Key` directly on each request.

### Audit Trail

The SQLite audit log (`adte_audit.db`) records every triage verdict and feedback action with:
- `incident_id` — the incident being acted on
- `verdict`, `risk_score`, `confidence` — scoring output
- `timestamp` — ISO 8601 UTC
- `label` / `ip` — for feedback rows

The audit log does not yet record *which key* submitted an action (key-to-action attribution is a planned enhancement). All verdicts and feedback are stored centrally in a single SQLite file — there is no per-user data siloing. Every role with analyst+ access can read the full history.

---

## 5. Recruiter Access: Live Deployment

**Recruiter Access — Live on Railway**

### Current State (publicly deployed)

- ADTE is **live** at [https://autonomousdetection.up.railway.app](https://autonomousdetection.up.railway.app), auto-deploying from `main` on every push.
- Recruiters enter at the **Overview** page (`#overview`) — a guided landing view of what ADTE is and how to drive it.
- A **public recruiter passkey** is published in the Settings panel and the README. It maps (via the `ADTE_API_KEY_RECRUITER` env alias) to the **analyst** role. Publishing it is intentional, not a leak — it is revoked by rotating the env var on Railway.
- The hosted queue runs in **DEMO MODE by design** — the Wazuh Indexer is VM-private and no Sentinel credentials are deployed on the host, so the queue serves the 8 seeded demo incidents and the UI labels the state DEMO MODE (expected, never an outage).

### How a recruiter gets in

1. Open [https://autonomousdetection.up.railway.app/#overview](https://autonomousdetection.up.railway.app/#overview).
2. Open **Settings** (gear icon, top-right) — the Recruiter access panel shows the passkey with a one-click fill button.
3. Click **Log In**. The key is exchanged for an HttpOnly session cookie; nothing is persisted browser-side.
4. Run triage on the four bundled scenarios, then explore the queue, cases, signal breakdown, MITRE mapping, and audit views.

**What the analyst-level passkey can and cannot do:**
- Can: load the four bundled examples, run `/api/triage` (single + batch), view queue, cases, verdicts, feedback, stats, and IP intel.
- Cannot: `DELETE` anything (admin only) or read `/api/config` (senior_analyst+).

**Security properties of the hosted deployment:**
- AbuseIPDB, VirusTotal, OTX API keys: env vars on the server, never returned in any response.
- `ANTHROPIC_API_KEY`: env var only; the browser receives `llm_available: true/false` — never the key itself.
- Session token: HttpOnly cookie, unreadable by JavaScript; SHA-256-hashed at rest server-side, 8 h TTL, revoked on logout.

---

## 6. Admin Access: Full Permissions & Development Workflow

**Admin Access: Full Permissions & Development Workflow**

### Setup Sequence

```powershell
# 1. Generate and persist the admin key
$env:ADTE_API_KEY_ADMIN = "adte-admin-$(New-Guid)"

# 2. Print it and save to Bitwarden immediately
Write-Host "Admin key: $($env:ADTE_API_KEY_ADMIN)"

# 3. Start the server
python -m adte.server

# 4. Open http://localhost:5000
# 5. Go to Settings → paste the key → Save
```

### What Admin Access Enables

| Capability | Endpoint |
|-----------|----------|
| Run triage on any incident | `POST /api/triage` |
| View live Wazuh alert queue | `GET /api/queue` |
| Read all triage verdicts | `GET /api/verdicts` |
| Read analyst feedback history | `GET /api/feedback` |
| Submit FP/TP feedback | `POST /api/feedback` |
| Enrich any IP | `GET /api/intel` |
| View safety gate config + key status | `GET /api/config` |
| **Clear all verdicts** | `DELETE /api/verdicts` |
| **Clear all feedback** | `DELETE /api/feedback` |

The admin key is the only credential that can delete data. Keep it out of any shared config file or environment that others can read.

---

## 7. ADTE Feature Map: What Each Part Does

**Feature Breakdown by Category**

### Detection & Scoring

**Weighted Scoring Engine — 5 core signals (sum 100) + 2 additive signals (cluster context +15, file reputation +40), final score capped at 100**

| Signal | Max Weight | Method |
|--------|-----------|--------|
| Impossible Travel | 30 pts | Haversine distance / time delta → speed (km/h); flags physically impossible origin shifts |
| MFA Fatigue | 25 pts | Sliding 10-min denial window + capitulation detection (T1621) |
| IP Reputation | 20 pts | Live threat intel lookup with FP suppression from YAML registry |
| Device Novelty | 15 pts | Device ID compared against user's known inventory |
| Login Hour Anomaly | 10 pts | Sign-in timestamp vs. user's baseline login-hour window |
| Cluster Context | +15 pts (additive) | Correlated-case context (shared source IP/user, 60-min window): sibling volume (1 → +5, 2 → +8, 3+ → +10) + kill-chain progression (+5), capped at 15 — applied on top of the 0–100 core score, final capped at 100. Only present when the alert actually correlates; solo alerts score byte-identically to the 5-core-signal engine. |
| File Reputation | +40 pts (additive) | File-hash verdicts from Wazuh FIM/VirusTotal alerts — the embedded VT verdict is preferred (zero API cost), with a bounded live hash lookup as fallback: malicious ratio ≥ 0.5 → +40, partial detections → +20, confirmed-no-hash → +15, clean → 0. Registered only when file evidence exists; non-file alerts score byte-identically. Aggravator only, never a mitigator. |

**Verdict thresholds:**
- `risk_score < 30` → `low_risk` — auto-close
- `30 ≤ risk_score ≤ 70` → `medium_risk` — escalate for analyst review
- `risk_score > 70` → `high_risk` — disable account, revoke sessions, P1 escalation

**Wazuh weight redistribution:** Wazuh alerts carry no geolocation or MFA data. The engine detects which signals are unevaluable and proportionally redistributes their combined 55-point weight across the three remaining signals, keeping the full 0–100 scoring range reachable. The redistribution operates over the five core signals only — the additive uplifts (cluster context, file reputation), when present, are applied after that normalisation (e.g. the both-skipped 78 becomes 83 with one correlated case sibling).

**Safety Gate Configuration (reserved — ADTE is triage-only):**

> ADTE executes no automated actions. These env vars are surfaced read-only via `GET /api/config` and are **reserved for a future execution/containment layer** — they gate nothing in the current codebase. See `docs/SAFETY.md`.

| Gate | Env Var | Default | Reserved purpose |
|------|---------|---------|-------------|
| 1. Kill Switch | `ADTE_KILL_SWITCH` | `false` | Emergency halt — overrides everything |
| 2. Dry Run | `ADTE_DRY_RUN` | `true` | Blocks all write/mutate operations |
| 3. Execution Opt-In | `ADTE_EXECUTION_ENABLED` | `false` | Second explicit confirmation required |
| 4. Tenant Allowlist | `ADTE_TENANT_ALLOWLIST` | empty (open) | Restrict to specific SIEM tenant IDs |
| 5. User/Severity Gate | `ADTE_USER_ALLOWLIST` | empty (open) | Restrict to named UPNs unless severity ≥ High |
| 6. Action Allowlist | `ADTE_ACTION_ALLOWLIST` | `CLOSE_INCIDENT,POST_COMMENT` | Whitelist of permitted action types |

There is no execution layer today, so these gates enforce nothing — the table documents the intended contract for a future containment layer.

---

### Live SIEM Ingestion (Wazuh + Sentinel)

- **Wazuh adapter** (`adte/adapters/wazuh.py`) — queries the OpenSearch Indexer (`ADTE_WAZUH_HOST`) for live alerts; the flagship live source, including the FIM/VirusTotal malware pipeline.
- **Microsoft Sentinel adapter** (`adte/adapters/sentinel.py`) — wired to a **live Microsoft Sentinel workspace**: OAuth2 client-credentials token → Log Analytics Query API (`SecurityIncident` joined with `SecurityAlert`) → normalized incidents. Env vars: `ADTE_SENTINEL_TENANT_ID` / `_CLIENT_ID` / `_CLIENT_SECRET` / `_WORKSPACE_ID` (GUIDs strictly validated). CLI: `python -m adte triage --source sentinel`. The first real Sentinel incident was fetched and triaged end-to-end on 2026-08-18.
- **Queue ladder** — `/api/queue` tries wazuh → sentinel → demo: the first adapter that is configured AND reachable wins; otherwise the 8 seeded demo incidents serve (`source: "demo"`, labeled DEMO MODE).

---

### Threat Intelligence (Server-Side Only)

| Source | Env Var | Notes |
|--------|---------|-------|
| AbuseIPDB | `ADTE_ABUSEIPDB_KEY` | Abuse reports, reputation score |
| VirusTotal | `ADTE_VT_API_KEY` | File hash detections, IP/domain reputation; 15s delay between requests (public key rate limit) |
| AlienVault OTX | `ADTE_OTX_KEY` | Pulse tags, threat classification; anonymous access works without a key |
| Mock fallback | *(none)* | Deterministic mock used when all keys are absent; safe for CI and offline testing |

**Aggregation logic across sources:**
- `is_malicious: true` if any source flags the IP, or if average confidence ≥ 0.5
- Confidence: averaged across all responding sources
- Tags: merged and deduplicated
- Private IPs (`10.x`, `172.16.x`, `192.168.x`, `127.x`) are short-circuited — no API call made

**LLM Narrative Summaries:**
- Powered by Anthropic Claude SDK (`ANTHROPIC_API_KEY` env var)
- Activated on `/api/triage` with `?use_llm=true`
- The frontend checks `llm_available` from `/api/config` and auto-activates LLM mode when available
- LLM output is advisory only — it cannot affect `verdict`, `risk_score`, or `recommended_action`
- Alert-derived fields are sanitized (control chars stripped, injection patterns redacted, 300-char truncation) before prompt construction

---

### Feedback Loop

- Analysts mark any verdict as **FP** (false positive) or **TP** (true positive) via the UI or `POST /api/feedback`.
- FP labels with an associated IP automatically append the IP to `examples/fp_registry.yaml` — the YAML-based known-benign registry used during IP reputation scoring.
- All feedback is persisted in SQLite (`adte_audit.db`) and viewable in the **Audit Log → Feedback** sub-tab.
- The feedback loop closes the detection tuning cycle: confirmed FPs suppress future false alerts for the same IP/CIDR.

---

### Alert Routing & Ticketing (Scripts)

- **`scripts/alert_router.py`** — Slack webhook integration; posts HIGH/MEDIUM risk verdicts to a configured channel. Falls back to stdout if no webhook is set. In-memory deduplication with overflow protection (MAX_QUEUE_SIZE=1000; oldest half evicted when full).
- **`scripts/ticket_client.py`** — Linear and Trello ticket creation for HIGH/MEDIUM verdicts. Structured ticket body includes verdict, risk score, MITRE techniques, and recommended actions.

---

### Frontend (11 Views)

| View | Sidebar Label | Description |
|------|--------------|-------------|
| `overview` | Overview | Landing page (`#overview`) for first-time visitors and recruiters — guided tour of what ADTE is and how to drive it |
| `triage` | Alert Input | Paste NormalizedIncident JSON, load examples, run triage, view scored result |
| `queue` | Alert Queue | Live SIEM queue (wazuh → sentinel ladder, demo fallback); click any row to load + triage instantly |
| `cases` | Cases | Correlated alert clusters (shared source IP / user / file hash); expand a case for members and kill-chain ordering |
| `signals` | Signal Breakdown | Per-signal score bars and rationale strings from the last triage run |
| `mitre` | MITRE/NIST | MITRE ATT&CK technique tags and NIST 800-61 phase badges for the active verdict |
| `intel` | Threat Intel | IP Rep signal from last triage (top section, when result exists) + IP enrichment lookup (AbuseIPDB/VT/OTX); clicking a signal IP populates the lookup inline |
| `safety` | Safety Gates | Live read of all 6 gate states from `/api/config` |
| `weights` | Signal Weights | Current signal weight configuration |
| `audit` | Audit Log | VERDICTS sub-tab: SQLite audit log with verdict filter + clear; FEEDBACK sub-tab: FP/TP labels with incident ID filter + clear |
| `settings` | Settings (gear icon, top-right) | ADTE API Key login (exchanged for an HttpOnly session cookie), Recruiter access panel with one-click passkey fill, LLM Summaries status badge |

**Design:** Dark charcoal aesthetic (SentinelOne-style), JetBrains Mono + IBM Plex Sans, Chart.js for signal visualizations. Light/dark theme toggle in header. Sidebar collapses to icon-only at 56px.

---

## 8. API Keys: Where They Live & Why

**API Keys: Where They Live & Why**

| Key Type | Storage | Returned to Browser? | Notes |
|----------|---------|---------------------|-------|
| `ADTE_ABUSEIPDB_KEY` | Server env var | Never | Masked in `/api/config` response (`xxxx****xxxx`) |
| `ADTE_VT_API_KEY` | Server env var | Never | Masked in `/api/config` |
| `ADTE_OTX_KEY` | Server env var | Never | Masked in `/api/config` |
| `ANTHROPIC_API_KEY` | Server env var | Never | Browser only sees `llm_available: true/false` |
| `ADTE_API_KEY_ADMIN` (and other roles) | Server env var; browser holds only an HttpOnly session cookie after login | Only as masked preview in `/api/config` | ADTE's own bearer token — exchanged at login, never persisted browser-side |

**Why this split:**

Third-party API keys (AbuseIPDB, VT, OTX, Claude) are server-side secrets. They authenticate ADTE to external paid services. If they leaked to the browser, any visitor could extract them from DevTools and consume your quota. The server mediates all third-party calls and returns only the enriched results.

The ADTE bearer token is ADTE's own credential — it authenticates the user to ADTE's server, not to any external service. The browser never persists it: `POST /api/auth/login` exchanges it for an HttpOnly session cookie (unreadable by JavaScript, SHA-256-hashed at rest server-side, 8 h TTL, revoked on logout).

---

## 9. Detailed Permission Breakdown

**Four Roles, Full Detail**

### `readonly` (Level 0)

**Env var:** `ADTE_API_KEY_READONLY`

**Can call:**
- `GET /` — loads the SPA
- `GET /health` — liveness check
- `GET /api/examples` — read the 4 bundled incident examples

**Cannot call:** Any `/api/triage`, `/api/queue`, `/api/verdicts`, `/api/feedback`, `/api/intel`, or `/api/config` endpoint.

**Practical effect:** Can open the UI but cannot run any triage or view any real data. The Alert Input, Alert Queue, and all data views will return 403 errors.

**Use case:** Compliance auditor who needs proof the system is running; recruiter demo with maximum access restriction.

---

### `analyst` (Level 1)

**Env var:** `ADTE_API_KEY_ANALYST`

**Can call (inherits readonly +):**
- `POST /api/triage` — run the full triage pipeline
- `GET /api/queue` — view the live alert queue
- `GET /api/verdicts` — read triage audit history
- `GET /api/feedback` — read feedback history
- `POST /api/feedback` — submit FP/TP labels (promotes FP IPs to registry)
- `GET /api/intel` — enrich any IP against live TI sources

**Cannot call:** `GET /api/config` (safety gate config), `DELETE /api/verdicts`, `DELETE /api/feedback`.

**Use case:** SOC Tier-1 analyst doing daily triage work. Full read/write access to the detection pipeline. No ability to modify system configuration or delete audit records.

---

### `senior_analyst` (Level 2)

**Env var:** `ADTE_API_KEY_SENIOR`

**Can call (inherits analyst +):**
- `GET /api/config` — view safety gate states, masked key status, `llm_available` flag

**Cannot call:** `DELETE /api/verdicts`, `DELETE /api/feedback`.

**Use case:** SOC Tier-2 supervisor or lead analyst. Can review the current safety gate configuration to understand what automated actions are enabled. Cannot delete audit records.

---

### `admin` (Level 3)

**Env var:** `ADTE_API_KEY_ADMIN`

**Can call:** Every endpoint, including:
- `DELETE /api/verdicts` — clear all verdict audit log rows (irreversible)
- `DELETE /api/feedback` — clear all analyst feedback rows (irreversible)

**Use case:** David only. Used for system administration, post-demo cleanup, and development iteration.

---

## 10. Recent Security Improvements: P12–P15 Summary

**What Changed Across the Recent Security Phases**

- **P12 — RBAC Implementation:** `require_role` decorator built and applied to all 12 endpoints. Four-tier role system (`readonly` → `analyst` → `senior_analyst` → `admin`) with numeric level comparison. Open/demo mode auto-detected when no env vars are set so development works without configuration overhead. `TESTING` bypass for the test suite.

- **P13 — SOC Dashboard aggregation endpoints:** **Shipped in Phase 29.** `GET /api/stats/verdicts` (verdict distribution), `GET /api/stats/mitre` (technique frequency), and `GET /api/stats/feedback` (FP/TP ratio) now aggregate the audit-log data — all `analyst`-role, 10/minute, with an optional ISO-8601 `since` window and soft-delete exclusion. A dashboard *view* consuming them is still future UI work; the backend they depend on is now live.

- **P14 — authHeaders() Wiring (Critical Bug Fix):** Before P14, the RBAC decorator on every endpoint was enforcing key validation, but the frontend was not actually sending the `X-ADTE-Key` header on any `fetch()` call. Every API request was returning 401 in secured mode, making RBAC completely non-functional end-to-end. P14 introduced the `authHeaders()` helper (`sessionStorage.getItem('adte_api_key')` → `{ 'X-ADTE-Key': key }`) and wired it into all 12 fetch calls, completing the auth circuit. *(Since superseded: browser auth now rides an HttpOnly session cookie set by `POST /api/auth/login`; `authHeaders()` survives as a stub returning `{}`.)*

- **P15 — Credential Hygiene (Third-Party Key Removal):** Prior Settings UI had input fields for `ANTHROPIC_API_KEY` and potentially other third-party keys, which would have stored secrets in `localStorage` and sent them to the server on settings save. P15 removed all third-party key inputs from the frontend. The server now reads `ANTHROPIC_API_KEY` from env vars only and exposes a `llm_available: bool` capability flag on `/api/config`. The browser never sees or stores any third-party key. `.env.example` was updated to document this model. The Settings view now shows a read-only **LLM Summaries: AVAILABLE / NOT CONFIGURED** badge based on the server-side flag.

---

## 11. Taking ADTE Public: What's Needed

**Deployment Considerations**

### Current State

ADTE is **live on Railway only**, at [https://autonomousdetection.up.railway.app](https://autonomousdetection.up.railway.app) (`Dockerfile` + `railway.json`, auto-deploying on every push to `main`). **Render is parked** — `render.yaml` remains in the repo but is inert (the GitHub link is severed and the service is out of the deployment picture). ADTE can also be run locally as a single `python -m adte.server` process on port 5000 serving both the Flask API and the static frontend SPA.

### Deployment Steps (when ready)

1. **Choose a host:** Render (free tier), Railway, or a VPS (DigitalOcean, Hetzner).
2. **Push to `main`** — the deploy builds the frontend (esbuild bundles `frontend/src/app.jsx` → `frontend/bundle.js`; see the `render.yaml` buildCommand and the Dockerfile).
3. **Set env vars on the host:** All `ADTE_API_KEY_*` vars, TI keys, Anthropic key, Wazuh credentials if accessible.
4. **Set `ADTE_CORS_ORIGINS`** to the public domain (e.g., `https://adte.yourdomain.com`).
5. **HTTPS only** — deploy behind a TLS terminator (Render/Railway handle this automatically).

### Critical Before Going Public

- **TI result caching + quota — addressed in Phase 29.** The aggregator now fronts all three providers with a bounded 1-hour TTL cache (in-memory, per process) and enforces per-provider daily quotas (`ADTE_TI_QUOTA_<PROVIDER>`; defaults AbuseIPDB 1000 / VT 500 / OTX 10000) that skip a provider once spent and fall back to mock when all are exhausted — so repeated-IP and high-cardinality demo traffic no longer burns free-tier quota. A cross-process/persistent cache (SQLite or Redis) is still the next step only if the app scales past a single process.
- **Live SIEM connectivity:** The Wazuh Indexer lives at a local VM address (`192.168.127.129:9200`) — not reachable from a public cloud host without a VPN tunnel or exposing the VM's port publicly. The queue endpoint walks the live-source ladder (wazuh → sentinel) and falls back gracefully to the 8 seeded demo incidents (`source: "demo"`, labeled DEMO MODE) when no live adapter is configured or reachable — the expected hosted state.

### Recruiter Access Model (live today)

```
Server runs publicly on Railway
    ↓
ADTE_API_KEY_RECRUITER set on the host (public recruiter passkey → analyst role)
    ↓
Recruiter opens https://autonomousdetection.up.railway.app/#overview
    ↓
Settings (gear icon) → one-click passkey fill → Log In (HttpOnly session cookie)
    ↓
Full triage, queue, cases, intel, and verdict history access
No ability to delete data or view safety gate config
```

---

## 12. Startup & Access Troubleshooting

**Common Issues & Fixes**

### 401 Unauthorized on All API Calls

**Cause:** The browser has no valid session — you never logged in, the 8-hour session TTL expired, or a redeploy wiped the server-side session store (sessions live on the ephemeral disk, so one re-login after every redeploy is expected).

**Fix:**
1. Check the server terminal — confirm the key is set: `Write-Host $env:ADTE_API_KEY_ADMIN`
2. In the UI, open **Settings** (gear icon, top-right) and paste that exact value into the ADTE API Key field.
3. Click **Log In**.
4. Refresh and try again.

---

### 403 Forbidden on a Specific Endpoint

**Cause:** The key in the browser maps to a role that is below the minimum required for that endpoint (e.g., a readonly key trying to call `/api/triage`).

**Fix:** Use a higher-privilege key, or confirm you are using the correct key for your intended role.

---

### Alert Queue Shows "source: demo" Instead of a Live Source

**First, note:** DEMO MODE is the **expected** state for the hosted deployment (the Wazuh Indexer is VM-private and no Sentinel credentials are deployed) — the UI labels it DEMO MODE, not an outage. The queue walks the ladder wazuh → sentinel → demo and serves the 8 seeded demo incidents on the last rung.

**To get live Sentinel data**, check the four Sentinel env vars first:
```powershell
Write-Host $env:ADTE_SENTINEL_TENANT_ID
Write-Host $env:ADTE_SENTINEL_CLIENT_ID
Write-Host $env:ADTE_SENTINEL_WORKSPACE_ID
# ADTE_SENTINEL_CLIENT_SECRET must also be set — don't echo secrets
```
All three IDs must be valid GUIDs (strictly validated at adapter construction).

**To get live Wazuh data**, the usual suspects:
- VM is not running or is not on the expected IP (`192.168.127.129`).
- `ADTE_WAZUH_HOST`, `ADTE_WAZUH_USER`, or `ADTE_WAZUH_PASS` env vars are not set.
- Wazuh services (`wazuh-manager`, `wazuh-indexer`) are stopped inside the VM.

```powershell
# Check env vars
Write-Host $env:ADTE_WAZUH_HOST
Write-Host $env:ADTE_WAZUH_USER

# Verify VM connectivity
Test-NetConnection -ComputerName 192.168.127.129 -Port 9200
```

---

### Threat Intel Shows `"source": "mock"` (No Live Enrichment)

**Cause:** No TI API keys are configured.

**Fix:**
```powershell
$env:ADTE_ABUSEIPDB_KEY = "your-key"
$env:ADTE_VT_API_KEY    = "your-key"
$env:ADTE_OTX_KEY       = "your-key"
```

Then restart the server. OTX works without a key (anonymous rate limit is generous).

---

### LLM Summaries Show "NOT CONFIGURED"

**Cause:** `ANTHROPIC_API_KEY` is not set in the server environment.

**Fix:**
```powershell
$env:ANTHROPIC_API_KEY = "sk-ant-..."
```

Restart the server. The `/api/config` endpoint will return `llm_available: true`, and the Settings badge will update to **AVAILABLE** on the next page load.

---

### Server Won't Start — ModuleNotFoundError

**Fix:** Ensure the package is installed in editable mode:
```powershell
pip install -e ".[dev]"
```

---

### Tests Fail or Drop Below 766

The project enforces a 766-test minimum. If `pytest` reports fewer than 766 passing tests after any change, something regressed. Run:
```powershell
pytest -v --tb=short
```
and investigate any failures before proceeding.

---

*Updated 2026-08-18. Reflects codebase state at the live-Sentinel milestone (766 tests).*
