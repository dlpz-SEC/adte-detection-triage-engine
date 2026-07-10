# ADTE — Autonomous Detection & Triage Engine

<div align="center">

![SOC Engineering](https://img.shields.io/badge/SOC%20Engineering-Incident%20Triage-0B1220?style=for-the-badge&logo=microsoftsecurity&logoColor=white)
![Detection Logic](https://img.shields.io/badge/Detection%20Logic-Risk--Based%20Decisioning-1D4ED8?style=for-the-badge&logo=opensearch&logoColor=white)
![Automation](https://img.shields.io/badge/Automation-Recommend--Only%20Triage-DC2626?style=for-the-badge&logo=githubactions&logoColor=white)
![Explainability](https://img.shields.io/badge/Explainability-Transparent%20Verdicts-6D28D9?style=for-the-badge&logo=googledocs&logoColor=white)

</p>

![Multi-Source SIEM](https://img.shields.io/badge/SIEM-Multi--Source%20Ingestion-0078D4?style=for-the-badge&logo=shield&logoColor=white)
![Python](https://img.shields.io/badge/Python-Engineering%20Logic-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Pytest](https://img.shields.io/badge/Testing-Pytest-0A9EDC?style=for-the-badge&logo=pytest&logoColor=white)

</div>

---

## Premise

Security Operations Centers (SOCs) are overwhelmed. Analysts spend hours manually triaging hundreds of alerts per day — most of which are false positives or low-confidence noise. The ones that matter (credential theft, active intrusions, MFA fatigue attacks) require fast, structured decisions, not ad-hoc guesswork.

**ADTE is an automated first-responder for that triage step.**

When a security alert arrives — from Microsoft Sentinel, Wazuh, or any supported source — ADTE evaluates it across five behavioural signals derived from real-world attack patterns:

1. **Impossible Travel** — Did the user physically teleport? New York to Moscow in 30 minutes is not a VPN quirk; it's stolen credentials.
2. **MFA Fatigue** — Are repeated push denials followed by an approval? That's T1621: an attacker wearing down a user until they accidentally approve.
3. **IP Reputation** — Is the source IP flagged by AbuseIPDB, VirusTotal, or AlienVault OTX as C2, Tor, or a known scanner?
4. **Device Novelty** — Is this the first time this device has been seen for this user? A compromised machine posing as the user won't be in the inventory.
5. **Login Hour Anomaly** — Is the activity happening at 2 AM when the user is typically offline? Attackers don't respect business hours.

Each signal is weighted by its real-world reliability and combined into a 0–100 risk score. The score maps to a verdict:

| Risk Score | Verdict | Recommended Response |
|-----------|---------|-------------------|
| > 70 | **HIGH RISK** | Disable account, revoke sessions, page Tier-2 |
| 30–70 | **MEDIUM RISK** | Escalate to analyst for review within SLA |
| < 30 | **LOW RISK** | Auto-close, update baseline |

The verdict is **deterministic** — the same incident always produces the same score, the same rationale, the same recommended action. There is no black box. Every decision can be explained signal by signal.

ADTE recommends, it does not act. The pipeline ends at an explainable verdict and a *recommended* action; every medium/high verdict is flagged for human review. Acting on a verdict — disabling an account, revoking sessions, closing an incident — is left to the analyst or a downstream SOAR/ticketing workflow. There is no code path in ADTE that mutates an external system.

ADTE is not a SOC replacement. It is a force multiplier — it handles the mechanical triage so analysts can focus on the cases that actually need human judgment.

---

## What This Is

- Automated triage for security incidents from multiple sources using 5 weighted signals
- Source-agnostic OCSF-inspired incident schema — normalized `events[]` with per-event `type` and `source`; severity is engine-derived (rejected on input)
- Deterministic scoring (0-100 risk score, 0-100 confidence)
- Human-in-the-loop by default — recommends an action, never executes one
- Explainable decisions with per-signal rationale
- CLI and web UI for running triage and reviewing verdicts

## What This Is NOT

- Not a SOC replacement — human review required for medium/high risk
- Not an actuator — it recommends containment, it does not perform it
- Not a detection rule library — focuses on triage, not alert generation
- Not magic — garbage signals in = garbage verdicts out

## Architecture

```
Security Alert / Incident
  (Wazuh live, Sentinel-format JSON)
       ↓
  [Normalize]
       ↓
   [Enrich]  ← Threat Intel, User History, FP Registry
       ↓
    [Score]  ← 5 weighted signals (travel, MFA, IP rep, device, hours)
       ↓
   [Policy]  → Verdict: LOW / MEDIUM / HIGH
       ↓
   [Report]  → Verdict + per-signal rationale + recommended action
                (returned to analyst / web UI / downstream workflow)
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed pipeline and module dependency map.

## Quickstart

```bash
git clone https://github.com/dlpz-SEC/adte-detection-triage-engine.git
cd adte-detection-triage-engine
pip install -e ".[dev]"
pytest -v

# Run triage on example incidents (mock source, default)
python -m adte triage --input examples/incident_impossible_travel_mfa_fatigue.json --format pretty --explain
python -m adte triage --input examples/incident_benign_vpn_travel.json --format pretty --explain
python -m adte triage --input examples/incident_needs_human_ambiguous.json --format pretty --explain
```

## Demo

Interactive web UI for running triage on incident JSON and reviewing verdicts live.  No CLI required — paste any `NormalizedIncident` JSON, or use the **Quick Load** tiles to pre-fill one of the four bundled scenarios (critical / high / medium / low), then click **Run Triage**.

```bash
python -m adte.server
# Open http://localhost:5000
```

## Wazuh Integration

> **Infrastructure requirement:** This integration connects to a Wazuh Indexer running at `localhost:9200` inside a local VM. It is not publicly demo-able — the integration is demonstrated via screenshots and the adapter code itself. The cloud threat intel integrations (AbuseIPDB, VirusTotal, OTX) below are publicly usable by anyone with free-tier API keys.

Pull live alerts from a local Wazuh Indexer (OpenSearch at port 9200):

```bash
export ADTE_WAZUH_HOST=https://localhost:9200   # default
export ADTE_WAZUH_USER=wazuh-api-user
export ADTE_WAZUH_PASS=your-password

# Triage all alerts from the last 24 hours
python -m adte triage --source wazuh --hours 24 --format pretty --explain

# Limit to 100 alerts (warning logged if more exist)
python -m adte triage --source wazuh --hours 6 --limit 100 --format json
```

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `ADTE_WAZUH_HOST` | `https://localhost:9200` | Wazuh Indexer (OpenSearch) base URL |
| `ADTE_WAZUH_USER` | *(required)* | Wazuh API username |
| `ADTE_WAZUH_PASS` | *(required)* | Wazuh API password |

**Signal behaviour for Wazuh alerts:**

Wazuh alerts carry no geolocation data and no MFA events. The engine
automatically skips those two signals and redistributes their combined
weight (55 pts) proportionally across the three evaluable signals, so
the full 0–100 scoring range remains reachable:

| Signal | Wazuh behaviour |
|--------|-----------------|
| Impossible travel (30 pts) | **Skipped** — no geo data; weight redistributed |
| MFA fatigue (25 pts) | **Skipped** — no MFA events; weight redistributed |
| IP reputation (20 pts) | Evaluated normally |
| Device novelty (15 pts) | Evaluated normally (agent ID used as device ID) |
| Login hour anomaly (10 pts) | Evaluated normally |

When both signals are skipped, the effective scale is `100/45`:
- IP + device fire → score 78 → `high_risk`
- IP alone → score 44 → `medium_risk`

**Pagination and `--limit`:** ADTE pages through all available Wazuh alerts
automatically (500 per request). Use `--limit N` to cap the total; a
warning is printed to stderr when alerts are truncated.

## MITRE ATT&CK Integration

ATT&CK mapping runs end-to-end through the backend, not as a cosmetic label:

- **Native ingestion.** When a Wazuh/OpenSearch alert carries `rule.mitre.id`,
  those technique IDs are ingested onto the event and unioned into the verdict's
  `mitre_techniques` — the log source's own labeling is trusted, not
  reverse-engineered.
- **Signal + keyword derivation.** Fired scoring signals and per-event rule text
  are mapped against a curated 40-entry technique map
  (`adte/data/mitre_technique_map.yaml`) covering technique **and** sub-technique
  IDs across Credential Access, Lateral Movement, C2, Exfiltration, Defense
  Evasion, Persistence, and more.
- **`mitre_details` in every verdict.** Alongside the bare-ID `mitre_techniques`
  list, each triage response carries
  `mitre_details: [{id, name, tactic, source}]` where `source` is `signal`,
  `native`, or `rule_text` — so the provenance of every technique is explicit.
- **Advisory enrichment.** `llm_enrichment` resolves native IDs first
  (`source: "native_log"`), then keyword lookup (`deterministic_mapping`), else
  `null`. It is **advisory only** and never affects the verdict, risk score, or
  confidence.
- **Technique frequency stats.** `GET /api/stats/mitre` aggregates technique
  recurrence across the verdict audit log.

## Threat Intelligence API Keys

ADTE enriches IP addresses against live threat intelligence sources when API
keys are configured.  All keys are optional — without any keys the engine
falls back to deterministic mock lookups suitable for offline testing and CI.

| Environment Variable | Source | Required |
|---------------------|--------|----------|
| `ADTE_ABUSEIPDB_KEY` | [AbuseIPDB](https://www.abuseipdb.com) | No (mock fallback) |
| `ADTE_VT_API_KEY` | [VirusTotal](https://www.virustotal.com) | No (mock fallback) |
| `ADTE_OTX_KEY` | [AlienVault OTX](https://otx.alienvault.com) | No (anonymous allowed) |

### Setup

1. Register for free API keys at each provider.
2. Add keys to your `.env` file (gitignored) or export them in your shell:

```bash
export ADTE_ABUSEIPDB_KEY=your_abuseipdb_key
export ADTE_VT_API_KEY=your_virustotal_key
export ADTE_OTX_KEY=your_otx_key   # optional — OTX works without a key
```

3. Run triage normally — the engine automatically uses live APIs when keys are set.

### Aggregation Logic

When multiple sources are configured:

- **Confidence**: averaged across all sources that respond without error.
- **`is_malicious`**: `True` if any source flags the IP, or if average confidence ≥ 0.5.
- **Tags**: merged and deduplicated across sources.
- **Source**: comma-joined provider names (e.g. `"abuseipdb,virustotal,otx"`).
- **Fallback**: if all configured sources return errors, the mock lookup is used and a warning is logged.
- **Private IPs**: `127.x`, `10.x`, `172.16.x`, `192.168.x` are short-circuited without any API call.

### Rate Limits

VirusTotal public keys are limited to 4 requests/minute.  ADTE applies a
15-second inter-request delay automatically.  For high-volume triage, use a
commercial API key or expect delays.

## Signal Weights

| Signal | Weight | Rationale |
|--------|--------|-----------|
| Impossible Travel | 30 | Strongest indicator — physically impossible = stolen creds |
| MFA Fatigue | 25 | T1621 push-spray pattern, high confidence when followed by approval |
| IP Reputation | 20 | C2/Tor/scanner feeds, but NAT can cause FPs |
| Device Novelty | 15 | New device alone is moderate signal |
| Login Hour Anomaly | 10 | Weakest standalone, best as corroboration |

Weights sum to 100. See [docs/DECISIONS.md](docs/DECISIONS.md) for threshold logic and confidence formula.

## Safety Model

ADTE's safety guarantee is architectural: it has no code path that mutates an
external system. It produces verdicts and *recommended* actions; every
medium/high verdict is flagged `human_review_required`, and acting on it is a
human or downstream-system decision.

See [docs/SAFETY.md](docs/SAFETY.md) for the full safety model, including the
environment variables reserved for a future automated-containment layer.

## Test Coverage

391 tests across 21 files — test_geo, test_intel, test_policy, test_engine, test_llm_assist, test_llm_cache, test_llm_enrichment, test_wazuh_adapter, test_native_mitre, test_feedback, test_mitre_mapper, test_mitre_map_schema, test_demo_stories, test_sql_injection, test_prompt_injection_adversarial, test_audit_log, test_stats_endpoints, test_ti_cache_quota, test_ticket_client, test_verdict_export, test_schema_migration

Example verdicts:
- `incident_account_takeover_tor_exfil.json` → **CRITICAL** (~99)
- `incident_impossible_travel_mfa_fatigue.json` → **HIGH_RISK** (79)
- `incident_needs_human_ambiguous.json` → **MEDIUM_RISK** (43)
- `incident_benign_vpn_travel.json` → **LOW_RISK** (5)

## Example Output

### Impossible Travel + MFA Fatigue (HIGH RISK)

```
  ========================================================
    VERDICT:  HIGH RISK
  ========================================================

  Incident:    INC-2025-0042
  User:        alice@contoso.com
  Severity:    High
  Risk Score:  79/100
  Confidence:  83%
  Action:      Immediately disable account, revoke sessions, escalate to Tier-2

  Recommended actions:
    - disable_account
    - revoke_sessions
    - notify_soc_tier2
    - create_ticket_p1

  Signal breakdown:
  Signal                    Score    Max   Conf  Detail
  ------------------------ ------ ------ ------  ----------------------------------------
  impossible_travel          30.0     30  100%  Impossible travel detected — New York -> Moscow: 7510 km in 30 min ...
  mfa_fatigue                25.0     25  100%  11 MFA denials in 10-min window (12/14 total denied) — followed by ...
  ip_reputation               0.0     20   80%  No malicious IPs detected
  device_novelty             15.0     15   65%  1 unknown device(s): DESKTOP-UNKNOWN (dev-MOSCOW-UNKNOWN)
  login_hour_anomaly          8.6     10   66%  12/14 events outside baseline hours (08:00-18:00 America/New_York)

  ** Human review required **
```

See [docs/EXAMPLE_WALKTHROUGH.md](docs/EXAMPLE_WALKTHROUGH.md) for all three scenarios with signal explanations.

## Security

A structured security audit was performed against the full codebase using static analysis and manual review.  All findings have been remediated.

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| H-1 | HIGH | `verify_ssl=False` default in Wazuh adapter | **Fixed** — default is now `True`; opt-out via `ADTE_WAZUH_VERIFY_SSL=false` |
| H-2 | HIGH | Global `urllib3.disable_warnings()` suppressed TLS warnings process-wide | **Fixed** — scoped to per-request `warnings.catch_warnings()` context |
| M-1 | MEDIUM | Wazuh alert fields (device names, rule descriptions) flowed unsanitized into LLM prompt | **Fixed** — detail strings truncated to 300 chars before prompt construction |
| M-2 | MEDIUM | No HTTP timeout on Wazuh Indexer requests — CLI could hang indefinitely | **Fixed** — `timeout=30` on all outbound requests |
| M-3 | MEDIUM | `except Exception: return None` in LLM client swallowed all errors silently | **Fixed** — failures now logged at WARNING level before fallback |
| M-4 | MEDIUM | MFA fatigue capitulation check used `denied[0]` (newest for Wazuh desc order) | **Fixed** — uses `min(e.timestamp for e in denied)` regardless of ordering |
| M-5 | MEDIUM | `requests` missing from `pyproject.toml` dependencies | **Fixed** — `requests>=2.32.4` added |
| M-6 | MEDIUM | Broad `except Exception` in CLI exposed Pydantic field names via error message | **Fixed** — catches `ValidationError`/`TypeError`/`KeyError` with sanitised messages |
| L-1 | LOW | No guard for `available_weight == 0` — ZeroDivisionError if all signals skipped | **Fixed** — explicit zero guard before division |
| L-2 | LOW | Malformed FP registry YAML entries silently dropped | **Fixed** — logs `WARNING` with the offending entry |
| L-3 | LOW | `IPv4Network(strict=False)` accepted ambiguous CIDRs without warning | **Fixed** — tries `strict=True` first; logs `WARNING` and normalises on mismatch |

See [docs/PROJECT_PROGRESS.md](docs/PROJECT_PROGRESS.md) for full project history.

## Limitations

- Sentinel support is the incident JSON format only (no live Azure API) — Wazuh Indexer live ingestion is functional
- Recommend-only — ADTE surfaces a recommended action but performs no automated containment
- Batch processing limited to Wazuh source — mock source processes one incident file at a time
- LLM summary is optional polish, not decision input

## Roadmap

- [x] Wazuh live alert integration
- [x] Multi-source threat intel enrichment (AbuseIPDB, VirusTotal, OTX)
- [x] Anthropic SDK integration — structured LLM summaries with deterministic fallback when no key configured
- [x] Security audit — all HIGH/MEDIUM/LOW findings remediated
- [x] Full 9-view web UI (Flask + esbuild-bundled React SPA)
- [x] Alert router — Slack webhook integration with stdout fallback (`scripts/alert_router.py`)
- [x] Auto-ticket pipeline — Linear and Trello ticket creation for high/medium risk verdicts (`scripts/ticket_client.py`)
- [x] Verdict audit log — SQLite persistence of every triage verdict via `/api/verdicts` endpoint
- [x] Analyst feedback loop — FP/TP labels via API + UI; FP IPs auto-promoted to FP registry
- [x] MITRE ATT&CK + NIST 800-61 badges on all verdict surfaces (triage result, queue, history)
- [x] Native MITRE ingestion from Wazuh `rule.mitre.id`; 40-entry technique/sub-technique map; `mitre_details` provenance in every verdict; wired advisory `llm_enrichment`
- [x] Aggregation endpoints — `/api/stats/verdicts`, `/api/stats/mitre`, `/api/stats/feedback` (P13 backend)
- [x] Threat-intel bounded TTL cache + per-provider daily quotas; LLM narrative response cache
- [x] Adversarial prompt-injection test suite + gap report (`docs/INJECTION_GAP_REPORT.md`)
- [x] Verdict History + Feedback History views with filter and clear controls
- [ ] Real Sentinel REST API integration (live Azure ingestion)
- [ ] Automated containment/response-execution layer (gated) — currently recommend-only
- [ ] Batch processing mode
- [ ] KQL rule pack for upstream detection
- [ ] SOAR-ready JSON action output for open-source orchestration tools
- [x] `use_llm=True` query param on `/api/triage` — activate Claude-powered narrative summaries when `ANTHROPIC_API_KEY` is set
- [x] RBAC auth UX — `/api/auth-check` endpoint; Settings "Save & Verify" with immediate key validation and role feedback
- [x] sessionStorage for ADTE bearer token — auto-clears on window close; no third-party key ever touches the browser
- [x] Parallel threat intel API calls — AbuseIPDB, VirusTotal, OTX queried concurrently (ThreadPoolExecutor); module-level singleton preserves per-IP cache across requests
- [x] High risk example scenario enriched — device novelty and login hour signals now fire correctly (score 55 → 79)
- [x] Queue triage cache — 300s server-side TTL cache by `incident_id`; eliminates redundant re-triage on 60s auto-refresh
- [x] Mutually exclusive stat cards — Critical (≥75) / High (71–74) / Medium (30–70) / Low (<30) buckets; skeleton placeholders on first load
- [x] Alert queue source banner — full-width WAZUH LIVE (green) vs WAZUH UNAVAILABLE (amber) banner replacing the old inline badge
- [x] CRITICAL quick load tile — 4th scenario: CEO account takeover via Tor exit, all 5 signals fire (expected score ~99)
- [x] Cross-view IP navigation — clicking any IP in Queue, IP Rep, or Threat Intel history navigates to Threat Intel and auto-runs enrichment lookup
- [x] Verdict History navigation — every cell redirects to the most relevant engine view (Signal Breakdown, MITRE / NIST, or Alert Input)

## Development

This project was built with AI-assisted drafting and scaffolding to accelerate iteration. All code was reviewed, tested, and modified by hand. Final logic, signal weights, and architectural decisions are deterministic and human-owned.

## License

MIT
