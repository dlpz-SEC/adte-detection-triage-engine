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

**Live demo: [autonomousdetection.up.railway.app/#overview](https://autonomousdetection.up.railway.app/#overview)**

</div>

Deployed on Railway and serving the full web UI, so there is no clone, no install
and no local server needed to look around. Browsing the interface and the four
bundled example incidents is open to anyone; loading the alert queue and running
triage require a passkey, which is provided below. See [Access](#access) for the split.

---

## Access

The hosted instance runs in **secured mode**, so the API is not open to the
public internet. What that means for a visitor:

| Available without a passkey | Requires a passkey |
|---|---|
| Browsing the UI and navigating every view | Running triage (`POST /api/triage`) |
| The four bundled example incidents (`GET /api/examples`) | The alert queue and its 8 seeded demo alerts |
| `GET /health` | Cases, verdict history, audit log, stats |

Views that read protected data render an `AUTHENTICATION REQUIRED` notice until
you log in, rather than failing silently or appearing empty.

To run triage on the hosted instance, open **Settings** and log in. **Reviewers
and recruiters** can use the shared analyst passkey:

```
5547a65b2cbf0692a5a4a416278713d69465a12b70bf85ac
```

It runs triage and reads the queue, cases, threat intel, and audit log; it
cannot delete anything or change configuration. Sessions are stored server-side
with an 8 hour TTL and are cleared by every redeploy, so an occasional re-login
is expected rather than a fault.

Running it locally behaves the same way. With no `ADTE_API_KEY_*` variables set
the server starts in demo mode, where reads are open but any write (triage
included, since it is a `POST`) returns 403. Set one key and log in to use the
local web UI end to end. The **CLI never goes through Flask**, so
`python -m adte triage` runs with no key configured at all.

---

## Premise

Security Operations Centers (SOCs) are overwhelmed. Analysts spend hours manually triaging hundreds of alerts per day — most of which are false positives or low-confidence noise. The ones that matter (credential theft, active intrusions, MFA fatigue attacks) require fast, structured decisions, not ad-hoc guesswork.

**ADTE is an automated first-responder for that triage step.**

When a security alert arrives — from Microsoft Sentinel, Wazuh, or any supported source — ADTE evaluates it across five core behavioural signals derived from real-world attack patterns:

1. **Impossible Travel** — Did the user physically teleport? New York to Moscow in 30 minutes is not a VPN quirk; it's stolen credentials.
2. **MFA Fatigue** — Are repeated push denials followed by an approval? That's T1621: an attacker wearing down a user until they accidentally approve.
3. **IP Reputation** — Is the source IP flagged by AbuseIPDB, VirusTotal, or AlienVault OTX as C2, Tor, or a known scanner?
4. **Device Novelty** — Is this the first time this device has been seen for this user? A compromised machine posing as the user won't be in the inventory.
5. **Login Hour Anomaly** — Is the activity happening at 2 AM when the user is typically offline? Attackers don't respect business hours.

Each signal is weighted by its real-world reliability and combined into a 0–100 risk score. Two **additive** signals then sit on top of that base (final score capped at 100), each applied only when its evidence exists:

- **File reputation** (up to **+40**) — a multi-engine malware verdict when the alert carries a file, from Wazuh's own VirusTotal result or an ADTE hash lookup (see Wazuh Malware-Response Integration below).
- **Cluster context** (up to **+15**) — when the alert correlates with recent related alerts (shared source IP, user, or file hash — see Alert Correlation & Case Management below).

Both are **aggravators only**: they can raise a score, never lower one. The score maps to a verdict:

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

- Automated triage for security incidents from multiple sources using 5 core weighted signals, plus two additive signals: cluster-context (up to +15, correlated related alerts) and file-reputation (up to +40, malware verdict) — both aggravators that never reduce a score
- Wazuh FIM/VirusTotal malware-pipeline integration — ingests rule 554/87105/553 alerts, scores the embedded VirusTotal verdict (or an ADTE `/files` hash lookup), correlates the same hash across hosts into one campaign case, and recommends containment. **Triage-only: ADTE recommends, Wazuh's active response executes** (see `docs/WAZUH_MALWARE_INTEGRATION.md`)
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
  (Wazuh live / raw Wazuh alert / Sentinel-format JSON)
       ↓
  [Normalize]  ← OCSF-inspired schema; source auto-detected
       ↓
   [Enrich]  ← Threat Intel (IP + file hash), User History, FP Registry
       ↓
    [Score]  ← 5 core weighted signals (travel, MFA, IP rep, device, hours) → 0-100
               + additive file reputation (up to +40) when file evidence exists
               + additive cluster context (up to +15) when correlated alerts exist
               (capped at 100; additive signals never lower a score)
       ↓
   [Policy]  → Verdict: LOW / MEDIUM / HIGH
       ↓
 [Correlate] → Join/create a case (shared IP, user, or file hash)
       ↓
   [Report]  → Verdict + per-signal rationale + recommended action
                (returned to analyst / web UI / downstream workflow)
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed pipeline and module dependency map.

## Quickstart

**Nothing to install:** the deployed instance is at
[autonomousdetection.up.railway.app](https://autonomousdetection.up.railway.app).
Open it to browse the UI and the bundled example incidents. Running triage there
needs an API key, as described in [Access](#access).

To run it locally instead:

```bash
git clone https://github.com/dlpz-SEC/adte-detection-triage-engine.git
cd adte-detection-triage-engine
pip install -e ".[dev]"
pytest -v

# Run triage on example incidents (offline, no API keys needed)
python -m adte triage --input examples/incident_impossible_travel_mfa_fatigue.json --format pretty --explain
python -m adte triage --input examples/incident_benign_vpn_travel.json --format pretty --explain
python -m adte triage --input examples/incident_needs_human_ambiguous.json --format pretty --explain
```

## Demo

Interactive web UI for running triage on incident JSON and reviewing verdicts live.  No CLI required — paste any `NormalizedIncident` JSON, or use the **Quick Load** tiles to pre-fill one of the four bundled scenarios (critical / high / medium / low), then click **Run Triage**.

The deployed instance already serves this UI at
[autonomousdetection.up.railway.app](https://autonomousdetection.up.railway.app);
log in via Settings first so **Run Triage** is permitted. To serve it yourself:

```bash
python -m adte.server
# Open http://localhost:5000
```

**Alert Queue — demo mode.** With no Wazuh Indexer reachable (the expected state
for a hosted deployment, since the Indexer lives on a private VM), the queue
serves a curated 8-alert set rather than an empty view: the four identity
incidents above, plus **four raw Wazuh alerts** carrying the malware-response
story end-to-end —

| Seeded alert | Score | Evidence path exercised |
|--------------|-------|-------------------------|
| `554` file added — `/tmp/malware/eicar.com` | 73 `high_risk` | no verdict yet → **ADTE** VirusTotal hash lookup |
| `87105` VirusTotal conviction (58/72) | 73 `high_risk` | **embedded Wazuh verdict** — zero API calls |
| `553` file deleted by active response | 73 `high_risk` | pre-delete checksum still convicts |
| `87105` on a **second host** | 73 → **78** | joins the first host's case by **file hash**, then gains +5 cluster context |

These are normalised through `WazuhAdapter.normalize_alert` — the same ingestion
path a live Indexer feeds — so the demo exercises the adapter rather than
faking its output. Click any row to triage it; the malware rows render the
file-reputation signal, the VirusTotal evidence panel, and the correlated
campaign case. No Wazuh credentials and no VirusTotal key are required.

## Wazuh Integration

> **Two ways in — only one needs infrastructure.**
> **Push (no infrastructure):** POST a raw Wazuh alert straight to `/api/triage` — it is auto-detected, normalized, scored, and correlated. No Wazuh credentials, and no VirusTotal key, because a rule-87105 alert already carries Wazuh's own VirusTotal verdict. Anyone can reproduce the full malware path from the bundled JSON.
> **Pull (VM-local):** `/api/queue` and `--source wazuh` query a Wazuh Indexer at `localhost:9200`, so they only work where that host is reachable — a local VM, not a public deploy.
>
> The cloud threat intel integrations (AbuseIPDB, VirusTotal, OTX) are publicly usable by anyone with free-tier API keys.

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

The additive cluster-context signal sits outside this redistribution math
entirely — it is applied after the core score is normalised. In the
both-skipped scenario above, a correlated Wazuh alert scores 83 with one case
sibling (78 + 5) and 88 when an ascending kill-chain is also detected (78 + 10).

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
  are mapped against a curated 42-entry technique map
  (`adte/data/mitre_technique_map.yaml`) covering technique **and** sub-technique
  IDs across Credential Access, Lateral Movement, C2, Exfiltration, Defense
  Evasion, Persistence, Execution, and more. First-match precedence is enforced
  by schema tests (sub-techniques must precede their generic parents).
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

## Alert Correlation & Case Management

Single-alert scoring is only half the triage problem — real intrusions surface
as *sequences*: the same source IP hitting three different rules in ten
minutes, or a technique progression that walks the ATT&CK kill chain. ADTE
groups related alerts into **cases**:

- **Entity correlation.** Every triaged alert (single or batch) joins an open
  case when it shares a source IP or user with recent alerts inside a rolling
  window (default 60 min). Wazuh's `AGENT\system` pseudo-users never correlate
  by user; private RFC1918 source IPs deliberately do (internal lateral
  movement is the story worth catching).
- **Kill-chain detection.** Member techniques resolve to ATT&CK tactics, and a
  strictly ascending progression across ≥2 alerts and ≥3 tactics (e.g.
  Credential Access → Lateral Movement → Exfiltration, gaps allowed) flags the
  case — detected via longest-increasing-subsequence over event-time order, so
  an out-of-order arrival never hides a real chain.
- **Case-level escalation, explainable.** The case scores
  `base (worst member) + volume bonus + tactic-breadth bonus + kill-chain
  bonus` (capped at 100) with a per-factor rationale mirroring the engine's
  signal rationale. Three medium-risk alerts from one IP walking the kill
  chain escalate the *case* to high risk — while **solo (uncorrelated) alerts
  score byte-identically** to the 5-signal engine. The case layer itself never
  rewrites a verdict after the fact; correlated alerts gain risk only through
  the engine's own additive `cluster_context` signal (below).
- **Context feeds scoring (cluster context).** Before scoring, `/api/triage`,
  each `/api/triage/batch` element, and `/api/queue` take a read-only peek at
  the case store; when correlated siblings exist inside the window, the
  additive `cluster_context` signal adds up to +15 to the alert's own risk
  score (see Signal Weights). The peek excludes the alert's own incident ID —
  re-triaging an alert never boosts itself — and the queue peeks but still
  never ingests.
- **API + UI.** `GET /api/cases` (list, open/closed filter),
  `GET /api/cases/<id>` (members + rationale), `DELETE /api/cases` (admin,
  soft-delete). The web UI adds a Cases view (expandable rows, kill-chain
  chips, member drill-down), a CASE column + per-case summary strip on batch
  results, and a case banner on every triage result.
- **Correlation is fail-open** — a broken case store yields `"case": null`,
  never a failed triage. Cases persist in the same cross-worker SQLite store
  as the audit log. The window runs on ingestion time, so demo fixtures with
  historical event timestamps still correlate; re-pasting the *same* incident
  refreshes its existing case membership (no duplicate members — a replayed
  alert can't inflate the score or fake a cross-alert kill chain), while
  distinct related alerts grow the case.

## Threat Intelligence API Keys

ADTE enriches IP addresses against live threat intelligence sources when API
keys are configured.  All keys are optional — without any keys the engine
falls back to deterministic synthetic lookups suitable for offline testing and CI.

| Environment Variable | Source | Required |
|---------------------|--------|----------|
| `ADTE_ABUSEIPDB_KEY` | [AbuseIPDB](https://www.abuseipdb.com) | No (synthetic fallback) |
| `ADTE_VT_API_KEY` | [VirusTotal](https://www.virustotal.com) | No (synthetic fallback) |
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
- **Fallback**: if all configured sources return errors, the synthetic lookup is used and a warning is logged.
- **Private IPs**: `127.x`, `10.x`, `172.16.x`, `192.168.x` are short-circuited without any API call.

### Rate Limits

VirusTotal public keys are limited to 4 requests/minute. Enrichment runs on the
request thread, so ADTE **never sleeps through** that window — when a lookup
would land inside it, the VirusTotal source **abstains** for that observable
(the aggregator excludes it from the confidence average) and the other providers
still answer. Blocking instead of abstaining is what turns a rate limit into a
denial-of-service: a 10-observable refresh would sit for ~150 s and be killed by
the WSGI worker timeout. Per-provider daily quotas
(`ADTE_TI_QUOTA_<PROVIDER>`) and a bounded TTL cache further cap outbound calls.
For high-volume triage, use a commercial key.

## Signal Weights

| Signal | Weight | Rationale |
|--------|--------|-----------|
| Impossible Travel | 30 | Strongest indicator — physically impossible = stolen creds |
| MFA Fatigue | 25 | T1621 push-spray pattern, high confidence when followed by approval |
| IP Reputation | 20 | C2/Tor/scanner feeds, but NAT can cause FPs |
| Device Novelty | 15 | New device alone is moderate signal |
| Login Hour Anomaly | 10 | Weakest standalone, best as corroboration |
| File Reputation (additive) | +40 | Malware verdict — embedded VirusTotal result or ADTE `/files` hash lookup; aggravator only, clean scan = 0, never reduces a score |
| Cluster Context (additive) | +15 | Correlated-case siblings + kill-chain progression — aggravator only, never reduces a score |

The five core weights sum to 100 and map directly to the 0–100 base score. Two additive signals sit on top (final score capped at 100): **file reputation** adds up to +40 when a file event carries a malware verdict (confirmed → +40, partial detection → +20, clean → 0), and **cluster context** adds up to +15 when the alert belongs to a correlated case (1 sibling → +5, 2 → +8, 3+ → +10; ascending kill-chain → +5 more). Each is not-applicable (never enters the signal set) when its input is absent, so a plain uncorrelated non-file alert scores byte-identically to the 5-signal engine. See [docs/DECISIONS.md](docs/DECISIONS.md) for threshold logic and confidence formula.

## Safety Model

ADTE's safety guarantee is architectural: it has no code path that mutates an
external system. It produces verdicts and *recommended* actions; every
medium/high verdict is flagged `human_review_required`, and acting on it is a
human or downstream-system decision.

See [docs/SAFETY.md](docs/SAFETY.md) for the full safety model, including the
environment variables reserved for a future automated-containment layer.

## Test Coverage

669 tests across 34 files — test_geo, test_intel, test_intel_hash, test_policy, test_engine, test_llm_assist, test_llm_cache, test_llm_enrichment, test_wazuh_adapter, test_native_mitre, test_feedback, test_mitre_mapper, test_mitre_map_schema, test_demo_stories, test_sql_injection, test_prompt_injection_adversarial, test_audit_log, test_stats_endpoints, test_ti_cache_quota, test_ticket_client, test_verdict_export, test_schema_migration, test_session_store, test_triage_batch, test_triage_input_formats, test_case_policy, test_kill_chain, test_case_store, test_cases_api, test_peek_correlation, test_cluster_signal, test_cluster_integration, test_file_signal, test_file_integration

Example verdicts (fresh clone, no API keys — deterministic synthetic intel):

| Example | Verdict | Score | Confidence |
|---------|---------|-------|-----------|
| `incident_account_takeover_tor_exfil.json` | **HIGH_RISK** (severity Critical) | 99 | 83 |
| `incident_impossible_travel_mfa_fatigue.json` | **HIGH_RISK** (severity Critical) | 99 | 85 |
| `incident_needs_human_ambiguous.json` | **MEDIUM_RISK** | 43 | 57 |
| `incident_benign_vpn_travel.json` | **LOW_RISK** | 5 | 55 |

> These four values are **golden-pinned** in the test suite (`GOLDEN_SOLO` in
> `tests/test_cluster_integration.py`): any change that moves them by a single
> point fails CI. They are the parity contract that lets additive signals ship
> without touching the core 100-point math.
>
> **They are intel-mode dependent.** With live threat-intel keys configured, the
> IP-reputation signal reflects what the real feeds say about the fixture's IPs
> — e.g. the impossible-travel example scores **79** with live keys (its IP is
> not currently flagged) versus **99** against the synthetic feed, which pins
> `198.51.100.23` as known C2. The scores above are what a fresh clone and CI
> reproduce.

## Example Output

### Impossible Travel + MFA Fatigue (HIGH RISK)

```
  ========================================================
    VERDICT:  HIGH RISK
  ========================================================

  Incident:    INC-2025-0042
  User:        alice@contoso.com
  Severity:    Critical
  Risk Score:  99/100
  Confidence:  85%
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
  ip_reputation              20.0     20   95%  1 malicious IP(s): 198.51.100.23 [tags: c2, cobalt-strike]
  device_novelty             15.0     15   65%  1 unknown device(s): DESKTOP-UNKNOWN (dev-MOSCOW-UNKNOWN)
  login_hour_anomaly          8.6     10   66%  12/14 events outside baseline hours (08:00-18:00 America/New_York)

  ** Human review required **
```

Every number above is reproducible from a fresh clone with no API keys. Note the
verdict (`HIGH RISK`, >70) and the severity band (`Critical`, ≥90) are distinct:
the verdict drives the recommended action, the severity is display-only and
engine-derived — it is *rejected* if supplied on input.

### Wazuh Malware Conviction (HIGH RISK)

A raw Wazuh rule-87105 alert POSTed straight to `/api/triage` — no Wazuh
credentials, no VirusTotal key, because the alert already carries Wazuh's own
VirusTotal verdict:

```
  VERDICT:  HIGH RISK     Risk Score: 73/100

  impossible_travel           —        skipped (no geolocation)  → weight redistributed
  mfa_fatigue                 —        skipped (no MFA outcome)  → weight redistributed
  ip_reputation             0.0     20  agent's own RFC1918 IP — not evaluated externally
  device_novelty           15.0     15  agent 003 not in baseline
  login_hour_anomaly        0.0     10  within baseline hours
                                        → core = 15 x 100/45 = 33
  file_reputation          40.0    +40  VirusTotal 58/72 engines flagged it malicious
                                        (embedded verdict)       → 33 + 40 = 73

  Recommended: quarantine_file, preserve_forensic_copy, hash_sweep_fleet, isolate_host
  ** ADTE recommends. Wazuh's active response executes. ADTE never deletes. **
```

See [docs/EXAMPLE_WALKTHROUGH.md](docs/EXAMPLE_WALKTHROUGH.md) for the auth
scenarios with signal explanations, and
[docs/WAZUH_MALWARE_INTEGRATION.md](docs/WAZUH_MALWARE_INTEGRATION.md) for the
malware pipeline's field contract.

## Security

Security review is continuous, not a one-off gate: every phase that widens the attack surface gets an adversarial audit (multi-agent finders + independent refutation passes) against an explicit threat model — **alert data is attacker-authored by construction**, and the triage endpoint accepts analyst-pasted JSON, so no field from a SIEM is trusted. All findings below have been remediated.

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| P32-1 | MEDIUM | Attacker-controlled `data.virustotal.permalink` rendered into an `<a href>` — React does not sanitize `href`, so the field was a phishing sink (script execution was blocked only by CSP having no `unsafe-inline`) | **Fixed** — `safeVtPermalink` allowlists scheme (`https:`) **and** host (`*.virustotal.com`); no link renders otherwise. Exploit and regression both verified in-browser |
| P32-2 | HIGH | VirusTotal client slept the full 15 s rate-limit window **on the request thread**; `enrich()` iterates observables sequentially, so a 10-observable refresh blocked ~150 s and the WSGI worker timeout killed the request — a self-inflicted DoS, and attacker-drivable via a many-hash alert | **Fixed** — the client now abstains inside the window instead of sleeping (measured 15.0 s → 0.0 s per lookup); 3 regression tests pin no-block/no-HTTP |
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
- Batch triage ships on the **API/UI** (`POST /api/triage/batch`, 25-alert cap); the **CLI** still takes one incident file at a time (no `--batch` flag)
- Live Wazuh *pull* (`/api/queue`) requires network reach to the Indexer at `localhost:9200`, so it is VM-local only — the hosted demo uses the push model (POST the alert). The malware integration needs neither Wazuh credentials nor a VirusTotal key, because the alert carries Wazuh's own verdict
- LLM summary is optional polish, not decision input
- The Agentic Analysis view is an explicit in-progress placeholder — it makes no backend call

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
- [x] Native MITRE ingestion from Wazuh `rule.mitre.id`; 42-entry technique/sub-technique map; `mitre_details` provenance in every verdict; wired advisory `llm_enrichment`
- [x] Aggregation endpoints — `/api/stats/verdicts`, `/api/stats/mitre`, `/api/stats/feedback` (P13 backend)
- [x] Threat-intel bounded TTL cache + per-provider daily quotas; LLM narrative response cache
- [x] Adversarial prompt-injection test suite + gap report (`docs/INJECTION_GAP_REPORT.md`)
- [x] Verdict History + Feedback History views with filter and clear controls
- [x] Alert correlation / case management — rolling-window entity correlation (IP/user), ATT&CK kill-chain detection, explainable case-level escalation, Cases view + `/api/cases` endpoints; per-alert verdicts untouched at the time (Phase 30 — superseded by the cluster-context signal below)
- [x] Cluster-context 6th signal — correlated-case context (sibling volume + kill-chain) feeds the per-alert score as an additive signal, up to +15 on top of the 100-point core; solo alerts byte-identical, parity golden-pinned (Phase 31)
- [x] File-reputation 7th signal + Wazuh malware-pipeline integration — ingests FIM/VirusTotal alerts (rule 554/87105/553), an additive malware verdict (up to +40) built from the embedded VT result or an ADTE `/files` hash lookup, file-hash campaign correlation across hosts, and recommend-only containment actions; ADTE never executes (Phase 32, see `docs/WAZUH_MALWARE_INTEGRATION.md`)
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
- [x] CRITICAL quick load tile — 4th scenario: CEO account takeover via Tor exit, all 5 core signals fire (expected solo score ~99)
- [x] Cross-view IP navigation — clicking any IP in Queue, IP Rep, or Threat Intel history navigates to Threat Intel and auto-runs enrichment lookup
- [x] Verdict History navigation — every cell redirects to the most relevant engine view (Signal Breakdown, MITRE / NIST, or Alert Input)

## Skills Demonstrated

Every item below is implemented in this repository and covered by the test suite — no aspirational entries.

### Detection Engineering & SOC Operations

| Skill | Where it lives |
|-------|----------------|
| **MITRE ATT&CK mapping** — technique *and* sub-technique IDs, native ingestion from `rule.mitre.id`, explicit per-technique provenance (`signal` / `native` / `rule_text`) | `adte/intel/mitre_mapper.py`, `adte/data/mitre_technique_map.yaml` (42 entries) |
| **NIST SP 800-61 Rev. 2 lifecycle** — verdicts carry the IR phase; audit trail satisfies non-repudiation (soft-delete only) | `adte/report.py`, `adte/store/audit_log.py` |
| **Kill-chain detection** — longest-increasing-subsequence over ATT&CK tactic ordering, gap-tolerant, ≥3 tactics across ≥2 alerts | `adte/case_policy.py` |
| **Alert correlation / case management** — rolling-window entity correlation on IP, user, and file hash; campaign detection across hosts | `adte/store/case_store.py` |
| **Risk scoring model design** — weighted signals with proportional redistribution for non-evaluable inputs; additive aggravators that provably never mitigate | `adte/engine.py`, `adte/decision_policy.py` |
| **Threat-intel enrichment** — AbuseIPDB / VirusTotal / OTX aggregation, IP **and** file-hash reputation, bounded TTL cache, per-provider daily quotas | `adte/intel/` |
| **False-positive management** — Sigma-style FP registry, analyst FP/TP feedback loop, FP auto-promotion | `adte/intel/sigma_fp_registry.py` |
| **SIEM integration** — live Wazuh/OpenSearch ingestion, FIM + VirusTotal active-response pipeline, Sentinel incident format, multi-format auto-detection | `adte/adapters/wazuh.py`, `docs/WAZUH_MALWARE_INTEGRATION.md` |
| **Log normalization** — OCSF-inspired source-agnostic schema; severity engine-derived and rejected on input | `adte/models.py` |

### Security Engineering (AppSec)

| Skill | Evidence |
|-------|----------|
| **Threat modeling** — alert data is treated as attacker-authored by construction, not as trusted SIEM output | drives the validation below |
| **SSRF defense** — scheme allowlist, cloud-metadata/IMDS and link-local blocking, fail-closed | `_validate_indexer_url` (`adte/adapters/wazuh.py`) |
| **XSS / unsafe-sink prevention** — URL scheme **and** host allowlisting before any `href`; React does not sanitize `href` | `safeVtPermalink` (`frontend/src/app.jsx`) |
| **Injection prevention** — regex-gated hash before URL interpolation; parameterized SQL throughout | `adte/intel/threat_intel.py`, `adte/store/` |
| **DoS / resource exhaustion** — non-blocking rate-limit handling, bounded lookups per incident, per-provider quotas, member/IP/hash caps, request deadlines | `adte/intel/virustotal.py`, `adte/case_policy.py` |
| **Prompt-injection hardening** — field sanitization, delimiters, adversarial test suite + gap report | `adte/llm/assist.py`, `docs/INJECTION_GAP_REPORT.md` |
| **AuthN/AuthZ** — RBAC role hierarchy, constant-time key comparison, HttpOnly/SameSite=Strict cookies, cross-worker session store | `adte/server.py`, `adte/store/session_store.py` |
| **Web hardening** — CSRF origin validation behind a TLS proxy (`ProxyFix`), CORS deny-by-default, CSP + HSTS + nosniff, 1 MB body cap, per-route rate limits | `adte/server.py` |
| **Secrets hygiene** — third-party keys never reach the browser; `.env` gitignored; masked in `/api/config` | `adte/server.py` |
| **Adversarial self-review** — multi-agent audits with independent refutation passes; findings triaged, fixed, and documented | `docs/INJECTION_GAP_REPORT.md`, Security table above |

### Software Engineering

| Skill | Evidence |
|-------|----------|
| **Python 3.11** — full type hints, Google-style docstrings, Pydantic v2 models at every module boundary | entire `adte/` package |
| **Testing** — 669 tests; unit, integration, adversarial, and **golden-parity** pins that fail CI on a 1-point scoring drift | `tests/` |
| **Change control under risk** — rollback tags, additive-only diffs, and sha256 output-parity proofs before/after every edit to scoring-critical code | `pre-file-signal`, `pre-cluster-signal` tags |
| **Concurrency** — `ThreadPoolExecutor` fan-out, request deadlines, cross-worker SQLite state (gunicorn multi-worker correctness) | `adte/intel/aggregator.py`, `adte/store/` |
| **Databases** — SQLite with `BEGIN IMMEDIATE` race-safe upserts, lazy schema migrations, indexing, retention pruning | `adte/store/case_store.py` |
| **API design** — 24 REST routes, RBAC per route, structured errors (422 never 500), CSV/JSON export | `adte/server.py` |
| **Frontend** — React SPA (9 views), esbuild bundling, Chart.js, dark/light theming, zero-dependency-CDN CSP compliance | `frontend/src/app.jsx` |
| **DevOps** — multi-stage Docker (Node build → Python runtime), Railway CI/CD auto-deploy, 12-factor env config | `Dockerfile`, `railway.json` |
| **AI/LLM integration** — Anthropic SDK, prompt caching, response caching, deterministic fallback, advisory-only isolation from the verdict | `adte/llm/` |

---

## Development

This project was built with AI-assisted drafting and scaffolding to accelerate iteration. All code was reviewed, tested, and modified by hand. Final logic, signal weights, and architectural decisions are deterministic and human-owned.

## License

MIT
