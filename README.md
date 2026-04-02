# ADTE — Autonomous Detection & Triage Engine

<div align="center">

![SOC Engineering](https://img.shields.io/badge/SOC%20Engineering-Incident%20Triage-0B1220?style=for-the-badge&logo=microsoftsecurity&logoColor=white)
![Detection Logic](https://img.shields.io/badge/Detection%20Logic-Risk--Based%20Decisioning-1D4ED8?style=for-the-badge&logo=opensearch&logoColor=white)
![Automation](https://img.shields.io/badge/Automation-Safe%20Response%20Orchestration-DC2626?style=for-the-badge&logo=githubactions&logoColor=white)
![Explainability](https://img.shields.io/badge/Explainability-Transparent%20Verdicts-6D28D9?style=for-the-badge&logo=googledocs&logoColor=white)

</p>

![Multi-Source SIEM](https://img.shields.io/badge/SIEM-Multi--Source%20Ingestion-0078D4?style=for-the-badge&logo=shield&logoColor=white)
![Python](https://img.shields.io/badge/Python-Engineering%20Logic-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Pytest](https://img.shields.io/badge/Testing-Pytest-0A9EDC?style=for-the-badge&logo=pytest&logoColor=white)

</div>



Deterministic, source-agnostic triage engine for security incidents — supports Sentinel, Wazuh, and more — with weighted signal scoring, explainable verdicts, and defense-in-depth execution controls.

## What This Is

- Automated triage for security incidents from multiple sources using 5 weighted signals
- Deterministic scoring (0-100 risk score, 0-100 confidence)
- 6-layer safety gate system before any automated action
- Explainable decisions with per-signal rationale
- CLI for dry-run analysis and batch processing

## What This Is NOT

- Not a SOC replacement — human review required for medium/high risk
- Not production-ready — uses mock APIs, needs real SIEM/API integration
- Not a detection rule library — focuses on triage, not alert generation
- Not magic — garbage signals in = garbage verdicts out

## Architecture

```
Security Alert / Incident
  (Sentinel mock, Wazuh, …)
       ↓
  [Normalize]
       ↓
   [Enrich]  ← Threat Intel, User History, FP Registry
       ↓
    [Score]  ← 5 weighted signals (travel, MFA, IP rep, device, hours)
       ↓
   [Policy]  → Verdict: LOW / MEDIUM / HIGH
       ↓
[Safety Gates] → 6 checks before any action
       ↓
  [Execute]  → Source adapters (Sentinel mock, Wazuh, Entra ID mock)
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

## Wazuh Integration

Pull live alerts from a local Wazuh Indexer (OpenSearch at port 9200):

```bash
export ADTE_WAZUH_INDEXER_URL=https://localhost:9200   # default
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
| `ADTE_WAZUH_INDEXER_URL` | `https://localhost:9200` | Wazuh Indexer (OpenSearch) base URL |
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

Six gates evaluated in order — ALL must pass for execution:

1. **Kill Switch** — `ADTE_KILL_SWITCH=true` halts everything
2. **Dry Run** — `ADTE_DRY_RUN=true` (default) blocks writes
3. **Execution Enabled** — `ADTE_EXECUTION_ENABLED=true` required
4. **Tenant Allowlist** — must be in `ADTE_TENANT_ALLOWLIST`
5. **User/Severity Gate** — user in allowlist OR severity >= High
6. **Action Allowlist** — action type in `ADTE_ACTION_ALLOWLIST`

Default config blocks everything. You must explicitly disable dry-run AND enable execution to take any action.

See [docs/SAFETY.md](docs/SAFETY.md) for full gate logic and example scenarios.

## Test Coverage

110 tests across 8 files — test_geo, test_intel, test_policy, test_engine, test_safety, test_llm_assist, test_wazuh_adapter

Example verdicts:
- `incident_impossible_travel_mfa_fatigue.json` → **HIGH_RISK** (75)
- `incident_benign_vpn_travel.json` → **LOW_RISK** (5)
- `incident_needs_human_ambiguous.json` → **MEDIUM_RISK** (43)

## Example Output

### Sentinel Mock — Impossible Travel + MFA Fatigue (HIGH RISK)
![Sentinel Mock - HIGH RISK](docs/PHASE%201%20SCREENSHOTS/phase1-sentinel-mock-high-risk.png)

All 5 signals evaluable. Impossible travel (New York → Moscow in 30 min)
and MFA fatigue (12 denials followed by approval) fire at full weight.
Risk score 75/100, confidence 98%.

### Live Wazuh — SSH Brute Force (MEDIUM RISK)
![Wazuh Live - MEDIUM RISK](docs/PHASE%201%20SCREENSHOTS/phase1-wazuh-live-medium-risk.png)

Real alerts ingested from Wazuh Indexer via OpenSearch API. Impossible
travel and MFA signals skipped (unavailable for Wazuh alerts), weight
redistributed across remaining 3 signals. Unknown device and after-hours
login detected. Risk score 56/100, confidence 40%.

## Limitations

- Sentinel integration uses mock APIs — Wazuh Indexer integration is functional
- Single-incident processing — no batch mode yet
- No persistence — stateless between runs
- LLM summary is optional polish, not decision input

## Roadmap

- [x] Wazuh live alert integration
- [ ] Real Sentinel REST API integration
- [ ] Response action logging with exportable recommendations
- [ ] Batch processing mode
- [ ] KQL rule pack for upstream detection
- [ ] SOAR-ready JSON action output for open-source orchestration tools
- [ ] Multi-source threat intel enrichment (AbuseIPDB, VirusTotal, OTX)

## Development

This project was built with AI-assisted drafting and scaffolding to accelerate iteration. All code was reviewed, tested, and modified by hand. Final logic, signal weights, safety gates, and architectural decisions are deterministic and human-owned.

## License

MIT
