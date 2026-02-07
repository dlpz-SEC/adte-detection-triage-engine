# ADTE — Autonomous Detection & Triage Engine

<div align="center">

![SOC Engineering](https://img.shields.io/badge/SOC%20Engineering-Incident%20Triage-0B1220?style=for-the-badge&logo=microsoftsecurity&logoColor=white)
![Detection Logic](https://img.shields.io/badge/Detection%20Logic-Risk--Based%20Decisioning-1D4ED8?style=for-the-badge&logo=opensearch&logoColor=white)
![Automation](https://img.shields.io/badge/Automation-Safe%20Response%20Orchestration-DC2626?style=for-the-badge&logo=githubactions&logoColor=white)
![Explainability](https://img.shields.io/badge/Explainability-Transparent%20Verdicts-6D28D9?style=for-the-badge&logo=googledocs&logoColor=white)

</p>

![Microsoft Sentinel](https://img.shields.io/badge/SIEM-Microsoft%20Sentinel-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)
![Microsoft Entra ID](https://img.shields.io/badge/Identity-Microsoft%20Entra%20ID-5E5ADB?style=for-the-badge&logo=microsoftentra&logoColor=white)
![Python](https://img.shields.io/badge/Python-Engineering%20Logic-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Pytest](https://img.shields.io/badge/Testing-Pytest-0A9EDC?style=for-the-badge&logo=pytest&logoColor=white)

</div>



Deterministic triage engine for Microsoft Sentinel incidents with weighted signal scoring, explainable verdicts, and defense-in-depth execution controls.

## What This Is

- Automated triage for Sentinel incidents using 5 weighted signals
- Deterministic scoring (0-100 risk score, 0-100 confidence)
- 6-layer safety gate system before any automated action
- Explainable decisions with per-signal rationale
- CLI for dry-run analysis and batch processing

## What This Is NOT

- Not a SOC replacement — human review required for medium/high risk
- Not production-ready — uses mock APIs, needs real Sentinel/Graph integration
- Not a detection rule library — focuses on triage, not alert generation
- Not magic — garbage signals in = garbage verdicts out

## Architecture

```
Sentinel Incident
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
  [Execute]  → Mock adapters (Sentinel, Entra ID)
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed pipeline and module dependency map.

## Quickstart

```bash
git clone https://github.com/dlpz-SEC/adte-azure-sentinel-triage-engine.git
cd adte-azure-sentinel-triage-engine
pip install -e ".[dev]"
pytest -v  # 71 tests

# Run triage on example incidents
python -m adte triage --input examples/incident_impossible_travel_mfa_fatigue.json --format pretty --explain
python -m adte triage --input examples/incident_benign_vpn_travel.json --format pretty --explain
python -m adte triage --input examples/incident_needs_human_ambiguous.json --format pretty --explain
```

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

71 tests across 7 files — test_geo, test_intel, test_policy, test_engine, test_safety, test_llm_assist

Example verdicts:
- `incident_impossible_travel_mfa_fatigue.json` → **HIGH_RISK** (75)
- `incident_benign_vpn_travel.json` → **LOW_RISK** (5)
- `incident_needs_human_ambiguous.json` → **MEDIUM_RISK** (43)

## Limitations

- Mock APIs only — no real Sentinel/Graph calls
- Single-incident processing — no batch mode yet
- No persistence — stateless between runs
- LLM summary is optional polish, not decision input

## Roadmap

- [ ] Real Sentinel REST API integration
- [ ] Microsoft Graph API for Entra ID actions
- [ ] Batch processing mode
- [ ] KQL rule pack for upstream detection
- [ ] SOAR playbook export (Logic Apps / Sentinel Automation)

## Development

This project was built with AI-assisted drafting and scaffolding to accelerate iteration. All code was reviewed, tested, and modified by hand. Final logic, signal weights, safety gates, and architectural decisions are deterministic and human-owned.

## License

MIT
