# ADTE — Automated Detection Triage Engine for Microsoft Sentinel

## What This Is

ADTE is a **deterministic incident triage engine** for Microsoft Sentinel that automates the NIST 800-61 Detection & Analysis phase. It ingests Sentinel incident JSON, enriches each observable against threat intelligence and user behavioral baselines, scores the result across five weighted signal classes, and produces a structured, explainable verdict with recommended containment actions — all governed by a six-layer defence-in-depth safety gate framework.

## What This Is NOT

- **Not a SOC replacement.** ADTE augments Tier-1 analysts by automating repeatable triage decisions; it does not replace human judgement for complex or novel threats.
- **Not production-ready out of the box.** The current implementation uses deterministic mock enrichment sources. Production deployment requires integrating real Sentinel REST API, Microsoft Graph API, and threat intelligence feeds.
- **Not a silver bullet.** The five-signal scoring model covers common identity-based attack patterns (impossible travel, MFA fatigue, malicious IPs, device novelty, login-hour anomaly). It does not cover lateral movement, data exfiltration, or endpoint-level telemetry.
- **Not an autonomous response system.** Even with execution enabled, every action passes through six independent safety gates. The default configuration blocks all write operations.
- **Not an LLM-dependent system.** The optional LLM integration adds narrative polish only. The verdict is always computed deterministically and cannot be overridden by AI output.

## Architecture

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│              │    │              │    │              │    │              │
│    Ingest    │───>│  Normalize   │───>│   Enrich     │───>│    Score     │
│              │    │              │    │              │    │              │
│ Sentinel JSON│    │ from_sentinel│    │ Threat Intel │    │ 5 weighted   │
│ (incidents)  │    │ extraction   │    │ FP Registry  │    │ signals      │
│              │    │              │    │ User History  │    │ (sum = 100)  │
└──────────────┘    └──────────────┘    │ Geo / Travel │    └──────┬───────┘
                                        └──────────────┘           │
                                                                   v
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│              │    │              │    │              │    │              │
│  (Execute)   │<───│    Report    │<───│   Policy     │<───│   Decide     │
│              │    │              │    │              │    │              │
│ Sentinel API │    │ NIST 800-61  │    │ 6 safety     │    │ Thresholds   │
│ Graph API    │    │ structured   │    │ gates        │    │ low < 30     │
│ (gated)      │    │ + LLM assist │    │              │    │ high > 70    │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
```

## Quickstart

### Install

```bash
# Clone and install in editable mode
git clone <repo-url> && cd adte-azure-sentinel-triage-engine
pip install -e ".[dev]"
```

### Run All 3 Example Incidents

```bash
# True positive: impossible travel + MFA fatigue + C2 IP → high_risk (75/100)
python -m adte triage -i examples/incident_impossible_travel_mfa_fatigue.json -f pretty -e

# False positive: benign VPN travel → low_risk (5/100)
python -m adte triage -i examples/incident_benign_vpn_travel.json -f pretty -e

# Ambiguous: borderline travel + new device → medium_risk (43/100)
python -m adte triage -i examples/incident_needs_human_ambiguous.json -f pretty -e
```

### Run Tests

```bash
# Run all 71 tests
pytest

# With coverage
pytest --cov=adte --cov-report=term-missing

# Specific test file
pytest tests/test_engine.py -v
```

### CLI Options

```
python -m adte triage [OPTIONS]

Options:
  -i, --input PATH     Path to Sentinel incident JSON file (required)
  --dry-run            Run in dry-run mode — no write actions (default)
  --execute            Enable execution mode (DRY_RUN=false, EXECUTION_ENABLED=true)
  -f, --format TEXT    Output format: json (default) or pretty
  -e, --explain        Include signal breakdown in output
  -s, --save PATH      Save JSON output to file
```

## Safety Gates

ADTE enforces **six independent safety gates** evaluated in order. All must pass before any automated action executes. The default configuration blocks everything:

| # | Gate | Default | Purpose |
|---|------|---------|---------|
| 1 | **Kill Switch** | `false` | Emergency halt — blocks all actions when `true` |
| 2 | **Dry Run** | `true` | Read-only mode — prevents all write/mutate operations |
| 3 | **Execution Enabled** | `false` | Explicit opt-in required for any automated action |
| 4 | **Tenant Allowlist** | `[]` (open) | Restricts actions to approved Azure tenant IDs |
| 5 | **User / Severity** | `[]` (open) | User must be on allowlist OR severity must be High/Critical |
| 6 | **Action Allowlist** | `CLOSE_INCIDENT, POST_COMMENT` | Only listed action types are permitted |

A fresh deployment with no env vars configured will refuse to execute any automated actions (gates 2 and 3 block by default).

See [docs/SAFETY.md](docs/SAFETY.md) for full gate documentation and example scenarios.

## Signal Weights

| Signal | Weight | MITRE ATT&CK |
|--------|--------|---------------|
| Impossible Travel | 30 | T1078 (Valid Accounts) |
| MFA Fatigue | 25 | T1621 (MFA Request Generation) |
| IP Reputation | 20 | T1090 (Proxy), T1573 (Encrypted Channel) |
| Device Novelty | 15 | T1200 (Hardware Additions) |
| Login Hour Anomaly | 10 | T1078 (Valid Accounts) |

Weights sum to 100 for an intuitive 0-100 risk scale. See [docs/DECISIONS.md](docs/DECISIONS.md) for rationale.

## Project Structure

```
adte-azure-sentinel-triage-engine/
├── adte/
│   ├── __init__.py
│   ├── __main__.py          # python -m adte entry point
│   ├── cli.py               # Typer CLI (triage command)
│   ├── config.py            # SafetyConfig (6 gates, Pydantic BaseSettings)
│   ├── decision_policy.py   # Signal weights, thresholds, confidence
│   ├── engine.py            # TriageEngine pipeline (enrich → score → decide)
│   ├── llm_assist.py        # Optional LLM narrative summaries
│   ├── models.py            # Pydantic v2 models (incidents, entities, profiles)
│   ├── report.py            # NIST 800-61 structured report generation
│   ├── adapters/
│   │   ├── sentinel.py      # Sentinel API adapter (mock)
│   │   └── entra_id.py      # Entra ID / Graph API adapter (mock)
│   ├── intel/
│   │   ├── threat_intel.py   # Threat intelligence lookup (mock feeds)
│   │   └── sigma_fp_registry.py  # False-positive registry (YAML/CIDR)
│   ├── store/
│   │   └── user_history.py   # User behavioral baselines (mock profiles)
│   └── utils/
│       └── geo.py            # Haversine distance, impossible travel detection
├── examples/
│   ├── fp_registry.yaml
│   ├── incident_impossible_travel_mfa_fatigue.json
│   ├── incident_benign_vpn_travel.json
│   └── incident_needs_human_ambiguous.json
├── tests/
│   ├── conftest.py           # Shared fixtures
│   ├── test_engine.py        # 11 tests — full pipeline verdicts and schema
│   ├── test_geo.py           # 10 tests — haversine, travel speed
│   ├── test_intel.py         # 14 tests — threat intel, FP registry
│   ├── test_llm_assist.py    #  6 tests — LLM safety contract, deterministic summary
│   ├── test_policy.py        # 10 tests — verdict classification, confidence
│   └── test_safety.py        # 16 tests — all 6 safety gates, audit logging
├── docs/
│   ├── ARCHITECTURE.md
│   ├── DECISIONS.md
│   ├── SAFETY.md
│   └── EXTENSIONS.md
├── pyproject.toml
├── .env.example
└── CLAUDE.md
```

## Skills Demonstrated

- **Security Engineering** — NIST 800-61 incident response lifecycle, MITRE ATT&CK mapping, defence-in-depth safety controls, structured audit logging, kill switch design
- **Azure / Cloud Security** — Microsoft Sentinel incident model, Entra ID (Azure AD) identity response actions, Graph API integration patterns, multi-tenant safety architecture
- **Python Engineering** — Pydantic v2 data validation, BaseSettings for environment-driven config, Typer CLI framework, fluent builder pattern, comprehensive type hints
- **Detection Engineering** — Weighted signal scoring, impossible travel detection (haversine formula), MFA fatigue/push-spray detection, IP reputation correlation, behavioral baseline deviation
- **Testing** — 71 pytest tests across 7 files, fixture-based test architecture, boundary value analysis, safety gate exhaustive testing, schema validation
- **AI/ML Integration** — Optional LLM advisory layer with safety contract (AI cannot override deterministic verdict), graceful fallback to template-based summaries

## Future Work

- **Real Sentinel REST API** — Replace mock adapters with `azure-mgmt-securityinsight` calls for live incident ingestion, comment posting, and incident closure
- **Microsoft Graph API** — Integrate Entra ID operations (token revocation, password reset, account disable) via Graph SDK with proper OAuth2 app registration
- **KQL Rule Optimization** — Feed triage verdicts back to Sentinel analytics rules to tune detection sensitivity and reduce false positive volume
- **SOAR Playbook Export** — Generate Azure Logic Apps / Sentinel Playbook definitions from triage output for one-click automated response workflows
- **Real Threat Intelligence Feeds** — Integrate VirusTotal, AbuseIPDB, GreyNoise, and Microsoft Defender TI for production IP reputation scoring
- **Async Pipeline** — Convert enrichment lookups to async (aiohttp) for parallel API calls and sub-second triage latency at scale

## License

MIT
