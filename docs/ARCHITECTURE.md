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
│                                                            └────┬───┘      │
│                                                                 │          │
└─────────────────────────────────────────────────────────────────┼──────────┘
                                                                  │
                          NIST 800-61: Containment                v
┌─────────────────────────────────────────────────────────────────────────────┐
│   ┌──────────────┐   ┌─────────┐                                           │
│   │ SAFETY GATES │──>│ EXECUTE │  (Sentinel API, Entra ID / Graph API)     │
│   │ (6 layers)   │   │ (gated) │                                           │
│   └──────────────┘   └─────────┘                                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Pipeline Stages

### 1. Ingest

**Input:** Sentinel incident JSON file (or API response)

The CLI reads a JSON file representing a Microsoft Sentinel incident with embedded alert entities and sign-in metadata. In production, this would be replaced by a Sentinel webhook or polling adapter.

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

Evaluates five signal classes, each returning a weighted score (0 to weight_max), a human-readable rationale string, and a per-signal confidence:

| Signal | Max Weight | Method |
|--------|-----------|--------|
| Impossible Travel | 30 | Haversine distance / time delta → speed (km/h) |
| MFA Fatigue | 25 | Sliding 10-min window denial count + capitulation detection |
| IP Reputation | 20 | Threat intel lookup with FP suppression |
| Device Novelty | 15 | Device ID comparison against user's known inventory |
| Login Hour Anomaly | 10 | Timestamp vs. user's baseline login-hour window |

The aggregate risk score is `sum(signal_scores)`, clamped to [0, 100].

**Modules:** `adte/engine.py` (signal methods), `adte/decision_policy.py` (weights), `adte/utils/geo.py`, `adte/store/user_history.py`

### 5. Decide

**Input:** Risk score → **Output:** Verdict + recommended actions

Maps the aggregate risk score to a categorical verdict using fixed thresholds:
- `risk_score < 30` → `low_risk` → auto-close, update baseline
- `30 ≤ risk_score ≤ 70` → `medium_risk` → escalate for analyst review
- `risk_score > 70` → `high_risk` → disable account, revoke sessions, escalate P1

**Module:** `adte/engine.py` (`decide`), `adte/decision_policy.py` (`classify_verdict`)

### 6. Report

**Input:** Full decision output → **Output:** NIST 800-61 structured report

Compiles a structured report section with incident metadata, signal summary, safety flags, and optionally an LLM-generated narrative summary. The LLM integration is advisory only — it can never override the deterministic verdict.

**Modules:** `adte/report.py`, `adte/llm_assist.py`

### 7. Execute (Gated)

**Input:** Decision output → **Output:** API responses (or block records)

Automated containment actions (close incident, post comment, revoke tokens, reset password, disable account) are executed only after passing all six safety gates. Every blocked action is logged as structured JSON to stderr for audit.

**Modules:** `adte/adapters/sentinel.py`, `adte/adapters/entra_id.py`, `adte/config.py`

## Module Dependency Map

```
cli.py
├── config.py (SafetyConfig)
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
    ├── sentinel.py (SentinelAdapter)
    └── entra_id.py (EntraIDAdapter)
```

## Data Flow

```
SentinelIncident (raw JSON)
    │
    ▼  NormalizedIncident.from_sentinel()
NormalizedIncident
    │  - incident_id, user, severity
    │  - sign_in_events: list[SignInMetadata]
    │    - timestamp, ip_address, location, device_id, mfa_result
    │
    ▼  TriageEngine(incident, user_profile, fp_registry)
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
    ├── risk_score: int
    ├── confidence: int
    ├── recommended_action: str
    ├── actions: list[str]
    ├── rationale: list[{signal, score, detail}]
    ├── evidence: {threat_intel, fp_matches, sign_in_count, ...}
    ├── safety: {human_review_required, automated_actions_permitted, ...}
    └── report: {nist_phase, incident_id, signal_summary, one_paragraph_summary, ...}
```

## Key Design Principles

1. **Determinism** — The same input always produces the same verdict. No randomness, no external state mutation during scoring.
2. **Explainability** — Every signal produces a human-readable rationale string. The output includes full evidence and signal breakdowns.
3. **Safety by default** — All automated actions are blocked out of the box. Six independent gates must all pass. The kill switch provides emergency halt.
4. **Separation of concerns** — Enrichment, scoring, policy, and execution are isolated modules with clean interfaces.
5. **Auditability** — Blocked actions are logged as structured JSON to stderr. The report section includes timestamps, signal scores, and NIST phase alignment.
