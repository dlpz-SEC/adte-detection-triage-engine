# Extensions Guide

This document explains how to extend ADTE with new signal types and additional
enrichment sources.

> **Scope note:** ADTE is a triage engine — it ingests, scores, and recommends.
> An automated-containment / response-execution layer (acting on verdicts in
> Sentinel, Entra ID, etc.) is a roadmap item, not part of the current codebase.
> The extension points below all sit on the triage side of the pipeline. For a
> new *ingestion* source, model it on the live `adte/adapters/wazuh.py` adapter,
> which converts an external alert feed into `NormalizedIncident` objects.

## Adding New Signal Types

To add a new signal class to the scoring model:

### Step 1: Define the weight in `decision_policy.py`

```python
WEIGHT_NEW_SIGNAL: int = X  # Points for this signal

SIGNAL_WEIGHTS: dict[str, int] = {
    "impossible_travel": 30,
    "mfa_fatigue": 25,
    "ip_reputation": 20,
    "device_novelty": 15,
    "login_hour_anomaly": 10,
    "new_signal": X,  # Add here
}
```

**Important:** All weights must sum to 100. Redistribute existing weights to accommodate the new signal.

### Step 2: Add the signal method to `engine.py`

```python
def _compute_new_signal(self) -> SignalResult:
    """Evaluate the new signal.

    Returns:
        (score, rationale, confidence) tuple.
    """
    weight = SIGNAL_WEIGHTS["new_signal"]

    # Your detection logic here...
    if condition_detected:
        return (float(weight), "Description of what was detected", 0.85)

    return (0.0, "No anomaly detected", 0.8)
```

### Step 3: Register in `score()`

```python
def score(self) -> "TriageEngine":
    self._signals["impossible_travel"] = self._compute_impossible_travel()
    self._signals["mfa_fatigue"] = self._compute_mfa_fatigue()
    self._signals["ip_reputation"] = self._compute_ip_reputation()
    self._signals["device_novelty"] = self._compute_device_novelty()
    self._signals["login_hour_anomaly"] = self._compute_login_hour_anomaly()
    self._signals["new_signal"] = self._compute_new_signal()  # Add here
    # ... rest of score() unchanged
```

### Step 4: Add tests

Add tests in `tests/test_engine.py` to verify the new signal fires correctly for each example incident.

### Step 5: Update example incident rationale count

In `test_engine.py`, update the rationale structure assertion:
```python
assert len(rationale) == 6  # was 5, now 6
```

### Signal Ideas for Future Implementation

| Signal | Weight (suggested) | Data Source |
|--------|-------------------|-------------|
| **Brute force velocity** | 10-15 | Failed sign-in count in sliding window |
| **OAuth app consent** | 10-15 | Risky app consent grants via Graph API |
| **Mailbox rule creation** | 10-15 | Suspicious inbox rules (forwarding) |
| **Privileged role activation** | 15-20 | PIM role activations correlated with other signals |
| **Cross-tenant anomaly** | 10-15 | Sign-ins from unusual guest tenants |

## Adding New Enrichment Sources

### Adding a New Threat Intelligence Feed

Create a new module or extend `adte/intel/threat_intel.py`:

```python
# adte/intel/virustotal.py

import os
import httpx

_VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
_VT_BASE = "https://www.virustotal.com/api/v3"

def check_virustotal(ip: str) -> ThreatIntelResult:
    """Query VirusTotal for IP reputation."""
    if not _VT_API_KEY:
        return ThreatIntelResult(
            is_malicious=False, confidence=0.0,
            source="virustotal-disabled", tags=[],
        )

    resp = httpx.get(
        f"{_VT_BASE}/ip_addresses/{ip}",
        headers={"x-apikey": _VT_API_KEY},
        timeout=10.0,
    )
    data = resp.json()
    stats = data["data"]["attributes"]["last_analysis_stats"]
    malicious_count = stats.get("malicious", 0)
    total = sum(stats.values())

    return ThreatIntelResult(
        is_malicious=malicious_count > 3,
        confidence=malicious_count / total if total else 0.0,
        source="virustotal",
        tags=["vt-malicious"] if malicious_count > 3 else [],
    )
```

### Integrating into the Enrichment Pipeline

Update `engine.py` `enrich()` to call additional sources:

```python
def enrich(self) -> "TriageEngine":
    for ip in unique_ips:
        self._threat_intel_results[ip] = check_threat_intel(ip)

        # Add additional TI sources:
        vt_result = check_virustotal(ip)
        if vt_result.is_malicious:
            self._threat_intel_results[ip] = vt_result  # Override with higher-confidence source

        _, ptype = self._fp_registry.is_known_benign_any(ip)
        self._fp_matches[ip] = ptype
    return self
```

### Adding FP Registry Patterns

Edit `examples/fp_registry.yaml` to add new known-benign patterns:

```yaml
- name: "office_365_infrastructure"
  pattern_type: "cloud_service"
  description: "Microsoft 365 frontend IPs"
  cidrs:
    - "13.107.6.0/24"
    - "13.107.18.0/24"
    - "13.107.128.0/22"
    - "23.103.160.0/20"
```

### Adding User Behavioral Baselines

To replace mock user profiles with real data, implement a query against your identity provider or SIEM:

```python
# adte/store/user_history.py

async def get_user_profile_from_graph(upn: str) -> UserProfile:
    """Build a user profile from Graph API and Sentinel sign-in logs."""
    # 1. Query recent sign-in logs for location/device/hour patterns
    # 2. Query registered devices
    # 3. Build baseline from last 30 days of activity
    ...
```

The `UserProfile` model in `adte/models.py` already supports all necessary fields:
- `known_devices: list[DeviceInfo]` — registered device inventory
- `baseline_login_hours: LoginHourRange` — from sign-in log time analysis
- `last_seen_location: GeoLocation | None` — from most recent sign-in
- `last_seen_at: datetime | None` — timestamp of last activity
- `risk_level: str` — from an upstream identity-risk provider

## Adding New Recommended Actions

The list of recommended actions per verdict lives in `engine.py` `decide()`
(`self._actions`). These are advisory strings surfaced to the analyst — ADTE does
not execute them. To add one, append it to the relevant verdict branch:

```python
if self._verdict == "high_risk":
    self._actions = [
        "disable_account",
        "revoke_sessions",
        "quarantine_mailbox",  # Add here
        "notify_soc_tier2",
        "create_ticket_p1",
    ]
```

Consuming these recommendations (e.g. driving a SOAR playbook) is the
responsibility of a downstream system, not ADTE.
