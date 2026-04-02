# Decision Policy

This document explains the scoring model, signal weights, verdict thresholds, and confidence formula used by the ADTE triage engine.

## Signal Weights

All signal weights sum to **100**, mapping directly to a 0-100 risk scale. Each weight reflects real-world SOC experience and MITRE ATT&CK frequency data.

| Signal | Weight | MITRE ATT&CK | Rationale |
|--------|--------|---------------|-----------|
| **Impossible Travel** | 30 | T1078 (Valid Accounts) | Strongest single indicator. A physically implausible location change (>800 km/h) almost always means stolen credentials or a VPN/proxy anomaly. Hard to produce accidentally and correlates strongly with initial-access TTPs. |
| **MFA Fatigue** | 25 | T1621 (MFA Request Generation) | Rapid-fire MFA push denials followed by a single approval are a well-documented social-engineering technique. Slightly below impossible travel because a small number of accidental denials can occur during legitimate re-auth flows. |
| **IP Reputation** | 20 | T1090 (Proxy), T1573 (Encrypted Channel) | A match against threat-intel feeds (C2, Tor exit, scanner) is strong context but never dispositive on its own — shared infrastructure and NAT can cause false positives. |
| **Device Novelty** | 15 | T1200 (Hardware Additions) | A sign-in from an unrecognised device is a moderate signal. Lower weight because users legitimately acquire new devices, but combined with other signals it shifts confidence meaningfully. |
| **Login Hour Anomaly** | 10 | T1078 (Valid Accounts) | Activity outside the user's historical working hours is the weakest standalone signal. Many legitimate reasons exist (travel, on-call) but it adds supporting evidence when correlated with stronger indicators. |

### Why These Five Signals?

These signals were chosen because they:

1. **Cover the most common identity-based attack patterns** observed in real-world SOC operations against enterprise identity environments (Entra ID, LDAP, etc.)
2. **Are computable from Sentinel sign-in log data** without requiring endpoint telemetry or network flow analysis
3. **Correlate with MITRE ATT&CK techniques** commonly seen in initial access and credential abuse campaigns
4. **Have clear benign/malicious thresholds** that can be expressed as deterministic rules rather than requiring probabilistic models
5. **Are independently meaningful** — each signal can fire alone and still provide actionable triage context

### Why Not Other Signals?

Signals that were considered but deferred:

- **Lateral movement** — Requires cross-host correlation beyond sign-in logs
- **Data exfiltration** — Requires DLP or Cloud App Security integration
- **Endpoint anomalies** — Requires Defender for Endpoint telemetry
- **Email-based indicators** — Requires Defender for Office 365 integration
- **User and Entity Behavior Analytics (UEBA)** — Microsoft's built-in UEBA overlaps significantly; we complement rather than duplicate

## Verdict Thresholds

The risk score (0-100) maps to three categorical verdicts:

```
  0                    30                    70                   100
  ├────────────────────┼─────────────────────┼────────────────────┤
        low_risk              medium_risk           high_risk
       (< 30)               (30 - 70)               (> 70)
```

| Verdict | Range | Recommended Action |
|---------|-------|--------------------|
| `low_risk` | 0 – 29 | Auto-close as benign, update user baseline |
| `medium_risk` | 30 – 70 | Escalate to analyst for manual review within SLA |
| `high_risk` | 71 – 100 | Immediately disable account, revoke sessions, escalate P1 |

### Threshold Rationale

- **30 (low/medium boundary):** A score of 30 means at least one significant signal fired (impossible travel alone = 30). This threshold ensures that any single strong indicator triggers analyst review rather than auto-closure.

- **70 (medium/high boundary):** A score above 70 requires multiple corroborating signals. For example:
  - Impossible travel (30) + MFA fatigue (25) + IP reputation (20) = 75 → `high_risk`
  - A single signal alone cannot cross this threshold, preventing false-positive escalations

### Boundary Behavior

- `classify_verdict(29)` → `low_risk` (strict less-than)
- `classify_verdict(30)` → `medium_risk` (inclusive)
- `classify_verdict(70)` → `medium_risk` (inclusive)
- `classify_verdict(71)` → `high_risk` (strict greater-than)

## Confidence Scoring

Confidence represents **how certain we are that the verdict is correct**, independent of whether the verdict is high- or low-risk.

### Formula

```
confidence = round(coverage × agreement × 100)
```

Where:
- **Coverage** = `signals_evaluated / signals_total` (currently 5 total)
- **Agreement** = average per-signal confidence of fired signals (0.0 – 1.0)

### Per-Signal Confidence

Each signal method returns a confidence value based on data quality:

| Condition | Confidence | Example |
|-----------|-----------|---------|
| Strong, unambiguous data | 0.8 – 1.0 | Malicious IP with 0.95 TI confidence |
| Moderate data, clear direction | 0.5 – 0.7 | Borderline travel speed (500-800 km/h) |
| Sparse or missing data | 0.3 – 0.4 | No MFA events to evaluate |
| Contradictory signals | 0.3 – 0.5 | Device is novel but IP is clean |

### Example Calculations

**True positive (all signals fire):**
- 5/5 signals evaluated → coverage = 1.0
- Average confidence of fired signals ≈ 0.80
- Confidence = round(1.0 × 0.80 × 100) = **80%**

**False positive (no signals fire):**
- 5/5 signals evaluated → coverage = 1.0
- Average confidence of non-fired signals ≈ 0.80
- Confidence = round(1.0 × 0.80 × 100) = **80%**

**Sparse data (only 3 signals evaluable):**
- 3/5 signals evaluated → coverage = 0.6
- Average confidence ≈ 0.70
- Confidence = round(0.6 × 0.70 × 100) = **42%**

## Impossible Travel Detection

### Algorithm

1. Build comparison pairs from consecutive sign-in events (and optionally the user's `last_seen_location` → first event)
2. Compute great-circle distance using the **haversine formula**
3. Compute travel speed: `distance_km / (time_delta_minutes / 60)`
4. Classify:
   - Speed > 800 km/h → **impossible travel** (full weight)
   - Speed > 500 km/h → **borderline travel** (partial weight, linearly scaled)
   - Speed ≤ 500 km/h → **normal travel** (zero score)

### Threshold Rationale

- **800 km/h** — Exceeds the cruising speed of commercial aircraft (~900 km/h) with margin for airport transit time. A user cannot physically be in two cities 800+ km apart within minutes.
- **500 km/h** — Bullet trains and short-hop flights can legitimately achieve this speed. Borderline scores trigger analyst review without auto-escalation.

## MFA Fatigue Detection

### Algorithm

1. Collect all sign-in events with `mfa_result == "Denied"`
2. Sliding window: for each denial, count subsequent denials within 10 minutes
3. If the maximum burst ≥ 3 denials:
   - Check for **fatigue capitulation**: a `Success` event after the denial burst
   - If capitulation detected: increase confidence by 0.2
4. Score: full weight (25) if threshold met, zero otherwise

### Parameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Denial threshold | 3 | Matches Microsoft's own MFA fatigue detection heuristic |
| Window size | 10 min | Attackers typically push rapidly; legitimate re-auth rarely produces 3+ denials in 10 minutes |
| Capitulation bonus | +0.2 confidence | A denial burst followed by approval is the hallmark of fatigue attack success |
