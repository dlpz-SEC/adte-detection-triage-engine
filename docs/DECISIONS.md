# Decision Policy

This document explains the scoring model, signal weights, verdict thresholds, and confidence formula used by the ADTE triage engine.

## Signal Weights

The five **core** signal weights sum to **100**, mapping directly to a 0-100 risk scale. A sixth signal, **cluster context**, is additive-only: it adds up to **+15** on top of the core score when the alert belongs to a correlated case (final score capped at 100) and is deliberately excluded from the sum-to-100 invariant — `SIGNAL_WEIGHTS` in `decision_policy.py` has 6 entries totaling 115, with the core five still summing to 100. Each weight reflects real-world SOC experience and MITRE ATT&CK frequency data.

| Signal | Weight | MITRE ATT&CK | Rationale |
|--------|--------|---------------|-----------|
| **Impossible Travel** | 30 | T1078 (Valid Accounts) | Strongest single indicator. A physically implausible location change (>800 km/h) almost always means stolen credentials or a VPN/proxy anomaly. Hard to produce accidentally and correlates strongly with initial-access TTPs. |
| **MFA Fatigue** | 25 | T1621 (MFA Request Generation) | Rapid-fire MFA push denials followed by a single approval are a well-documented social-engineering technique. Slightly below impossible travel because a small number of accidental denials can occur during legitimate re-auth flows. |
| **IP Reputation** | 20 | T1090 (Proxy), T1573 (Encrypted Channel) | A match against threat-intel feeds (C2, Tor exit, scanner) is strong context but never dispositive on its own — shared infrastructure and NAT can cause false positives. |
| **Device Novelty** | 15 | T1200 (Hardware Additions) | A sign-in from an unrecognised device is a moderate signal. Lower weight because users legitimately acquire new devices, but combined with other signals it shifts confidence meaningfully. |
| **Login Hour Anomaly** | 10 | T1078 (Valid Accounts) | Activity outside the user's historical working hours is the weakest standalone signal. Many legitimate reasons exist (travel, on-call) but it adds supporting evidence when correlated with stronger indicators. |
| **Cluster Context** | +15 (additive) | *(deliberately none)* | Correlated-case context: sibling alert volume (1 → +5, 2 → +8, 3+ → +10) plus an ascending kill-chain progression across the case (+5 more), capped at 15. An aggravator only — it never reduces a score, and it is **not applicable** (absent entirely) for uncorrelated alerts. The MITRE map assigns it no technique by design: case membership is context, not itself a TTP. See the "Cluster Context as an Additive 6th Signal" section below. |

### Why These Five Core Signals?

These signals were chosen because they:

1. **Cover the most common identity-based attack patterns** observed in real-world SOC operations against enterprise identity environments (Entra ID, LDAP, etc.)
2. **Are computable from Sentinel sign-in log data** without requiring endpoint telemetry or network flow analysis
3. **Correlate with MITRE ATT&CK techniques** commonly seen in initial access and credential abuse campaigns
4. **Have clear benign/malicious thresholds** that can be expressed as deterministic rules rather than requiring probabilistic models
5. **Are independently meaningful** — each signal can fire alone and still provide actionable triage context

A sixth, **additive** signal — `cluster_context` (Phase 31) — sits outside this list: it scores the alert's correlated-case surroundings rather than the incident's own content, and is recorded in its own decision section at the end of this document.

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
- **Coverage** = `signals_evaluated / signals_total` — 5 for a solo (uncorrelated) alert; 6 when correlated-case context makes the `cluster_context` signal applicable
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

> The worked examples above assume a **solo (uncorrelated) alert**, where 5 signals are
> applicable — they remain correct as written. For a correlated alert the denominator
> becomes 6 (e.g. 4/6 evaluated → coverage ≈ 0.67), so the same alert reports a slightly
> different confidence when it carries more evidence — an accepted asymmetry (see the
> Cluster Context decision section below).

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

1. Collect authentication events (`type == "authentication"`) with `auth_status == "failure"`
2. Sliding window: for each denial, count subsequent denials within 10 minutes
3. If the maximum burst ≥ 3 denials:
   - Check for **fatigue capitulation**: an `auth_status == "success"` event after the denial burst
   - If capitulation detected: increase confidence by 0.2
4. Score: full weight (25) if threshold met, zero otherwise

> **Skip semantics:** events with `auth_status` of `None` (no MFA outcome — non-authentication
> events, or sign-ins where MFA was never attempted) are excluded. An incident with no
> authentication event carrying an `auth_status` skips the signal and its weight is
> redistributed proportionally to the remaining signals.

### Parameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Denial threshold | 3 | Matches Microsoft's own MFA fatigue detection heuristic |
| Window size | 10 min | Attackers typically push rapidly; legitimate re-auth rarely produces 3+ denials in 10 minutes |
| Capitulation bonus | +0.2 confidence | A denial burst followed by approval is the hallmark of fatigue attack success |

## Phase 31 — Cluster Context as an Additive 6th Signal

Phase 31 promoted correlated-case (cluster) context from a display-only layer (Phase 30)
into a real engine signal, `cluster_context`. This section records the design decisions.

### Doctrine: context is an aggravator, never a mitigator

The five core signals compute the 0–100 base score exactly as before — weights
30/25/20/15/10 summing to 100, skip/redistribution math untouched. `cluster_context`
then adds up to **+15 on top**, with the final score capped at 100:

| Correlated siblings | Points |
|---------------------|--------|
| 1 | +5 |
| 2 | +8 |
| 3+ | +10 |
| Ascending kill-chain in the case | +5 more |
| **Cap** | **15** |

Signal confidence: `0.6 + 0.1 per extra sibling` (capped at 0.9), `+0.1` when a
kill-chain is detected (capped at 1.0).

### Rejected alternative: share normalization

The obvious alternative — giving cluster context a 15-point share inside a 115-point
denominator and normalising the total back to 0–100 — was **rejected because it is
non-monotonic**: weak context would *downgrade* a strong alert. Verified
counterexample: the Wazuh both-signals-skipped scenario scores 78/`high_risk` solo;
under share normalization, one correlated sibling would have dragged it to
67/`medium_risk` — more evidence producing a *lower* verdict. Under the shipped
additive design the same alert goes 78 → 83 (one sibling) → 88 (kill-chain).

### Not applicable vs skipped

`cluster_context` introduces a signal state distinct from "skipped":

| | Skipped (e.g. travel/MFA with no data) | Not applicable (no correlated context) |
|---|---|---|
| Rationale entry | Present | **Absent** |
| `signal_summary` entry | Present | **Absent** |
| Confidence coverage | Reduced (counted in the denominator) | **Unaffected** (never enters the signal set) |
| Weight | Redistributed to remaining signals | Nothing to redistribute (additive) |

A solo alert therefore produces **byte-identical output** to the 5-signal engine —
proven by sha256 diff on all four bundled examples before/after the change, and pinned
permanently by golden-pin tests.

### Accepted: bounded double-counting and escalated-flag drift

Case members persist their boosted final scores, and the case layer's own bonuses
(volume, tactic breadth, kill-chain) stack on that base. This bounded double-counting
was accepted deliberately. Corollary: the case `escalated` flag
(`classify(case) != classify(worst member)`) fires slightly less often, because the
worst member's base is now itself boosted. `case_policy.py` was left untouched. To
avoid compounding the effect, the signal deliberately does **not** score sibling risk
scores or tactic breadth — the case layer already awards those.

### Queue peeks, never ingests

The read-only `peek_correlation_context()` (in `adte/store/case_store.py`) runs before
scoring in `/api/triage`, each `/api/triage/batch` element, **and** `/api/queue` — but
the queue still never *ingests* (it re-triages the same incidents on every poll and
would multiply case membership). The peek uses the same join rules as ingest (shared
event source IP or user, 60-minute ingestion-time window), excludes the incident's own
`incident_id` from sibling facts (a re-triage never boosts itself; a singleton case
yields no context), and is fail-open: any store error means no context, never a failed
triage.

### Accepted: confidence asymmetry

A correlated alert computes coverage over 6 applicable signals (e.g. 4/6) versus 3/5
for the same alert solo — slightly different confidence with more evidence. This is
intended: more applicable evidence legitimately changes how certain the engine is.
