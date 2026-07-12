# Example Walkthrough

Three end-to-end triage runs against the bundled mock incident files.
Each scenario uses `--source mock` (no live SIEM connection required).

> **Schema note (OCSF-inspired):** incidents use a source-agnostic schema — events live under
> `events[]` (each with a `type`, `auth_status`, and `event_risk`) and the incident carries a
> top-level `source`. `severity` is **not** an input field; it is derived by the engine from the
> computed risk score (`<30` Low · `30–70` Medium · `>70` High · `≥90` Critical) and shown in the
> output for display only.

> **Correlation note (Phase 31):** the scores in this document are **solo** (uncorrelated)
> numbers. The CLI runs shown here never touch the case store, so they always reproduce.
> In the **web UI**, however, the CRITICAL and MEDIUM (ambiguous) Quick Load examples share
> the user `eve@contoso.com` — running those demo tiles within 60 minutes of each other
> correlates them into a case, and the *second* alert gains additive cluster-context points
> (up to +15) on top of its documented solo score. To reproduce the solo numbers, clear
> cases between tiles (`DELETE /api/cases`, admin role) — or run them back-to-back
> deliberately to demo the boost.

---

## Scenario 1 — Impossible Travel + MFA Fatigue (HIGH RISK)

**What this incident represents:** Alice's account shows a login from New York
followed 30 minutes later by a login from Moscow — physically impossible. The
account also received 11 MFA push denials (12 of 14 total) before one was
approved, a classic T1621 fatigue-spray pattern. The Moscow login also comes
from an unrecognised device, outside Alice's baseline hours.

**Command:**

```bash
python -m adte triage \
  --source mock \
  --input examples/incident_impossible_travel_mfa_fatigue.json \
  --format pretty \
  --explain
```

**Output:**

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
  login_hour_anomaly          8.6     10   66%  12/14 events outside baseline hours (08:00–18:00 America/New_York)

  ** Human review required **
```

**Why the engine scored it this way:**

Four of the five signals fired. `impossible_travel` (30/30) triggered because
7 510 km in 30 minutes exceeds any plausible travel speed. `mfa_fatigue` (25/25)
triggered because 11 pushes were denied before one was approved — the approval is
what the engine treats as the capitulation event. `device_novelty` (15/15) fired
on the unrecognised `DESKTOP-UNKNOWN` device from Moscow, and `login_hour_anomaly`
(8.6/10) fired because 12 of 14 events fell outside Alice's baseline hours.
`ip_reputation` contributed nothing (0/20) — no malicious IP is present in this
incident, so that signal correctly produces no uplift. Combined score 79/100 with
83% confidence → `HIGH_RISK`.

---

## Scenario 2 — Benign VPN Travel (LOW RISK)

**What this incident represents:** Bob's account shows logins from two European
cities separated by a distance consistent with train or car travel (~113 km/h).
No MFA anomalies, no malicious IPs (two IPs are on the false-positive registry),
and the registered device is known. Only a minor after-hours signal fires.

**Command:**

```bash
python -m adte triage \
  --source mock \
  --input examples/incident_benign_vpn_travel.json \
  --format pretty \
  --explain
```

**Output:**

```
  ========================================================
    VERDICT:  LOW RISK
  ========================================================

  Incident:    INC-2025-0043
  User:        bob@contoso.com
  Severity:    Low
  Risk Score:  5/100
  Confidence:  55%
  Action:      Auto-close as benign — log for baseline update

  Recommended actions:
    - auto_close_incident
    - update_baseline

  Signal breakdown:
  Signal                    Score    Max   Conf  Detail
  ------------------------ ------ ------ ------  ----------------------------------------
  impossible_travel           0.0     30   80%  Travel speed within normal range (113 km/h)
  mfa_fatigue                 0.0     25   70%  MFA denial rate 0% (0/4) below fatigue threshold
  ip_reputation               0.0     20   80%  No malicious IPs detected; 2 matched FP registry
  device_novelty              0.0     15   90%  All devices recognised: Bob-Surface (dev-003)
  login_hour_anomaly          5.0     10   55%  2/4 events outside baseline hours (09:00–17:30 Europe/London)
```

**Why the engine scored it this way:**

The only signal that fires is `login_hour_anomaly` (5/10, 55% confidence) — 2
of 4 events occurred outside Bob's 09:00–17:30 London baseline, a weak signal
on its own. Travel speed was plausible (113 km/h), the IPs hit the FP registry
(likely a known VPN exit node), the device is enrolled, and there were no MFA
denials. Low confidence (55%) reflects that only one weak signal contributed
data. Score 5/100 → `LOW_RISK`, auto-closeable with a baseline update logged.

---

## Scenario 3 — Ambiguous / Needs Human Review (MEDIUM RISK)

**What this incident represents:** Eve's account shows a login from Tokyo
followed by one from Osaka 30 minutes later. At 785 km/h the speed is
borderline — above commercial aviation cruising speed but within the
engine's configurable "borderline" band. A brand-new iPad (never seen
before) was used. No MFA anomalies and no malicious IPs.

**Command:**

```bash
python -m adte triage \
  --source mock \
  --input examples/incident_needs_human_ambiguous.json \
  --format pretty \
  --explain
```

**Output:**

```
  ========================================================
    VERDICT:  MEDIUM RISK
  ========================================================

  Incident:    INC-2025-0044
  User:        eve@contoso.com
  Severity:    Medium
  Risk Score:  43/100
  Confidence:  57%
  Action:      Escalate to analyst for manual review within SLA

  Recommended actions:
    - notify_soc_tier1
    - request_user_verification
    - create_ticket_p3

  Signal breakdown:
  Signal                    Score    Max   Conf  Detail
  ------------------------ ------ ------ ------  ----------------------------------------
  impossible_travel          28.5     30   50%  Borderline travel speed — Tokyo -> Osaka: 392 km in 30 min = 785 km/h
  mfa_fatigue                 0.0     25   70%  MFA denial rate 0% (0/4) below fatigue threshold
  ip_reputation               0.0     20   80%  No malicious IPs detected
  device_novelty             15.0     15   65%  1 unknown device(s): Eve-iPad-New (dev-new-ipad-991)
  login_hour_anomaly          0.0     10   80%  All 5 events within baseline hours (10:00–22:00 Asia/Tokyo)

  ** Human review required **
```

**Why the engine scored it this way:**

Two signals fire, but neither is conclusive. `impossible_travel` contributes
28.5/30 at only 50% confidence — the speed (785 km/h) is suspicious but not
definitively impossible (high-speed rail tops out ~350 km/h; this is well above
that, but the engine applies a partial score for the borderline band rather than
full weight). `device_novelty` fires at 15/15 because the iPad has never
appeared before in Eve's history. The combination gives 43/100 with 57%
confidence — enough to escalate but not enough for automated action. An analyst
should check whether Eve recently bought a new device and whether 785 km/h is
explained by a connecting flight.
