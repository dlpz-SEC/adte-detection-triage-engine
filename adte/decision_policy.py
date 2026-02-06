"""Decision policy: signal weights, verdict thresholds, and confidence scoring.

Centralises all tuneable constants that govern how the triage engine
translates raw enrichment signals into a final risk score and verdict.

Each weight reflects the relative importance of a signal class based on
real-world SOC experience and MITRE ATT&CK frequency data:

* **Impossible travel (30)** — Strongest single indicator.  A physically
  implausible location change almost always means stolen credentials or
  a VPN/proxy anomaly.  Gets the highest weight because it is hard to
  produce accidentally and correlates strongly with initial-access TTPs.

* **MFA fatigue (25)** — Rapid-fire MFA push denials followed by a
  single approval are a well-documented social-engineering technique
  (T1621).  Slightly below impossible travel because a small number of
  accidental denials can occur during legitimate re-auth flows.

* **IP reputation (20)** — A match against threat-intel feeds (C2, Tor
  exit, scanner) is strong context but is never dispositive on its own;
  shared infrastructure and NAT can cause false positives.

* **Device novelty (15)** — A sign-in from an unrecognised device is a
  moderate signal.  Lower weight because users legitimately acquire new
  devices, but combined with other signals it shifts confidence
  meaningfully.

* **Login-hour anomaly (10)** — Activity outside the user's historical
  working hours is the weakest standalone signal.  Many legitimate
  reasons exist (travel, on-call) but it adds supporting evidence when
  correlated with stronger indicators.

NIST 800-61 Phase: Detection & Analysis — codifies the scoring rubric
that converts enriched observables into a structured triage verdict.
"""

from __future__ import annotations

from typing import Literal

# ---------------------------------------------------------------------------
# Signal weights (must sum to 100 for intuitive 0-100 risk scale)
# ---------------------------------------------------------------------------

WEIGHT_IMPOSSIBLE_TRAVEL: int = 30
"""Points awarded when the computed travel speed between consecutive
sign-in locations exceeds the impossible-travel threshold (800 km/h)."""

WEIGHT_MFA_FATIGUE: int = 25
"""Points awarded when repeated MFA push denials are detected within a
short time window, consistent with a fatigue / push-spray attack."""

WEIGHT_IP_REPUTATION: int = 20
"""Points awarded when at least one source IP in the incident is flagged
as malicious by threat-intelligence feeds."""

WEIGHT_DEVICE_NOVELTY: int = 15
"""Points awarded when a sign-in originates from a device not in the
user's known-device inventory."""

WEIGHT_LOGIN_HOUR_ANOMALY: int = 10
"""Points awarded when sign-in events fall outside the user's historical
baseline login-hour window."""

# Compile into a lookup for iteration.
SIGNAL_WEIGHTS: dict[str, int] = {
    "impossible_travel": WEIGHT_IMPOSSIBLE_TRAVEL,
    "mfa_fatigue": WEIGHT_MFA_FATIGUE,
    "ip_reputation": WEIGHT_IP_REPUTATION,
    "device_novelty": WEIGHT_DEVICE_NOVELTY,
    "login_hour_anomaly": WEIGHT_LOGIN_HOUR_ANOMALY,
}

_TOTAL_WEIGHT: int = sum(SIGNAL_WEIGHTS.values())  # 100

# ---------------------------------------------------------------------------
# Verdict thresholds
# ---------------------------------------------------------------------------

THRESHOLD_LOW: int = 30
"""Risk scores below this value produce a ``low_risk`` verdict."""

THRESHOLD_HIGH: int = 70
"""Risk scores above this value produce a ``high_risk`` verdict.
Scores between ``THRESHOLD_LOW`` and ``THRESHOLD_HIGH`` (inclusive)
are ``medium_risk``."""

Verdict = Literal["low_risk", "medium_risk", "high_risk"]


def classify_verdict(risk_score: int) -> Verdict:
    """Map a 0-100 risk score to a categorical verdict.

    Args:
        risk_score: Aggregated risk score from signal evaluation.

    Returns:
        One of ``"low_risk"``, ``"medium_risk"``, or ``"high_risk"``.
    """
    if risk_score < THRESHOLD_LOW:
        return "low_risk"
    if risk_score > THRESHOLD_HIGH:
        return "high_risk"
    return "medium_risk"


# ---------------------------------------------------------------------------
# Confidence scoring
# ---------------------------------------------------------------------------

def compute_confidence(
    signals_present: int,
    signals_total: int,
    signal_agreement: float,
) -> int:
    """Compute an overall confidence percentage for the triage verdict.

    Confidence reflects *how certain we are that the verdict is correct*,
    independent of whether the verdict is high- or low-risk.  It is
    derived from two factors:

    1. **Coverage** — what fraction of signal types actually fired
       (i.e., had data to evaluate).  More coverage → more confidence.
    2. **Agreement** — how consistently the fired signals point in the
       same direction (all positive or all negative).  A 1.0 means
       perfect agreement; 0.5 means the signals contradict each other.

    The formula is:

        confidence = round(coverage * agreement * 100)

    Args:
        signals_present: Number of signal types that were evaluated
            (had sufficient data to produce a result).
        signals_total: Total number of signal types in the policy
            (currently 5).
        signal_agreement: Float 0.0–1.0 expressing how consistently
            the evaluated signals agree on direction.

    Returns:
        Confidence percentage clamped to 0-100.
    """
    if signals_total == 0:
        return 0
    coverage = signals_present / signals_total
    raw = coverage * signal_agreement * 100
    return max(0, min(100, round(raw)))
