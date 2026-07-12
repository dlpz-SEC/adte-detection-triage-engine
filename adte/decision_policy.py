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

* **Cluster context (up to +15, additive)** — Membership in an active
  correlated case (shared source IP or user within the correlation
  window, possibly an ascending ATT&CK kill chain).  Unlike the five
  core signals it is *additive*: the core signals produce the 0-100
  base exactly as before, then correlated-case context adds up to 15
  points on top, capped at 100.  Doctrine: **context is an aggravator,
  never a mitigator** — an alert can only score higher for being part
  of a case, never lower, and a solo alert is completely unaffected.

NIST 800-61 Phase: Detection & Analysis — codifies the scoring rubric
that converts enriched observables into a structured triage verdict.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

# ---------------------------------------------------------------------------
# Signal weights (the five core signals sum to 100 for an intuitive 0-100
# risk scale; cluster_context is an ADDITIVE context signal that sits on
# top — up to +15, with the final score capped at 100)
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

WEIGHT_CLUSTER_CONTEXT: int = 15
"""Maximum ADDITIVE points from correlated-case (cluster) context.

Unlike the five core weights this is not part of the 100-point
normalization base: the core signals compute the 0-100 score exactly as
if this signal did not exist, then cluster context adds up to this many
points on top (final score capped at 100).  When no correlated context
exists the signal is not applicable — it never enters the signal set,
so solo alerts score byte-identically to the five-signal engine."""

# Compile into a lookup for iteration.  The five CORE signals sum to 100;
# cluster_context (15) is additive on top and deliberately excluded from
# the core normalization denominator by the engine.
SIGNAL_WEIGHTS: dict[str, int] = {
    "impossible_travel": WEIGHT_IMPOSSIBLE_TRAVEL,
    "mfa_fatigue": WEIGHT_MFA_FATIGUE,
    "ip_reputation": WEIGHT_IP_REPUTATION,
    "device_novelty": WEIGHT_DEVICE_NOVELTY,
    "login_hour_anomaly": WEIGHT_LOGIN_HOUR_ANOMALY,
    "cluster_context": WEIGHT_CLUSTER_CONTEXT,
}

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
        signals_total: Total number of signal types that were applicable
            to this incident (the 5 core signals, plus cluster_context
            when correlated-case context exists — not-applicable signals
            are excluded from both counts).
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


# ---------------------------------------------------------------------------
# Cluster (correlated-case) context
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ClusterContext:
    """Correlated-case context for the ``cluster_context`` engine signal.

    A read-only snapshot of the case this incident *would* join (or has
    already joined), taken by ``adte.store.case_store.peek_correlation_context``
    BEFORE scoring.  Sibling facts deliberately exclude the incident being
    scored, so re-triaging the same incident never counts itself as
    correlation evidence.

    Attributes:
        case_id: Identifier of the matched active case.
        sibling_count: Correlated member alerts, EXCLUDING this incident.
        distinct_sibling_tactics: Distinct ATT&CK tactics across sibling
            members only (not this incident's own tactics).
        kill_chain_detected: Whether the case-level kill-chain detector
            found an ascending tactic progression.
        max_sibling_risk_score: Highest sibling risk score — surfaced in
            the signal rationale for analyst context, never scored.
        window_minutes: The correlation window, echoed for rationale text.
    """

    case_id: str
    sibling_count: int
    distinct_sibling_tactics: int
    kill_chain_detected: bool
    max_sibling_risk_score: float
    window_minutes: int
