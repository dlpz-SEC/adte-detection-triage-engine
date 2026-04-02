"""Core triage engine: enrichment, scoring, and verdict pipeline.

Orchestrates the full NIST 800-61 Detection & Analysis workflow:

1. **Enrich** — pull in threat intel, FP registry, user history, and
   geographic context for every observable in the incident.
2. **Score** — evaluate each signal class and accumulate a weighted
   risk score.
3. **Decide** — classify the risk score into a verdict and derive
   a recommended action.
4. **Output** — produce a structured JSON-serialisable report.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from adte.decision_policy import (
    SIGNAL_WEIGHTS,
    Verdict,
    classify_verdict,
    compute_confidence,
)
from adte.intel.sigma_fp_registry import FPRegistry
from adte.intel.threat_intel import check_threat_intel
from adte.models import (
    NormalizedIncident,
    SignInMetadata,
    ThreatIntelResult,
    UserProfile,
)
from adte.report import generate_report
from adte.utils.geo import (
    calculate_travel_speed,
    haversine_distance,
    is_impossible_travel,
)

# ---------------------------------------------------------------------------
# Internal types
# ---------------------------------------------------------------------------

# Each signal method returns (score, rationale, confidence).
#   score      – weighted points contributed (0 .. weight_max)
#   rationale  – human-readable explanation
#   confidence – per-signal confidence 0.0 .. 1.0
SignalResult = tuple[float, str, float]


def _ensure_aware(dt: datetime) -> datetime:
    """Return *dt* as a timezone-aware datetime (assume UTC if naive).

    Args:
        dt: A datetime that may or may not carry tzinfo.

    Returns:
        The same instant as a UTC-aware datetime.
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt

# MFA fatigue detection parameters.
_MFA_DENIAL_THRESHOLD: int = 3
_MFA_WINDOW_MINUTES: float = 10.0

# Recommended actions keyed by verdict.
_RECOMMENDED_ACTIONS: dict[Verdict, str] = {
    "high_risk": "Immediately disable account, revoke sessions, escalate to Tier-2",
    "medium_risk": "Escalate to analyst for manual review within SLA",
    "low_risk": "Auto-close as benign — log for baseline update",
}


class TriageEngine:
    """Stateful triage pipeline for a single normalised incident.

    Typical usage::

        engine = TriageEngine(incident, user_profile, fp_registry)
        output = engine.enrich().score().decide().to_output()

    Each pipeline stage mutates internal state and returns ``self``
    so calls can be chained fluently.
    """

    def __init__(
        self,
        incident: NormalizedIncident,
        user_profile: UserProfile,
        fp_registry: FPRegistry,
    ) -> None:
        """Initialise the triage engine.

        Args:
            incident: The normalised incident to triage.
            user_profile: Behavioural baseline for the primary user.
            fp_registry: Known-benign false-positive registry.
        """
        self._incident = incident
        self._profile = user_profile
        self._fp_registry = fp_registry

        # Enrichment artefacts (populated by enrich()).
        self._threat_intel_results: dict[str, ThreatIntelResult] = {}
        self._fp_matches: dict[str, str | None] = {}

        # Signal results (populated by score()).
        self._signals: dict[str, SignalResult] = {}
        self._skipped_signals: set[str] = set()
        self._risk_score: int = 0
        self._confidence: int = 0

        # Decision artefacts (populated by decide()).
        self._verdict: Verdict = "medium_risk"
        self._recommended_action: str = ""
        self._actions: list[str] = []

    # ------------------------------------------------------------------
    # Pipeline stages
    # ------------------------------------------------------------------

    def enrich(self) -> "TriageEngine":
        """Run enrichment lookups for every observable in the incident.

        Populates:
        - ``_threat_intel_results``: IP → ThreatIntelResult
        - ``_fp_matches``: IP → matching pattern_type or None

        Returns:
            ``self`` for fluent chaining.
        """
        seen_ips: set[str] = set()
        for event in self._incident.sign_in_events:
            ip = event.ip_address
            if not ip:
                continue
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            self._threat_intel_results[ip] = check_threat_intel(ip)
            _, ptype = self._fp_registry.is_known_benign_any(ip)
            self._fp_matches[ip] = ptype
        return self

    def score(self) -> "TriageEngine":
        """Evaluate all signal classes and compute the aggregate risk score.

        Returns:
            ``self`` for fluent chaining.
        """
        self._signals["impossible_travel"] = self._compute_impossible_travel()
        self._signals["mfa_fatigue"] = self._compute_mfa_fatigue()
        self._signals["ip_reputation"] = self._compute_ip_reputation()
        self._signals["device_novelty"] = self._compute_device_novelty()
        self._signals["login_hour_anomaly"] = self._compute_login_hour_anomaly()

        # Aggregate risk score with proportional weight redistribution for
        # skipped signals (signals that had no evaluable data).
        raw_sum = sum(s[0] for s in self._signals.values())
        skipped_weight = sum(
            SIGNAL_WEIGHTS[name] for name in self._skipped_signals
        )
        available_weight = 100 - skipped_weight
        if available_weight < 100:
            self._risk_score = max(0, min(100, round(
                raw_sum * 100 / available_weight
            )))
        else:
            self._risk_score = max(0, min(100, round(raw_sum)))

        # Confidence: coverage × agreement.
        # Skipped signals do not contribute to coverage.
        fired = [s for s in self._signals.values() if s[0] > 0]
        non_fired = [s for s in self._signals.values() if s[0] == 0]
        signals_present = len(SIGNAL_WEIGHTS) - len(self._skipped_signals)
        if fired:
            avg_confidence = sum(s[2] for s in fired) / len(fired)
        elif non_fired:
            avg_confidence = sum(s[2] for s in non_fired) / len(non_fired)
        else:
            avg_confidence = 0.0

        self._confidence = compute_confidence(
            signals_present=signals_present,
            signals_total=len(SIGNAL_WEIGHTS),
            signal_agreement=avg_confidence,
        )
        return self

    def decide(self) -> "TriageEngine":
        """Derive a verdict and recommended actions from the risk score.

        Returns:
            ``self`` for fluent chaining.
        """
        self._verdict = classify_verdict(self._risk_score)
        self._recommended_action = _RECOMMENDED_ACTIONS[self._verdict]

        self._actions = []
        if self._verdict == "high_risk":
            self._actions = [
                "disable_account",
                "revoke_sessions",
                "notify_soc_tier2",
                "create_ticket_p1",
            ]
        elif self._verdict == "medium_risk":
            self._actions = [
                "notify_soc_tier1",
                "request_user_verification",
                "create_ticket_p3",
            ]
        else:
            self._actions = [
                "auto_close_incident",
                "update_baseline",
            ]
        return self

    def to_output(self, *, use_llm: bool = False) -> dict[str, Any]:
        """Serialise the triage result into the canonical output schema.

        Args:
            use_llm: If True and an API key is available, use the LLM
                to generate a polished narrative summary.

        Returns:
            A JSON-serialisable dict with keys: ``verdict``,
            ``risk_score``, ``confidence``, ``recommended_action``,
            ``actions``, ``rationale``, ``evidence``, ``safety``,
            ``report``.
        """
        output = {
            "verdict": self._verdict,
            "risk_score": self._risk_score,
            "confidence": self._confidence,
            "recommended_action": self._recommended_action,
            "actions": self._actions,
            "rationale": [
                {"signal": name, "score": round(result[0], 1), "detail": result[1]}
                for name, result in self._signals.items()
            ],
            "evidence": self._build_evidence(),
            "safety": self._build_safety(),
            "report": self._build_report(),
        }
        output["report"] = generate_report(output, use_llm=use_llm)
        return output

    # ------------------------------------------------------------------
    # Signal computation methods
    # ------------------------------------------------------------------

    def _compute_impossible_travel(self) -> SignalResult:
        """Evaluate impossible-travel signal.

        Compares consecutive sign-in locations (and the user's
        ``last_seen_location``) to detect physically implausible
        movement speeds.

        Returns:
            ``(score, rationale, confidence)`` tuple.
        """
        weight = SIGNAL_WEIGHTS["impossible_travel"]
        events = self._incident.sign_in_events

        # Filter to events that have location data.
        located_events = [e for e in events if e.location is not None]

        if len(located_events) < 2 and not self._profile.last_seen_location:
            if not located_events:
                # No location data at all — skip the signal entirely and
                # redistribute its weight proportionally to the remaining signals.
                self._skipped_signals.add("impossible_travel")
                return (
                    0.0,
                    "Location data unavailable — signal skipped; "
                    "weight redistributed proportionally to remaining signals",
                    0.0,
                )
            return (0.0, "Insufficient location data for travel analysis", 0.3)

        max_speed: float = 0.0
        worst_pair: str = ""

        # Build comparison pairs: include last_seen → first located event if available.
        pairs: list[tuple[str, float, float, datetime, str, float, float, datetime]] = []

        if self._profile.last_seen_location and self._profile.last_seen_at and located_events:
            first = located_events[0]
            pairs.append((
                f"{self._profile.last_seen_location.city or 'last_seen'}",
                self._profile.last_seen_location.lat,
                self._profile.last_seen_location.lon,
                _ensure_aware(self._profile.last_seen_at),
                f"{first.location.city or first.ip_address}",  # type: ignore[union-attr]
                first.location.lat,  # type: ignore[union-attr]
                first.location.lon,  # type: ignore[union-attr]
                _ensure_aware(first.timestamp),
            ))

        for i in range(len(located_events) - 1):
            a, b = located_events[i], located_events[i + 1]
            if a.ip_address == b.ip_address:
                continue
            pairs.append((
                f"{a.location.city or a.ip_address}",  # type: ignore[union-attr]
                a.location.lat,  # type: ignore[union-attr]
                a.location.lon,  # type: ignore[union-attr]
                _ensure_aware(a.timestamp),
                f"{b.location.city or b.ip_address}",  # type: ignore[union-attr]
                b.location.lat,  # type: ignore[union-attr]
                b.location.lon,  # type: ignore[union-attr]
                _ensure_aware(b.timestamp),
            ))

        for label_a, lat_a, lon_a, ts_a, label_b, lat_b, lon_b, ts_b in pairs:
            dist = haversine_distance(lat_a, lon_a, lat_b, lon_b)
            delta_min = (ts_b - ts_a).total_seconds() / 60.0
            if delta_min <= 0:
                continue
            speed = calculate_travel_speed(dist, delta_min)
            if speed > max_speed:
                max_speed = speed
                worst_pair = (
                    f"{label_a} -> {label_b}: "
                    f"{dist:.0f} km in {delta_min:.0f} min = {speed:.0f} km/h"
                )

        if is_impossible_travel(max_speed):
            confidence = min(1.0, max_speed / 2000.0 + 0.5)
            return (
                float(weight),
                f"Impossible travel detected — {worst_pair}",
                confidence,
            )

        if max_speed > 500:
            partial = weight * (max_speed - 500) / 300.0
            return (
                min(float(weight), partial),
                f"Borderline travel speed — {worst_pair}",
                0.5,
            )

        return (0.0, f"Travel speed within normal range ({max_speed:.0f} km/h)", 0.8)

    def _compute_mfa_fatigue(self) -> SignalResult:
        """Evaluate MFA fatigue / push-spray signal.

        Counts MFA denials within a sliding window.  Three or more
        denials in a 10-minute window are flagged.

        Returns:
            ``(score, rationale, confidence)`` tuple.
        """
        weight = SIGNAL_WEIGHTS["mfa_fatigue"]
        events = self._incident.sign_in_events
        denied = [e for e in events if e.mfa_result == "Denied"]
        total_mfa = [e for e in events if e.mfa_result != "NotAttempted"]

        if not total_mfa:
            # No MFA data at all — skip the signal and redistribute its weight.
            self._skipped_signals.add("mfa_fatigue")
            return (
                0.0,
                "No MFA events to evaluate — signal skipped; "
                "weight redistributed proportionally to remaining signals",
                0.0,
            )

        # Sliding window: find the worst burst.
        max_denials_in_window: int = 0
        for i, start_event in enumerate(denied):
            window_end = start_event.timestamp.timestamp() + _MFA_WINDOW_MINUTES * 60
            count = sum(
                1 for d in denied[i:]
                if d.timestamp.timestamp() <= window_end
            )
            max_denials_in_window = max(max_denials_in_window, count)

        # Check if a denial burst was eventually followed by a success
        # (the hallmark of fatigue capitulation).
        fatigue_success = (
            len(denied) >= _MFA_DENIAL_THRESHOLD
            and any(e.mfa_result == "Success" for e in events if e.timestamp > denied[0].timestamp)
        )

        if max_denials_in_window >= _MFA_DENIAL_THRESHOLD:
            confidence = min(1.0, max_denials_in_window / 10.0 + 0.3)
            detail = (
                f"{max_denials_in_window} MFA denials in "
                f"{_MFA_WINDOW_MINUTES:.0f}-min window "
                f"({len(denied)}/{len(total_mfa)} total denied)"
            )
            if fatigue_success:
                detail += " — followed by approval (fatigue capitulation likely)"
                confidence = min(1.0, confidence + 0.2)
            return (float(weight), detail, confidence)

        denial_ratio = len(denied) / len(total_mfa) if total_mfa else 0.0
        return (
            0.0,
            f"MFA denial rate {denial_ratio:.0%} ({len(denied)}/{len(total_mfa)}) "
            f"below fatigue threshold",
            0.7,
        )

    def _compute_ip_reputation(self) -> SignalResult:
        """Evaluate IP reputation signal.

        Checks each unique IP against threat intel and the FP registry.
        IPs that match a known-benign pattern are excluded from the
        malicious count.

        Returns:
            ``(score, rationale, confidence)`` tuple.
        """
        weight = SIGNAL_WEIGHTS["ip_reputation"]

        if not self._threat_intel_results:
            return (0.0, "No IPs to evaluate", 0.3)

        malicious_ips: list[str] = []
        benign_overrides: list[str] = []
        worst_confidence: float = 0.0
        worst_tags: list[str] = []

        for ip, result in self._threat_intel_results.items():
            fp_match = self._fp_matches.get(ip)
            if fp_match:
                benign_overrides.append(f"{ip} (known {fp_match})")
                continue
            if result.is_malicious:
                malicious_ips.append(ip)
                if result.confidence > worst_confidence:
                    worst_confidence = result.confidence
                    worst_tags = result.tags

        if malicious_ips:
            tag_str = ", ".join(worst_tags) if worst_tags else "unknown"
            detail = (
                f"{len(malicious_ips)} malicious IP(s): "
                f"{', '.join(malicious_ips)} [tags: {tag_str}]"
            )
            if benign_overrides:
                detail += f"; {len(benign_overrides)} FP-suppressed"
            return (float(weight), detail, worst_confidence)

        parts: list[str] = ["No malicious IPs detected"]
        if benign_overrides:
            parts.append(f"{len(benign_overrides)} matched FP registry")
        return (0.0, "; ".join(parts), 0.8)

    def _compute_device_novelty(self) -> SignalResult:
        """Evaluate device-novelty signal.

        Compares device IDs in the incident against the user's
        ``known_devices`` inventory.

        Returns:
            ``(score, rationale, confidence)`` tuple.
        """
        weight = SIGNAL_WEIGHTS["device_novelty"]
        events = self._incident.sign_in_events

        if not events:
            return (0.0, "No sign-in events to evaluate", 0.3)

        known_ids = {d.device_id for d in self._profile.known_devices}
        incident_devices: dict[str, str] = {}
        for event in events:
            if event.device_id and event.device_id not in incident_devices:
                incident_devices[event.device_id] = event.device_name

        if not incident_devices:
            # No device IDs at all — unmanaged devices are suspicious.
            return (
                float(weight) * 0.5,
                "Sign-in events have no device IDs (unmanaged devices)",
                0.4,
            )

        novel = {
            did: name for did, name in incident_devices.items()
            if did not in known_ids
        }

        if novel:
            names = ", ".join(f"{name} ({did})" for did, name in novel.items())
            confidence = min(1.0, 0.5 + len(novel) * 0.15)
            return (
                float(weight),
                f"{len(novel)} unknown device(s): {names}",
                confidence,
            )

        known_names = ", ".join(
            f"{name} ({did})" for did, name in incident_devices.items()
        )
        return (0.0, f"All devices recognised: {known_names}", 0.9)

    def _compute_login_hour_anomaly(self) -> SignalResult:
        """Evaluate login-hour anomaly signal.

        Compares sign-in timestamps against the user's baseline
        login-hour window.

        Returns:
            ``(score, rationale, confidence)`` tuple.
        """
        weight = SIGNAL_WEIGHTS["login_hour_anomaly"]
        events = self._incident.sign_in_events
        baseline = self._profile.baseline_login_hours

        if not events:
            return (0.0, "No sign-in events to evaluate", 0.3)

        outside_count = 0
        for event in events:
            event_time = event.timestamp.time()
            if baseline.start <= baseline.end:
                in_window = baseline.start <= event_time <= baseline.end
            else:
                # Wraps midnight (e.g. 22:00 – 06:00).
                in_window = event_time >= baseline.start or event_time <= baseline.end
            if not in_window:
                outside_count += 1

        if outside_count == 0:
            return (
                0.0,
                f"All {len(events)} events within baseline hours "
                f"({baseline.start.strftime('%H:%M')}–{baseline.end.strftime('%H:%M')} "
                f"{baseline.timezone})",
                0.8,
            )

        ratio = outside_count / len(events)
        score = float(weight) * ratio
        confidence = 0.4 + ratio * 0.3
        return (
            score,
            f"{outside_count}/{len(events)} events outside baseline hours "
            f"({baseline.start.strftime('%H:%M')}–{baseline.end.strftime('%H:%M')} "
            f"{baseline.timezone})",
            confidence,
        )

    # ------------------------------------------------------------------
    # Output helpers
    # ------------------------------------------------------------------

    def _build_evidence(self) -> dict[str, Any]:
        """Compile raw evidence artefacts for the output report.

        Returns:
            Dict of evidence sections keyed by category.
        """
        return {
            "threat_intel": {
                ip: {
                    "is_malicious": r.is_malicious,
                    "confidence": r.confidence,
                    "source": r.source,
                    "tags": r.tags,
                }
                for ip, r in self._threat_intel_results.items()
            },
            "fp_matches": {
                ip: ptype for ip, ptype in self._fp_matches.items() if ptype
            },
            "sign_in_count": len(self._incident.sign_in_events),
            "unique_ips": list(self._threat_intel_results.keys()),
            "user": self._incident.user,
            "incident_id": self._incident.incident_id,
        }

    def _build_safety(self) -> dict[str, Any]:
        """Compile safety metadata for the output report.

        NIST 800-61: records what automated actions are permitted and
        whether human review is required.

        Returns:
            Dict with safety-related flags and checks.
        """
        return {
            "human_review_required": self._verdict != "low_risk",
            "automated_actions_permitted": self._verdict == "high_risk",
            "kill_switch_note": (
                "All automated actions honour ADTE_KILL_SWITCH. "
                "Set ADTE_KILL_SWITCH=true to halt."
            ),
            "dry_run_note": (
                "ADTE_DRY_RUN=true prevents write/mutate operations. "
                "Set ADTE_EXECUTION_ENABLED=true to allow actions."
            ),
        }

    def _build_report(self) -> dict[str, Any]:
        """Compile the NIST 800-61 structured report section.

        Returns:
            Dict with NIST-aligned report metadata.
        """
        return {
            "nist_phase": "Detection & Analysis",
            "incident_id": self._incident.incident_id,
            "severity": self._incident.severity,
            "user": self._incident.user,
            "verdict": self._verdict,
            "risk_score": self._risk_score,
            "confidence": self._confidence,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "signal_summary": {
                name: {
                    "score": round(result[0], 1),
                    "max_possible": SIGNAL_WEIGHTS[name],
                    "confidence": round(result[2], 2),
                    "detail": result[1],
                }
                for name, result in self._signals.items()
            },
        }
