"""Tests for adte.engine — full triage pipeline."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from adte.engine import TriageEngine
from adte.intel.sigma_fp_registry import FPRegistry
from adte.models import GeoLocation, NormalizedIncident, SignInMetadata
from adte.store.user_history import get_user_profile

# Required keys in every triage output.
_OUTPUT_KEYS = {
    "verdict",
    "risk_score",
    "confidence",
    "recommended_action",
    "actions",
    "rationale",
    "evidence",
    "safety",
    "report",
}

_REPORT_KEYS = {
    "nist_phase",
    "incident_id",
    "severity",
    "user",
    "verdict",
    "risk_score",
    "confidence",
    "timestamp",
    "signal_summary",
}

_SAFETY_KEYS = {
    "human_review_required",
    "automated_actions_permitted",
    "kill_switch_note",
    "dry_run_note",
}


def _run_pipeline(
    incident: NormalizedIncident,
    fp_registry: FPRegistry,
) -> dict:
    """Run the full triage pipeline and return the output dict."""
    profile = get_user_profile(incident.user)
    engine = TriageEngine(incident, profile, fp_registry)
    return engine.enrich().score().decide().to_output()


class TestEngineVerdicts:
    """Test that each example incident produces the expected verdict."""

    def test_engine_true_positive(
        self,
        incident_true_positive: NormalizedIncident,
        fp_registry: FPRegistry,
    ) -> None:
        """Impossible travel + MFA fatigue → high_risk."""
        output = _run_pipeline(incident_true_positive, fp_registry)
        assert output["verdict"] == "high_risk"
        assert output["risk_score"] > 70
        assert output["confidence"] > 50

    def test_engine_false_positive(
        self,
        incident_false_positive: NormalizedIncident,
        fp_registry: FPRegistry,
    ) -> None:
        """Benign VPN travel → low_risk."""
        output = _run_pipeline(incident_false_positive, fp_registry)
        assert output["verdict"] == "low_risk"
        assert output["risk_score"] < 30

    def test_engine_needs_human(
        self,
        incident_ambiguous: NormalizedIncident,
        fp_registry: FPRegistry,
    ) -> None:
        """Ambiguous borderline travel + new device → medium_risk."""
        output = _run_pipeline(incident_ambiguous, fp_registry)
        assert output["verdict"] == "medium_risk"
        assert 30 <= output["risk_score"] <= 70


class TestEngineOutputSchema:
    """Test that the output dict conforms to the expected schema."""

    def test_engine_output_schema(
        self,
        incident_true_positive: NormalizedIncident,
        fp_registry: FPRegistry,
    ) -> None:
        """Output contains all required top-level keys."""
        output = _run_pipeline(incident_true_positive, fp_registry)
        assert _OUTPUT_KEYS.issubset(output.keys())

    def test_engine_report_schema(
        self,
        incident_true_positive: NormalizedIncident,
        fp_registry: FPRegistry,
    ) -> None:
        """Report section contains all required keys."""
        output = _run_pipeline(incident_true_positive, fp_registry)
        assert _REPORT_KEYS.issubset(output["report"].keys())

    def test_engine_safety_schema(
        self,
        incident_true_positive: NormalizedIncident,
        fp_registry: FPRegistry,
    ) -> None:
        """Safety section contains all required keys."""
        output = _run_pipeline(incident_true_positive, fp_registry)
        assert _SAFETY_KEYS.issubset(output["safety"].keys())

    def test_engine_rationale_structure(
        self,
        incident_true_positive: NormalizedIncident,
        fp_registry: FPRegistry,
    ) -> None:
        """Rationale is a list of dicts with signal/score/detail."""
        output = _run_pipeline(incident_true_positive, fp_registry)
        rationale = output["rationale"]
        assert isinstance(rationale, list)
        assert len(rationale) == 5  # one per signal
        for entry in rationale:
            assert "signal" in entry
            assert "score" in entry
            assert "detail" in entry

    def test_engine_risk_score_bounded(
        self,
        incident_true_positive: NormalizedIncident,
        incident_false_positive: NormalizedIncident,
        incident_ambiguous: NormalizedIncident,
        fp_registry: FPRegistry,
    ) -> None:
        """Risk score is always in [0, 100] range."""
        for inc in [incident_true_positive, incident_false_positive, incident_ambiguous]:
            output = _run_pipeline(inc, fp_registry)
            assert 0 <= output["risk_score"] <= 100
            assert 0 <= output["confidence"] <= 100


class TestEngineSignals:
    """Test individual signal detection in context."""

    def test_true_positive_fires_travel_mfa_ip(
        self,
        incident_true_positive: NormalizedIncident,
        fp_registry: FPRegistry,
    ) -> None:
        """True positive should fire impossible_travel, mfa_fatigue, ip_reputation."""
        output = _run_pipeline(incident_true_positive, fp_registry)
        scores = {r["signal"]: r["score"] for r in output["rationale"]}
        assert scores["impossible_travel"] > 0
        assert scores["mfa_fatigue"] > 0
        assert scores["ip_reputation"] > 0

    def test_false_positive_no_major_signals(
        self,
        incident_false_positive: NormalizedIncident,
        fp_registry: FPRegistry,
    ) -> None:
        """False positive should not fire travel, MFA, IP, or device signals."""
        output = _run_pipeline(incident_false_positive, fp_registry)
        scores = {r["signal"]: r["score"] for r in output["rationale"]}
        assert scores["impossible_travel"] == 0
        assert scores["mfa_fatigue"] == 0
        assert scores["ip_reputation"] == 0
        assert scores["device_novelty"] == 0

    def test_ambiguous_fires_travel_and_device(
        self,
        incident_ambiguous: NormalizedIncident,
        fp_registry: FPRegistry,
    ) -> None:
        """Ambiguous incident fires borderline travel and device novelty."""
        output = _run_pipeline(incident_ambiguous, fp_registry)
        scores = {r["signal"]: r["score"] for r in output["rationale"]}
        assert scores["impossible_travel"] > 0
        assert scores["device_novelty"] > 0
        assert scores["ip_reputation"] == 0


# ---------------------------------------------------------------------------
# Signal skip & weight redistribution tests
# ---------------------------------------------------------------------------

def _make_sign_in(
    *,
    ip: str,
    device_id: str = "",
    mfa_result: str = "NotAttempted",
    location: GeoLocation | None = None,
    ts: str = "2024-06-15T12:00:00+00:00",
) -> SignInMetadata:
    """Helper: build a minimal SignInMetadata for skip/redistribution tests."""
    return SignInMetadata(
        user_principal_name="wazuh-host@test.local",
        ip_address=ip,
        location=location,
        device_id=device_id,
        device_name="test-device",
        mfa_result=mfa_result,  # type: ignore[arg-type]
        timestamp=datetime.fromisoformat(ts),
    )


def _make_incident(sign_ins: list[SignInMetadata]) -> NormalizedIncident:
    """Helper: wrap sign-in events into a NormalizedIncident."""
    return NormalizedIncident(
        incident_id="TEST-SKIP-001",
        user="wazuh-host@test.local",
        sign_in_events=sign_ins,
        severity="High",
        created_time=datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc),
    )


class TestSignalSkipAndRedistribution:
    """Test skip-and-redistribute behaviour for signals without evaluable data."""

    def test_no_geo_skips_travel_signal(self, fp_registry: FPRegistry) -> None:
        """All sign-in events with location=None → impossible_travel skipped."""
        incident = _make_incident([_make_sign_in(ip="10.0.0.1", mfa_result="Success")])
        profile = get_user_profile(incident.user)
        engine = TriageEngine(incident, profile, fp_registry)
        engine.enrich().score()
        assert "impossible_travel" in engine._skipped_signals
        scores = {name: result[0] for name, result in engine._signals.items()}
        assert scores["impossible_travel"] == 0.0
        detail = engine._signals["impossible_travel"][1]
        assert "skipped" in detail.lower()

    def test_no_mfa_events_skips_mfa_signal(self, fp_registry: FPRegistry) -> None:
        """All MFA results NotAttempted → mfa_fatigue skipped."""
        incident = _make_incident([_make_sign_in(
            ip="10.0.0.1",
            mfa_result="NotAttempted",
            location=GeoLocation(lat=40.0, lon=-74.0, city="New York", country="US"),
        )])
        profile = get_user_profile(incident.user)
        engine = TriageEngine(incident, profile, fp_registry)
        engine.enrich().score()
        assert "mfa_fatigue" in engine._skipped_signals
        scores = {name: result[0] for name, result in engine._signals.items()}
        assert scores["mfa_fatigue"] == 0.0
        detail = engine._signals["mfa_fatigue"][1]
        assert "skipped" in detail.lower()

    def test_both_skipped_redistributes_weight(self, fp_registry: FPRegistry) -> None:
        """No geo + no MFA: IP rep (20) + device novelty (15) → score 78, high_risk.

        available_weight = 100 - 30 (travel) - 25 (mfa) = 45
        round(35 * 100 / 45) = round(77.78) = 78
        """
        incident = _make_incident([_make_sign_in(
            ip="198.51.100.23",    # malicious C2 IP → IP rep fires (20 pts)
            device_id="unknown-wazuh-device-xyz",  # unknown → device novelty fires (15 pts)
            mfa_result="NotAttempted",
            location=None,
        )])
        profile = get_user_profile(incident.user)  # unknown user, empty known_devices
        engine = TriageEngine(incident, profile, fp_registry)
        output = engine.enrich().score().decide().to_output()
        assert "impossible_travel" in engine._skipped_signals
        assert "mfa_fatigue" in engine._skipped_signals
        assert output["risk_score"] == 78
        assert output["verdict"] == "high_risk"

    def test_partial_geo_uses_available_pairs(self, fp_registry: FPRegistry) -> None:
        """One event with location, one without → travel still evaluates."""
        sign_ins = [
            _make_sign_in(
                ip="72.229.28.185",
                mfa_result="Success",
                location=GeoLocation(lat=40.7128, lon=-74.0060, city="New York", country="US"),
                ts="2024-06-15T10:00:00+00:00",
            ),
            _make_sign_in(
                ip="198.51.100.23",
                mfa_result="Success",
                location=None,  # no geo for second event
                ts="2024-06-15T10:30:00+00:00",
            ),
        ]
        incident = _make_incident(sign_ins)
        profile = get_user_profile(incident.user)
        engine = TriageEngine(incident, profile, fp_registry)
        engine.enrich().score()
        # impossible_travel should NOT be skipped — one valid event exists but
        # no pair can be formed (only 1 located event), so falls through to
        # "Insufficient location data" (not skipped, just score 0).
        assert "impossible_travel" not in engine._skipped_signals
