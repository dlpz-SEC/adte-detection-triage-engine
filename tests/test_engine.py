"""Tests for adte.engine — full triage pipeline."""

from __future__ import annotations

from adte.engine import TriageEngine
from adte.intel.sigma_fp_registry import FPRegistry
from adte.models import NormalizedIncident
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
