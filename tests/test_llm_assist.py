"""Tests for adte.llm_assist — LLM integration.

These tests establish the safety contract that the LLM advisory
layer must honour: it can provide rationale and analysis, but it
must never override the deterministic scoring verdict.
"""

from __future__ import annotations

from adte.llm_assist import _build_deterministic_summary, generate_summary


def _make_decision_output(
    verdict: str = "high_risk",
    risk_score: int = 75,
    confidence: int = 80,
) -> dict:
    """Build a minimal decision_output dict for testing."""
    return {
        "verdict": verdict,
        "risk_score": risk_score,
        "confidence": confidence,
        "rationale": [
            {"signal": "impossible_travel", "score": 30.0, "detail": "NYC -> Moscow"},
            {"signal": "mfa_fatigue", "score": 25.0, "detail": "12 denials in 10 min"},
            {"signal": "ip_reputation", "score": 20.0, "detail": "1 malicious IP"},
            {"signal": "device_novelty", "score": 0.0, "detail": "All devices known"},
            {"signal": "login_hour_anomaly", "score": 0.0, "detail": "Within baseline"},
        ],
    }


class TestLLMSafetyContract:
    """Tests for the LLM safety contract."""

    def test_llm_cannot_override_verdict(self) -> None:
        """LLM output must not change the deterministic verdict.

        The contract is:

        1. The triage engine computes a verdict deterministically.
        2. The LLM may add narrative rationale or suggest
           investigation steps.
        3. The LLM output must NEVER change the verdict, risk_score,
           or recommended_action fields.
        """
        output = _make_decision_output()
        summary = generate_summary(output)
        # Summary is a string — it cannot mutate the output dict.
        assert isinstance(summary, str)
        # Original output unchanged.
        assert output["verdict"] == "high_risk"
        assert output["risk_score"] == 75

    def test_summary_does_not_contain_verdict_override(self) -> None:
        """Summary text must not instruct overriding the verdict."""
        output = _make_decision_output(verdict="high_risk")
        summary = generate_summary(output)
        lower = summary.lower()
        assert "override" not in lower
        assert "change verdict" not in lower


class TestDeterministicSummary:
    """Tests for the deterministic (no-API-key) summary path."""

    def test_deterministic_summary_without_api_key(
        self, monkeypatch: object,
    ) -> None:
        """Without API keys, generate_summary uses deterministic template."""
        import adte.llm_assist as mod

        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("AZURE_OPENAI_API_KEY", raising=False)

        output = _make_decision_output()
        summary = generate_summary(output)

        # Should NOT have the AI prefix.
        assert "[AI-assisted summary" not in summary
        # Should contain the verdict and score.
        assert "high risk" in summary
        assert "75" in summary

    def test_deterministic_summary_includes_fired_signals(self) -> None:
        """Deterministic summary mentions fired signal names."""
        output = _make_decision_output()
        summary = _build_deterministic_summary(output)
        assert "impossible travel" in summary
        assert "mfa fatigue" in summary
        assert "ip reputation" in summary

    def test_deterministic_summary_all_benign(self) -> None:
        """When no signals fire, summary says all benign."""
        output = _make_decision_output(verdict="low_risk", risk_score=0, confidence=80)
        output["rationale"] = [
            {"signal": "impossible_travel", "score": 0.0, "detail": "Normal"},
            {"signal": "mfa_fatigue", "score": 0.0, "detail": "None"},
            {"signal": "ip_reputation", "score": 0.0, "detail": "Clean"},
            {"signal": "device_novelty", "score": 0.0, "detail": "Known"},
            {"signal": "login_hour_anomaly", "score": 0.0, "detail": "OK"},
        ]
        summary = _build_deterministic_summary(output)
        assert "benign" in summary.lower()
        assert "low risk" in summary

    def test_deterministic_summary_medium_risk(self) -> None:
        """Medium risk summary contains correct verdict label."""
        output = _make_decision_output(verdict="medium_risk", risk_score=45)
        summary = _build_deterministic_summary(output)
        assert "medium risk" in summary
