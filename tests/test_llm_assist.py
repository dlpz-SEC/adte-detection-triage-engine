"""Tests for adte.llm.assist — LLM integration and structured output.

These tests establish the safety contract that the LLM advisory
layer must honour: it can provide rationale and analysis, but it
must never override the deterministic scoring verdict.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from adte.llm.assist import (
    _build_deterministic_summary,
    _parse_llm_response,
    generate_summary,
)


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
        # Summary is a structured dict — it cannot mutate the output dict.
        assert isinstance(summary, dict)
        assert "narrative" in summary
        # Original output unchanged.
        assert output["verdict"] == "high_risk"
        assert output["risk_score"] == 75

    def test_summary_does_not_contain_verdict_override(self) -> None:
        """Summary text must not instruct overriding the verdict."""
        output = _make_decision_output(verdict="high_risk")
        summary = generate_summary(output)
        lower = summary["narrative"].lower()
        assert "override" not in lower
        assert "change verdict" not in lower


class TestDeterministicSummary:
    """Tests for the deterministic (no-API-key) summary path."""

    def test_deterministic_summary_without_api_key(
        self, monkeypatch: object,
    ) -> None:
        """Without API keys, generate_summary uses deterministic template."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)  # type: ignore[attr-defined]

        output = _make_decision_output()
        summary = generate_summary(output)

        # Should use the template-based fallback.
        assert "template-based" in summary["confidence_note"]
        # Should contain the verdict and score.
        assert "high risk" in summary["narrative"]
        assert "75" in summary["narrative"]

    def test_deterministic_summary_includes_fired_signals(self) -> None:
        """Deterministic summary mentions fired signal names."""
        output = _make_decision_output()
        summary = _build_deterministic_summary(output)
        assert "impossible travel" in summary["narrative"]
        assert "mfa fatigue" in summary["narrative"]
        assert "ip reputation" in summary["narrative"]
        # MITRE technique for impossible_travel should appear
        assert "T1078.004" in str(summary["mitre_techniques"])

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
        assert "benign" in summary["narrative"].lower()
        assert "low risk" in summary["narrative"]
        # No signals fired → no MITRE mappings
        assert summary["mitre_tactics"] == []
        assert summary["mitre_techniques"] == []

    def test_deterministic_summary_medium_risk(self) -> None:
        """Medium risk summary contains correct verdict label."""
        output = _make_decision_output(verdict="medium_risk", risk_score=45)
        summary = _build_deterministic_summary(output)
        assert "medium risk" in summary["narrative"]

    def test_deterministic_summary_has_all_required_keys(self) -> None:
        """Deterministic summary always returns all five required keys."""
        output = _make_decision_output()
        summary = _build_deterministic_summary(output)
        for key in (
            "narrative", "mitre_tactics", "mitre_techniques",
            "nist_phases", "confidence_note",
        ):
            assert key in summary, f"Missing key: {key}"

    def test_deterministic_summary_nist_phases(self) -> None:
        """Deterministic summary always includes baseline NIST CSF 2.0 phases."""
        output = _make_decision_output()
        summary = _build_deterministic_summary(output)
        assert "DE.CM-1" in summary["nist_phases"]
        assert "DE.CM-7" in summary["nist_phases"]
        assert "RS.AN-1" in summary["nist_phases"]


class TestClaudeAPIPath:
    """Tests for the Anthropic API (Claude) integration path."""

    def _make_valid_llm_response(self) -> dict:
        """Return a valid structured response dict."""
        return {
            "narrative": "This incident is high risk due to impossible travel.",
            "mitre_tactics": ["Initial Access", "Credential Access"],
            "mitre_techniques": [
                {"id": "T1078.004", "name": "Valid Accounts: Cloud Accounts"},
                {"id": "T1621", "name": "Multi-Factor Authentication Request Generation"},
            ],
            "nist_phases": ["DE.CM-1", "RS.AN-1"],
            "confidence_note": "High confidence in MITRE mappings for this pattern.",
        }

    def _mock_anthropic_client(self, response_dict: dict) -> MagicMock:
        """Build a mock that looks like anthropic.Anthropic()."""
        mock_block = MagicMock()
        mock_block.text = json.dumps(response_dict)
        mock_message = MagicMock()
        mock_message.content = [mock_block]
        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_message
        return mock_client

    def test_call_claude_returns_dict_on_success(
        self, monkeypatch: object,
    ) -> None:
        """_call_claude returns a parsed dict when the API succeeds."""
        import adte.llm.assist as mod

        valid_response = self._make_valid_llm_response()
        mock_client = self._mock_anthropic_client(valid_response)

        monkeypatch.setattr(mod.anthropic, "Anthropic", lambda: mock_client)  # type: ignore[attr-defined]

        result = mod._call_claude("test prompt")
        assert result is not None
        assert result["narrative"] == valid_response["narrative"]
        assert result["mitre_tactics"] == valid_response["mitre_tactics"]

    def test_call_claude_returns_none_on_api_error(
        self, monkeypatch: object,
    ) -> None:
        """_call_claude returns None when the API raises an exception."""
        import adte.llm.assist as mod

        mock_anthropic_class = MagicMock(side_effect=Exception("API error"))
        monkeypatch.setattr(mod.anthropic, "Anthropic", mock_anthropic_class)  # type: ignore[attr-defined]

        result = mod._call_claude("test prompt")
        assert result is None

    def test_generate_summary_uses_claude_when_key_set(
        self, monkeypatch: object,
    ) -> None:
        """generate_summary returns Claude output when ANTHROPIC_API_KEY is set."""
        import adte.llm.assist as mod

        valid_response = self._make_valid_llm_response()
        mock_client = self._mock_anthropic_client(valid_response)

        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-abc")  # type: ignore[attr-defined]
        monkeypatch.setattr(mod.anthropic, "Anthropic", lambda: mock_client)  # type: ignore[attr-defined]

        output = _make_decision_output()
        result = generate_summary(output)

        assert result["narrative"] == valid_response["narrative"]
        assert result["confidence_note"] == valid_response["confidence_note"]
        # Original output dict must be unchanged
        assert output["verdict"] == "high_risk"

    def test_generate_summary_falls_back_on_claude_failure(
        self, monkeypatch: object,
    ) -> None:
        """generate_summary falls back to deterministic when Claude fails."""
        import adte.llm.assist as mod

        mock_anthropic_class = MagicMock(side_effect=Exception("timeout"))
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-abc")  # type: ignore[attr-defined]
        monkeypatch.setattr(mod.anthropic, "Anthropic", mock_anthropic_class)  # type: ignore[attr-defined]

        output = _make_decision_output()
        result = generate_summary(output)

        # Must fall back to the template-based path
        assert "template-based" in result["confidence_note"]
        assert isinstance(result["narrative"], str)

    def test_parse_llm_response_strips_markdown_fences(self) -> None:
        """_parse_llm_response handles JSON wrapped in markdown code fences."""
        valid = self._make_valid_llm_response()
        fenced = f"```json\n{json.dumps(valid)}\n```"

        result = _parse_llm_response(fenced)
        assert result is not None
        assert result["narrative"] == valid["narrative"]

    def test_parse_llm_response_returns_none_on_missing_keys(self) -> None:
        """_parse_llm_response returns None when required keys are absent."""
        incomplete = {"narrative": "Some text", "mitre_tactics": []}  # missing 3 keys
        result = _parse_llm_response(json.dumps(incomplete))
        assert result is None

    def test_parse_llm_response_returns_none_on_invalid_json(self) -> None:
        """_parse_llm_response returns None on malformed JSON."""
        result = _parse_llm_response("not json at all {")
        assert result is None

    def test_parse_llm_response_accepts_valid_json(self) -> None:
        """_parse_llm_response accepts a valid JSON string with all keys."""
        valid = self._make_valid_llm_response()
        result = _parse_llm_response(json.dumps(valid))
        assert result is not None
        assert result["mitre_techniques"] == valid["mitre_techniques"]
