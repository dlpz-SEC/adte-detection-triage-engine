"""Tests for the B2 LLM response cache in adte.llm.assist.

A repeated generate_summary() with an identical decision output must serve
the cached Claude summary without a second API call; distinct outputs and
expired entries must go back to the API.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

import adte.llm.assist as assist


def _decision_output(detail: str = "baseline") -> dict[str, Any]:
    """Build a minimal TriageEngine-style output dict."""
    return {
        "verdict": "high_risk",
        "risk_score": 90,
        "confidence": 80,
        "rationale": [
            {"signal": "impossible_travel", "score": 30, "detail": detail},
        ],
    }


_LLM_JSON = (
    '{"narrative": "n", "mitre_tactics": [], "mitre_techniques": [],'
    ' "nist_phases": [], "confidence_note": "llm"}'
)


def _mock_client() -> MagicMock:
    """Mock anthropic.Anthropic whose messages.create returns valid JSON."""
    client = MagicMock()
    message = MagicMock()
    message.content = [MagicMock(text=_LLM_JSON)]
    client.messages.create.return_value = message
    return client


@pytest.fixture()
def api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Enable the LLM path with a fake key."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key-for-tests")


class TestLLMResponseCache:
    """Cache hit/miss behavior of generate_summary."""

    def test_second_identical_call_skips_api(self, api_key: None) -> None:
        """Same decision output twice → exactly one messages.create call."""
        client = _mock_client()
        with patch.object(assist.anthropic, "Anthropic", return_value=client):
            first = assist.generate_summary(_decision_output())
            second = assist.generate_summary(_decision_output())
        assert client.messages.create.call_count == 1
        assert first == second
        assert first["confidence_note"] == "llm"

    def test_distinct_outputs_call_api_separately(self, api_key: None) -> None:
        """Different rationale → different cache key → two API calls."""
        client = _mock_client()
        with patch.object(assist.anthropic, "Anthropic", return_value=client):
            assist.generate_summary(_decision_output("first"))
            assist.generate_summary(_decision_output("second"))
        assert client.messages.create.call_count == 2

    def test_expired_entry_calls_api_again(
        self, api_key: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """After the TTL elapses, the same output re-hits the API."""
        now = {"t": 1000.0}
        monkeypatch.setattr(assist.time, "monotonic", lambda: now["t"])
        client = _mock_client()
        with patch.object(assist.anthropic, "Anthropic", return_value=client):
            assist.generate_summary(_decision_output())
            now["t"] += assist._LLM_CACHE_TTL_SECONDS + 1
            assist.generate_summary(_decision_output())
        assert client.messages.create.call_count == 2

    def test_failed_api_result_is_not_cached(self, api_key: None) -> None:
        """A failed call falls back deterministically and caches nothing."""
        client = MagicMock()
        client.messages.create.side_effect = RuntimeError("api down")
        with patch.object(assist.anthropic, "Anthropic", return_value=client):
            result = assist.generate_summary(_decision_output())
        assert "template-based" in result["confidence_note"]
        assert len(assist._llm_cache) == 0

    def test_cached_result_is_a_copy(self, api_key: None) -> None:
        """Mutating a returned summary must not poison the cache."""
        client = _mock_client()
        with patch.object(assist.anthropic, "Anthropic", return_value=client):
            first = assist.generate_summary(_decision_output())
            first["narrative"] = "mutated"
            second = assist.generate_summary(_decision_output())
        assert second["narrative"] == "n"
