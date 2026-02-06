"""Optional LLM integration for narrative summaries.

Provides AI-assisted plain-English summaries of triage results.
Falls back to deterministic template-based summaries when no API
key is configured or when the API call fails.

Safety contract:
- LLM output is ADVISORY ONLY and prefixed with a disclaimer.
- LLM receives ONLY the rationale list and verdict — never raw
  evidence, actions, or safety configuration.
- LLM output MUST NEVER override the deterministic verdict,
  risk_score, or recommended_action fields.
"""

from __future__ import annotations

import os
from typing import Any

_LLM_PREFIX = "[AI-assisted summary — non-authoritative]\n"


def _has_api_key() -> bool:
    """Return True if an OpenAI or Azure OpenAI key is configured."""
    return bool(
        os.environ.get("OPENAI_API_KEY")
        or os.environ.get("AZURE_OPENAI_API_KEY")
    )


def _build_deterministic_summary(decision_output: dict[str, Any]) -> str:
    """Build a template-based summary from the rationale list.

    Args:
        decision_output: The canonical output dict from TriageEngine.

    Returns:
        A plain-English summary paragraph.
    """
    verdict = decision_output.get("verdict", "unknown")
    risk_score = decision_output.get("risk_score", 0)
    confidence = decision_output.get("confidence", 0)
    rationale = decision_output.get("rationale", [])

    fired = [r for r in rationale if r.get("score", 0) > 0]
    quiet = [r for r in rationale if r.get("score", 0) == 0]

    verdict_label = verdict.replace("_", " ")

    if not fired:
        return (
            f"Verdict: {verdict_label} (score {risk_score}/100, "
            f"confidence {confidence}%). "
            f"No signals fired — all {len(quiet)} indicators were benign."
        )

    signal_parts = [
        f"{r['signal'].replace('_', ' ')} ({r['detail']})"
        for r in fired
    ]
    signals_text = "; ".join(signal_parts)

    return (
        f"Verdict: {verdict_label} (score {risk_score}/100, "
        f"confidence {confidence}%). "
        f"Key signals: {signals_text}."
    )


def _build_llm_prompt(decision_output: dict[str, Any]) -> str:
    """Build the prompt sent to the LLM.

    Only includes the verdict and rationale — never raw evidence
    or actions.

    Args:
        decision_output: The canonical output dict from TriageEngine.

    Returns:
        A prompt string for the LLM.
    """
    verdict = decision_output.get("verdict", "unknown")
    risk_score = decision_output.get("risk_score", 0)
    confidence = decision_output.get("confidence", 0)
    rationale = decision_output.get("rationale", [])

    rationale_text = "\n".join(
        f"- {r['signal']}: score={r['score']}, detail={r['detail']}"
        for r in rationale
    )

    return (
        "You are a security analyst writing a brief incident summary.\n"
        "Summarise the following triage result in 2-3 sentences.\n"
        "Do NOT change or contradict the verdict.\n\n"
        f"Verdict: {verdict}\n"
        f"Risk score: {risk_score}/100\n"
        f"Confidence: {confidence}%\n\n"
        f"Signal rationale:\n{rationale_text}"
    )


def _call_openai(prompt: str) -> str | None:
    """Call the OpenAI API and return the response text.

    Returns None if the call fails for any reason.
    """
    try:
        import openai  # noqa: F811

        client = openai.OpenAI(timeout=10.0)
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=256,
            temperature=0.3,
        )
        return response.choices[0].message.content
    except Exception:
        return None


def generate_summary(decision_output: dict[str, Any]) -> str:
    """Generate a plain-English summary of a triage decision.

    If an OpenAI API key is configured, calls the LLM for a polished
    narrative.  Otherwise (or on failure) falls back to a deterministic
    template-based summary.

    The LLM output is always prefixed with a non-authoritative
    disclaimer.

    Args:
        decision_output: The canonical output dict from
            ``TriageEngine.to_output()``.

    Returns:
        A human-readable summary string.
    """
    if _has_api_key():
        prompt = _build_llm_prompt(decision_output)
        llm_text = _call_openai(prompt)
        if llm_text:
            return _LLM_PREFIX + llm_text

    return _build_deterministic_summary(decision_output)
