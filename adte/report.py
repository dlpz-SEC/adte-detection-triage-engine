"""Structured report generation for triage output.

Builds the NIST 800-61 aligned report section with optional
LLM-assisted narrative summary.
"""

from __future__ import annotations

from typing import Any

from adte.llm_assist import generate_summary


def generate_report(
    decision_output: dict[str, Any],
    *,
    use_llm: bool = False,
) -> dict[str, Any]:
    """Augment a triage output dict with narrative report fields.

    Adds ``one_paragraph_summary`` and ``analyst_notes`` to the
    existing ``report`` section of the output.

    Args:
        decision_output: The canonical output dict from
            ``TriageEngine.to_output()``.
        use_llm: If True and an API key is available, use the LLM
            to polish the summary.  Otherwise use the deterministic
            template.

    Returns:
        The (mutated) ``report`` sub-dict with added narrative fields.
    """
    report = decision_output.get("report", {})

    if use_llm:
        summary = generate_summary(decision_output)
    else:
        from adte.llm_assist import _build_deterministic_summary

        summary = _build_deterministic_summary(decision_output)

    report["one_paragraph_summary"] = summary
    report["analyst_notes"] = _build_analyst_notes(decision_output)

    return report


def _build_analyst_notes(decision_output: dict[str, Any]) -> list[str]:
    """Build actionable analyst notes from the triage output.

    Args:
        decision_output: The canonical output dict.

    Returns:
        A list of analyst-facing notes.
    """
    notes: list[str] = []
    verdict = decision_output.get("verdict", "unknown")
    rationale = decision_output.get("rationale", [])

    fired = [r for r in rationale if r.get("score", 0) > 0]

    if verdict == "high_risk":
        notes.append(
            "HIGH RISK — immediate containment recommended per NIST 800-61."
        )
    elif verdict == "medium_risk":
        notes.append(
            "MEDIUM RISK — escalate for analyst review within SLA."
        )
    else:
        notes.append(
            "LOW RISK — consider auto-closing and updating baselines."
        )

    for signal in fired:
        notes.append(
            f"Signal '{signal['signal']}' fired (score {signal['score']}): "
            f"{signal['detail']}"
        )

    if not fired:
        notes.append("No signals fired — all indicators were benign.")

    return notes
