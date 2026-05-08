"""Narrative report fields for triage output (display only).

Adds the following fields to the ``report`` sub-dict that
``TriageEngine._build_report()`` produces:

  - one_paragraph_summary  - plain-English incident narrative
  - analyst_notes          - actionable, per-verdict bullet points
  - mitre_tactics          - MITRE ATT&CK tactic names
  - mitre_techniques       - MITRE ATT&CK technique IDs and names
  - nist_phases            - NIST CSF 2.0 category codes
  - confidence_note        - advisory note on MITRE mapping confidence

These fields are purely for human consumption — they do not feed back
into the engine and have no effect on ``verdict``, ``risk_score``,
``confidence``, or ``recommended_action``.

Callers that consume the triage output programmatically can ignore
the ``report`` key entirely; the authoritative decision fields are
at the top level of the output dict.
"""

from __future__ import annotations

from typing import Any

# _build_deterministic_summary is imported directly (bypassing generate_summary's
# API-key detection) so that use_llm=False is a guaranteed no-network path.
from adte.llm.assist import _build_deterministic_summary, generate_summary


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
    # Mutates the existing report sub-dict in place; callers should not hold
    # a separate reference to decision_output["report"] before calling this.
    report = decision_output.get("report", {})

    if use_llm:
        llm_result = generate_summary(decision_output)
    else:
        llm_result = _build_deterministic_summary(decision_output)

    report["one_paragraph_summary"] = llm_result["narrative"]
    report["mitre_tactics"]         = llm_result["mitre_tactics"]
    report["mitre_techniques"]      = llm_result["mitre_techniques"]
    report["nist_phases"]           = llm_result["nist_phases"]
    report["confidence_note"]       = llm_result["confidence_note"]
    report["analyst_notes"]         = _build_analyst_notes(decision_output)

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
