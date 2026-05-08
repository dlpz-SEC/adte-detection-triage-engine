"""Alert enrichment with MITRE ATT&CK and NIST CSF mappings.

Enriches a normalized alert dict with tactic, technique, and NIST
category data.  Uses a deterministic keyword lookup first; falls back
to a mock response when no match is found (LLM enrichment to be wired
in once an API key is available).

NIST 800-61 Phase: Detection & Analysis — context enrichment before
triage scoring.
"""

from __future__ import annotations

from typing import Any

from adte.intel.mitre_mapper import MitreMapper

# Lazy-loaded so a missing YAML file doesn't crash the server at import time.
_mapper: MitreMapper | None = None


def _get_mapper() -> MitreMapper | None:
    """Return the module-level MitreMapper, loading it on first call.

    Returns:
        Loaded MitreMapper, or None if the YAML file is absent.
    """
    global _mapper
    if _mapper is None:
        try:
            _mapper = MitreMapper.load()
        except FileNotFoundError:
            pass
    return _mapper


def enrich_alert(normalized_alert: dict[str, Any]) -> dict[str, Any]:
    """Enrich an alert with MITRE ATT&CK and NIST CSF mappings.

    Attempts a deterministic keyword lookup against the curated MITRE
    mapping file first.  If no rule keyword matches, returns a mock
    response with low confidence to signal that manual review is needed.

    Args:
        normalized_alert: A normalized alert dict containing at least a
            ``rule_description`` key.

    Returns:
        Enrichment dict with keys: source, mitre_tactic,
        mitre_technique_id, nist_category, confidence,
        analyst_recommendation.
    """
    rule_desc = normalized_alert.get("rule_description", "")
    m = _get_mapper()
    mitre_mapping = m.lookup_by_rule_text(rule_desc) if m else None

    if mitre_mapping:
        return {
            "source": "deterministic_mapping",
            "mitre_tactic": mitre_mapping["mitre_tactic"],
            "mitre_technique_id": mitre_mapping["mitre_technique_id"],
            "nist_category": mitre_mapping["nist_detect"],
            "confidence": 1.0,
            "analyst_recommendation": (
                f"Matches {mitre_mapping['mitre_technique_name']}"
            ),
        }

    # No deterministic match — return mock until LLM enrichment is wired in.
    return {
        "source": "mock_llm",
        "mitre_tactic": "Unknown",
        "mitre_technique_id": "T0000",
        "nist_category": "DE.CM-1",
        "confidence": 0.5,
        "analyst_recommendation": "Manual review required",
    }
