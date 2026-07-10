"""Incident enrichment with MITRE ATT&CK and NIST CSF mappings.

Wired into the triage pipeline via ``TriageEngine.llm_enrich()`` (called by
the ``/api/triage`` route).  Enrichment is **advisory only** — it never
influences ``risk_score``, ``verdict``, or ``confidence``.

Resolution order:
  1. **Native log labels** — when the source log carried MITRE technique IDs
     (e.g. Wazuh ``rule.mitre.id`` → per-event ``technique_ids``), those IDs
     are authoritative (``source: "native_log"``).
  2. **Keyword lookup** — otherwise the per-event rule text
     (``events[].app_display_name``; Wazuh puts ``rule.description`` there)
     is matched against the curated YAML technique map
     (``source: "deterministic_mapping"``).
  3. **None** — no native IDs and no keyword match means no enrichment;
     ``llm_enrichment`` stays ``null`` rather than emitting a misleading
     placeholder.

NIST 800-61 Phase: Detection & Analysis — context enrichment alongside
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


def _collect_native_ids(incident: dict[str, Any]) -> list[str]:
    """Collect distinct native technique IDs across the incident's events.

    Args:
        incident: ``NormalizedIncident.model_dump(mode="json")`` dict.

    Returns:
        Order-preserving list of distinct non-empty technique IDs.
    """
    ids: list[str] = []
    for event in incident.get("events") or []:
        for tid in event.get("technique_ids") or []:
            if tid and tid not in ids:
                ids.append(tid)
    return ids


def _collect_rule_text(incident: dict[str, Any]) -> str:
    """Join the distinct per-event rule text into one lookup string.

    Rule text lives per-event in ``app_display_name`` (the Wazuh adapter maps
    ``rule.description`` there).  Distinct non-empty values are joined with
    "; " in event order.  A legacy top-level ``rule_description`` key is
    honoured for backward compatibility with pre-OCSF callers.

    Args:
        incident: ``NormalizedIncident.model_dump(mode="json")`` dict.

    Returns:
        The combined rule text ("" when the incident carries none).
    """
    parts: list[str] = []
    for event in incident.get("events") or []:
        text = event.get("app_display_name") or ""
        if text and text not in parts:
            parts.append(text)
    legacy = incident.get("rule_description") or ""
    if legacy and legacy not in parts:
        parts.append(legacy)
    return "; ".join(parts)


def _entry_for_id(technique_id: str) -> dict[str, Any] | None:
    """Find the YAML mapping entry for an exact technique ID, if any.

    Args:
        technique_id: ATT&CK technique ID (e.g. ``"T1110.003"``).

    Returns:
        The matching mapping entry, or None.
    """
    m = _get_mapper()
    if m is None:
        return None
    for entry in m.mappings:
        if entry.get("mitre_technique_id") == technique_id:
            return entry
    return None


def enrich_alert(normalized_alert: dict[str, Any]) -> dict[str, Any] | None:
    """Enrich a normalised incident with MITRE ATT&CK / NIST CSF context.

    Advisory only — the result is surfaced as ``llm_enrichment`` in the
    triage output and never affects scoring.

    Args:
        normalized_alert: ``NormalizedIncident.model_dump(mode="json")``
            dict (a legacy flat dict with ``rule_description`` also works).

    Returns:
        Enrichment dict with keys ``source``, ``mitre_tactic``,
        ``mitre_technique_id``, ``technique_ids``, ``nist_category``,
        ``confidence``, ``analyst_recommendation`` — or ``None`` when the
        incident carries no native IDs and no rule text matches the map.
    """
    # 1. Native log labels win — the source SIEM already did the mapping.
    native_ids = _collect_native_ids(normalized_alert)
    if native_ids:
        primary = native_ids[0]
        entry = next(
            (e for tid in native_ids if (e := _entry_for_id(tid)) is not None),
            None,
        )
        if entry is not None:
            primary = entry["mitre_technique_id"]
        return {
            "source": "native_log",
            "mitre_tactic": entry["mitre_tactic"] if entry else "Unknown",
            "mitre_technique_id": primary,
            "technique_ids": native_ids,
            "nist_category": entry["nist_detect"] if entry else "DE.CM-1",
            "confidence": 1.0,
            "analyst_recommendation": (
                f"Log source labeled this {entry['mitre_technique_name']}"
                if entry
                else f"Log source labeled techniques: {', '.join(native_ids)}"
            ),
        }

    # 2. Deterministic keyword lookup on the per-event rule text.
    rule_text = _collect_rule_text(normalized_alert)
    m = _get_mapper()
    mitre_mapping = m.lookup_by_rule_text(rule_text) if (m and rule_text) else None
    if mitre_mapping:
        return {
            "source": "deterministic_mapping",
            "mitre_tactic": mitre_mapping["mitre_tactic"],
            "mitre_technique_id": mitre_mapping["mitre_technique_id"],
            "technique_ids": [mitre_mapping["mitre_technique_id"]],
            "nist_category": mitre_mapping["nist_detect"],
            "confidence": 1.0,
            "analyst_recommendation": (
                f"Matches {mitre_mapping['mitre_technique_name']}"
            ),
        }

    # 3. No enrichment found — stay null instead of emitting a placeholder.
    return None
