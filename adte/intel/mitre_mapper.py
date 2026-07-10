"""Lightweight MITRE ATT&CK → Wazuh rule mapping.

Maps Wazuh rule keywords to MITRE tactics/techniques and NIST categories
without requiring full framework dumps.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import yaml

# parents[1] walks up: mitre_mapper.py → intel/ → adte/data/
_MAPPING_PATH = Path(__file__).resolve().parents[1] / "data" / "mitre_technique_map.yaml"

_singleton: "MitreMapper | None" = None
_singleton_lock: threading.Lock = threading.Lock()


def _get_mapper() -> "MitreMapper | None":
    """Return the module-level cached MitreMapper, loading from disk on first call."""
    global _singleton
    if _singleton is None:
        # Double-checked lock: first check avoids lock contention on the hot path,
        # second check inside the lock handles the race between two waiting threads.
        with _singleton_lock:
            if _singleton is None:
                try:
                    _singleton = MitreMapper.load()
                except FileNotFoundError:
                    return None
    return _singleton


class MitreMapper:
    """Deterministic MITRE technique lookup by rule keyword."""

    def __init__(self, mappings: list[dict[str, Any]]) -> None:
        """Initialise with a pre-loaded list of mapping dicts.

        Args:
            mappings: List of mapping entries as loaded from YAML.
        """
        self.mappings = mappings
        # Flattened (keyword, entry) pairs in entry order — one pass per
        # lookup instead of a nested per-entry keyword scan. Entry-order
        # first-match semantics are preserved because every keyword of
        # entry N precedes every keyword of entry N+1.
        self._keyword_index: list[tuple[str, dict[str, Any]]] = [
            (kw, mapping)
            for mapping in mappings
            for kw in mapping.get("rule_keywords", [])
        ]

    @classmethod
    def load(cls, path: Path | str | None = None) -> "MitreMapper":
        """Load the mapping from YAML.

        Args:
            path: Path to the YAML file.  Defaults to
                ``adte/data/mitre_technique_map.yaml`` relative to the package.

        Returns:
            A MitreMapper instance populated with the loaded mappings.

        Raises:
            FileNotFoundError: If the resolved path does not exist.
        """
        resolved = Path(path) if path else _MAPPING_PATH
        if not resolved.exists():
            raise FileNotFoundError(f"MITRE mapping file not found: {resolved}")

        raw = yaml.safe_load(resolved.read_text(encoding="utf-8"))
        mappings = raw.get("mappings", [])
        return cls(mappings)

    def lookup_by_rule_text(self, rule_description: str) -> dict[str, Any] | None:
        """Find the first MITRE mapping whose keywords appear in rule text.

        Args:
            rule_description: A Wazuh rule description or alert title.

        Returns:
            The matching mapping dict, or None if no keyword matches.
        """
        rule_lower = rule_description.lower()
        for keyword, mapping in self._keyword_index:
            if keyword in rule_lower:
                return mapping
        return None


def get_techniques(signal_names: list[str]) -> list[str]:
    """Return deduplicated ATT&CK technique IDs for a list of fired signal names.

    Looks up each signal name against the MITRE mapping YAML using keyword
    matching.  Unknown signal names are silently skipped.  Duplicate technique
    IDs (e.g. two signals both mapping to T1078.004) are returned only once,
    in first-seen order.

    Args:
        signal_names: Engine signal names that fired (score > 0), e.g.
            ``["impossible_travel", "mfa_fatigue"]``.

    Returns:
        Deduplicated list of ATT&CK technique ID strings, e.g.
        ``["T1078.004", "T1621"]``.  Empty list if no matches or YAML missing.
    """
    mapper = _get_mapper()
    if mapper is None:
        return []
    seen: set[str] = set()
    result: list[str] = []
    for name in signal_names:
        match = mapper.lookup_by_rule_text(name)
        if match:
            tid: str = match.get("mitre_technique_id", "")
            if tid and tid not in seen:
                seen.add(tid)
                result.append(tid)
    return result


def get_technique_details(
    technique_ids: list[str], sources: dict[str, str] | None = None
) -> list[dict[str, str]]:
    """Return display detail objects for a list of ATT&CK technique IDs.

    Resolves each ID against the mapping YAML for its human-readable name
    and tactic.  IDs absent from the map are still returned (with empty
    name/tactic) so native log labels are never dropped from display.

    Args:
        technique_ids: Deduplicated ATT&CK technique IDs, in display order.
        sources: Optional map of technique ID → provenance label
            (``"signal"`` / ``"native"`` / ``"rule_text"``).  Missing IDs
            default to ``"signal"``.

    Returns:
        One ``{"id", "name", "tactic", "source"}`` dict per input ID.
    """
    mapper = _get_mapper()
    by_id: dict[str, dict[str, Any]] = {}
    if mapper is not None:
        for entry in mapper.mappings:
            by_id.setdefault(entry.get("mitre_technique_id", ""), entry)
    details: list[dict[str, str]] = []
    for tid in technique_ids:
        entry = by_id.get(tid)
        details.append(
            {
                "id": tid,
                "name": entry.get("mitre_technique_name", "") if entry else "",
                "tactic": entry.get("mitre_tactic", "") if entry else "",
                "source": (sources or {}).get(tid, "signal"),
            }
        )
    return details


def get_nist_phase(verdict: str) -> str:
    """Map a triage verdict string to a single NIST 800-61 phase label.

    ``high_risk`` maps to the Containment phase of NIST SP 800-61 Rev. 2.
    All other verdicts (``medium_risk``, ``low_risk``, or unknown) map to
    Detection & Analysis, reflecting that the incident is still being assessed.

    Args:
        verdict: Verdict string from the triage engine, e.g. ``"high_risk"``.

    Returns:
        A NIST 800-61 phase label string.  Never empty, never raises.
    """
    if verdict == "high_risk":
        return "Containment"
    return "Detection & Analysis"
