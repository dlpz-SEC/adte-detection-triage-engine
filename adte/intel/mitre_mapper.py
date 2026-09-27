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

# Display field → the YAML key it is read from.  The single projection used
# by both get_technique_details and get_technique_map; rule_keywords is
# matcher-internal and deliberately never exposed.
_DISPLAY_FIELDS: tuple[tuple[str, str], ...] = (
    ("name", "mitre_technique_name"),
    ("tactic", "mitre_tactic"),
    ("nist_csf", "nist_detect"),
    ("nist_csf_name", "nist_category"),
)


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
        # Technique ID → display fields, built once so get_technique_details
        # and get_technique_map read the same table and can never disagree.
        # The YAML repeats some IDs under different keyword sets (e.g. T1621);
        # the FIRST entry for an ID wins.  Entries with no ID are skipped.
        self._id_index: dict[str, dict[str, str]] = {}
        for mapping in mappings:
            tid = str(mapping.get("mitre_technique_id") or "")
            if tid and tid not in self._id_index:
                self._id_index[tid] = {
                    "id": tid,
                    **{
                        field: str(mapping.get(key) or "")
                        for field, key in _DISPLAY_FIELDS
                    },
                }

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

    Resolves each ID against the mapping YAML for its human-readable name,
    tactic, and NIST CSF subcategory.  IDs absent from the map are still
    returned (with every display field empty) so native log labels are never
    dropped from display.  A repeated YAML ID resolves to its FIRST entry —
    the same table :func:`get_technique_map` serves.

    Args:
        technique_ids: Deduplicated ATT&CK technique IDs, in display order.
        sources: Optional map of technique ID → provenance label
            (``"signal"`` / ``"native"`` / ``"rule_text"``).  Missing IDs
            default to ``"signal"``.

    Returns:
        One ``{"id", "name", "tactic", "source", "nist_csf", "nist_csf_name"}``
        dict per input ID, in input order.  ``nist_csf`` is the YAML's
        ``nist_detect`` subcategory ID and ``nist_csf_name`` its
        ``nist_category`` label.  Empty strings for an unmapped ID or a
        missing YAML.
    """
    mapper = _get_mapper()
    index = mapper._id_index if mapper is not None else {}
    details: list[dict[str, str]] = []
    for tid in technique_ids:
        fields = index.get(tid, {})
        details.append(
            {
                "id": tid,
                "name": fields.get("name", ""),
                "tactic": fields.get("tactic", ""),
                "source": (sources or {}).get(tid, "signal"),
                "nist_csf": fields.get("nist_csf", ""),
                "nist_csf_name": fields.get("nist_csf_name", ""),
            }
        )
    return details


def get_technique_map() -> dict[str, dict[str, str]]:
    """Return every mapped ATT&CK technique keyed by ID, for reference display.

    Serves the SPA's technique cards so they resolve from the same table as
    :func:`get_technique_details`, instead of a client-side copy that drifts.
    A repeated YAML ID resolves to its FIRST entry; entries with no ID are
    skipped; ``rule_keywords`` is never exposed.

    Returns:
        ``{technique_id: {"id", "name", "tactic", "nist_csf", "nist_csf_name"}}``
        with one entry per distinct ID, in YAML first-seen order.  Fresh
        copies, so mutating the result cannot corrupt later lookups.  Empty
        dict if the mapping YAML is missing.
    """
    mapper = _get_mapper()
    if mapper is None:
        return {}
    return {tid: dict(fields) for tid, fields in mapper._id_index.items()}


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
