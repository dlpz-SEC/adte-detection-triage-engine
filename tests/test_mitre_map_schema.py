"""Schema and precedence tests for adte/data/mitre_technique_map.yaml.

Guards the A3 expansion: every entry is structurally complete, technique IDs
are well-formed ATT&CK IDs, keywords are lowercase (the matcher lowercases
input only), and first-match precedence keeps sub-techniques ahead of their
generic parents.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from adte.intel.mitre_mapper import MitreMapper

_YAML_PATH = (
    Path(__file__).resolve().parent.parent / "adte" / "data" / "mitre_technique_map.yaml"
)
_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_REQUIRED_KEYS = {
    "rule_keywords",
    "mitre_tactic",
    "mitre_technique_id",
    "mitre_technique_name",
    "nist_detect",
    "nist_category",
}
_SIGNAL_NAMES = [
    "impossible_travel",
    "mfa_fatigue",
    "ip_reputation",
    "device_novelty",
    "login_hour_anomaly",
]


def _load_mappings() -> list[dict[str, Any]]:
    """Load the raw mappings list from the YAML file."""
    data = yaml.safe_load(_YAML_PATH.read_text(encoding="utf-8"))
    return data["mappings"]


class TestMapSchema:
    """Structural validation of every mapping entry."""

    def test_all_entries_have_required_keys(self) -> None:
        """Every entry carries the full required key set."""
        for i, entry in enumerate(_load_mappings()):
            missing = _REQUIRED_KEYS - set(entry)
            assert not missing, f"entry {i} missing keys: {missing}"

    def test_technique_ids_are_wellformed(self) -> None:
        """IDs match T\\d{4} with an optional .\\d{3} sub-technique suffix."""
        for entry in _load_mappings():
            tid = entry["mitre_technique_id"]
            assert _ID_RE.match(tid), f"malformed technique id: {tid!r}"

    def test_keywords_are_nonempty_lowercase_strings(self) -> None:
        """Keywords are non-empty and lowercase (matcher lowercases input only)."""
        for entry in _load_mappings():
            keywords = entry["rule_keywords"]
            assert isinstance(keywords, list) and keywords
            for kw in keywords:
                assert isinstance(kw, str) and kw.strip(), f"bad keyword {kw!r}"
                assert kw == kw.lower(), f"keyword not lowercase: {kw!r}"

    def test_no_keyword_shadows_engine_signal_names(self) -> None:
        """No keyword outside a signal's own entry may substring-match a signal.

        lookup_by_rule_text is first-match substring — a stray keyword like
        "travel" would hijack the impossible_travel signal mapping.
        """
        for signal in _SIGNAL_NAMES:
            for entry in _load_mappings():
                for kw in entry["rule_keywords"]:
                    if kw in signal:
                        assert kw == signal, (
                            f"keyword {kw!r} in entry {entry['mitre_technique_id']} "
                            f"shadows engine signal {signal!r}"
                        )


class TestLookupPrecedence:
    """Sub-technique entries must win over generic parents (first match)."""

    def setup_method(self) -> None:
        """Load a fresh mapper against the real YAML."""
        self.mapper = MitreMapper.load()

    def test_password_spray_maps_to_subtechnique(self) -> None:
        """Password-spray rule text hits T1110.003, not generic T1110."""
        match = self.mapper.lookup_by_rule_text("sshd: password spray attempt detected")
        assert match is not None
        assert match["mitre_technique_id"] == "T1110.003"

    def test_generic_brute_force_still_reachable(self) -> None:
        """Plain brute-force rule text still maps to generic T1110."""
        match = self.mapper.lookup_by_rule_text("sshd: brute force trying to get access")
        assert match is not None
        assert match["mitre_technique_id"] == "T1110"

    def test_log_clearing_maps_to_indicator_removal(self) -> None:
        """Log-clearing text maps to T1070 (moved off the misnamed T1562)."""
        match = self.mapper.lookup_by_rule_text("Audit log cleared on host web-01")
        assert match is not None
        assert match["mitre_technique_id"] == "T1070"

    def test_t1562_is_named_impair_defenses(self) -> None:
        """The T1562 entry carries its correct ATT&CK name."""
        for entry in _load_mappings():
            if entry["mitre_technique_id"] == "T1562":
                assert entry["mitre_technique_name"] == "Impair Defenses"
                break
        else:  # pragma: no cover - guarded by schema completeness
            raise AssertionError("no T1562 entry found")

    def test_wazuh_rootcheck_vocabulary_covered(self) -> None:
        """Classic Wazuh rootcheck text maps to Rootkit (T1014)."""
        match = self.mapper.lookup_by_rule_text("Rootkit detected: hidden process found")
        assert match is not None
        assert match["mitre_technique_id"] == "T1014"
