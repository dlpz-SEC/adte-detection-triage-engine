"""Tests for NIST CSF 2.0 correctness (Phase 2 of the MITRE/NIST plan).

Before this phase the technique YAML carried CSF 1.1-style IDs under a "CSF
2.0" label (15 of 42 pointed at DE.CM-4 / DE.CM-7, which CSF 2.0 does not
define), and every report received the same constant ``nist_phases`` list.

Covers:
  - adte.intel.nist_csf: the one table of CSF 2.0 IDs and official text
  - adte/data/mitre_technique_map.yaml: every nist_detect / nist_category pair
  - adte.llm.assist: derive_nist_phases, the LLM allowed list and filter
  - adte.llm.enrichment: no invented subcategory for an unmapped technique
  - the full /api/triage route: nist_phases now vary with the incident

Text in adte/intel/nist_csf.py was checked against NIST CSWP 29 (CSF 2.0,
February 2024), Appendix A, on 2026-10-01.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from adte.intel.nist_csf import CSF_SUBCATEGORIES, DE_AE, DE_CM, csf_subcategory_table
from adte.llm import enrichment
from adte.llm.assist import _SYSTEM_PROMPT, _parse_llm_response, derive_nist_phases
from adte.store.audit_log import init_db

_YAML_PATH = Path(__file__).resolve().parents[1] / "adte" / "data" / "mitre_technique_map.yaml"


def _yaml_entries() -> list[dict[str, Any]]:
    """Return the technique YAML's mapping entries."""
    return yaml.safe_load(_YAML_PATH.read_text(encoding="utf-8"))["mappings"]


def _output(
    *,
    verdict: str = "medium_risk",
    fired: tuple[str, ...] = (),
    present: tuple[str, ...] = (),
    threat_intel: dict[str, Any] | None = None,
    llm_enrichment: Any = None,
) -> dict[str, Any]:
    """Build a minimal engine output dict.

    Args:
        verdict: Engine verdict.
        fired: Signal names with a positive score.
        present: Signal names registered with a zero score.
        threat_intel: The ``evidence.threat_intel`` block.
        llm_enrichment: The ``llm_enrichment`` value.
    """
    rationale = [{"signal": s, "score": 10.0, "detail": "fired"} for s in fired]
    rationale += [{"signal": s, "score": 0.0, "detail": "quiet"} for s in present]
    return {
        "verdict": verdict,
        "rationale": rationale,
        "evidence": {"threat_intel": threat_intel or {}},
        "llm_enrichment": llm_enrichment,
    }


# ---------------------------------------------------------------------------
# The CSF table
# ---------------------------------------------------------------------------


class TestCsfTable:
    """adte.intel.nist_csf is the only place CSF IDs and text are written."""

    def test_ids_are_zero_padded_detect_subcategories(self) -> None:
        """CSF 2.0 IDs are zero-padded; nothing outside DE.CM / DE.AE is cited."""
        for sub_id in CSF_SUBCATEGORIES:
            assert re.fullmatch(r"DE\.(CM|AE)-\d{2}", sub_id), sub_id

    def test_continuous_monitoring_is_the_full_csf2_set(self) -> None:
        """All five DE.CM subcategories the CSF 2.0 core defines, and no others."""
        assert set(DE_CM) == {"DE.CM-01", "DE.CM-02", "DE.CM-03", "DE.CM-06", "DE.CM-09"}

    def test_adverse_event_analysis_is_what_adte_performs(self) -> None:
        """Analyse, correlate, enrich with threat intel, declare."""
        assert set(DE_AE) == {"DE.AE-02", "DE.AE-03", "DE.AE-07", "DE.AE-08"}

    def test_monitoring_text_follows_the_csf2_outcome_form(self) -> None:
        """Every DE.CM outcome in CSF 2.0 ends with the same clause."""
        for sub_id, text in DE_CM.items():
            assert text.endswith("monitored to find potentially adverse events"), sub_id

    def test_no_respond_subcategory(self) -> None:
        """ADTE is recommend-only; it never claims a RESPOND outcome."""
        assert not [s for s in CSF_SUBCATEGORIES if s.startswith("RS.")]

    def test_table_copy_is_fresh(self) -> None:
        """Mutating the served copy cannot change the source table."""
        table = csf_subcategory_table()
        table["DE.CM-01"] = "tampered"
        table.clear()
        assert csf_subcategory_table() == dict(CSF_SUBCATEGORIES)


# ---------------------------------------------------------------------------
# The technique YAML
# ---------------------------------------------------------------------------


class TestTechniqueYaml:
    """Every technique names the CSF 2.0 monitoring that would surface it."""

    def test_every_nist_detect_is_a_csf2_monitoring_subcategory(self) -> None:
        """No CSF 1.1 ID (DE.CM-4, DE.CM-7, ...) survives in any entry."""
        for entry in _yaml_entries():
            assert entry["nist_detect"] in DE_CM, entry["mitre_technique_id"]

    def test_nist_category_is_the_official_text(self) -> None:
        """The label is NIST's wording for that exact ID, not a paraphrase."""
        for entry in _yaml_entries():
            assert entry["nist_category"] == DE_CM[entry["nist_detect"]], (
                entry["mitre_technique_id"]
            )

    def test_repeated_technique_ids_agree(self) -> None:
        """Lookups take the FIRST entry, so a disagreeing duplicate is dead data."""
        first: dict[str, dict[str, Any]] = {}
        fields = ("mitre_tactic", "mitre_technique_name", "nist_detect", "nist_category")
        for entry in _yaml_entries():
            tid = entry["mitre_technique_id"]
            if tid in first:
                for field in fields:
                    assert entry[field] == first[tid][field], (tid, field)
            else:
                first[tid] = entry

    def test_known_duplicates_are_still_present(self) -> None:
        """Guards the test above from passing vacuously after a YAML cleanup."""
        ids = [e["mitre_technique_id"] for e in _yaml_entries()]
        assert ids.count("T1621") == 2
        assert ids.count("T1078.004") == 2

    def test_no_unpadded_ids_anywhere_in_the_file(self) -> None:
        """Comments included: the 1.1 numbering must not creep back."""
        text = _YAML_PATH.read_text(encoding="utf-8")
        assert not re.search(r"DE\.CM-\d(?!\d)", text)


# ---------------------------------------------------------------------------
# Derived nist_phases
# ---------------------------------------------------------------------------


class TestDeriveNistPhases:
    """Each ID is keyed on something the triage actually did."""

    def test_every_triage_is_analysed(self) -> None:
        """DE.AE-02 is the floor: even an empty result was analysed."""
        assert derive_nist_phases({}, []) == ["DE.AE-02"]

    def test_cluster_context_means_correlation(self) -> None:
        """DE.AE-03 only when the cluster_context signal is registered."""
        assert "DE.AE-03" in derive_nist_phases(_output(fired=("cluster_context",)), [])
        assert "DE.AE-03" not in derive_nist_phases(_output(fired=("impossible_travel",)), [])

    def test_threat_intel_evidence_means_intel_integrated(self) -> None:
        """DE.AE-07 when any threat-intel result was consulted, clean or not."""
        clean = {"203.0.113.9": {"is_malicious": False, "confidence": 0.1}}
        assert "DE.AE-07" in derive_nist_phases(_output(threat_intel=clean), [])
        assert "DE.AE-07" not in derive_nist_phases(_output(), [])

    def test_fired_ip_reputation_means_intel_integrated(self) -> None:
        """A fired ip_reputation implies intel ran even without an evidence block."""
        out = {"verdict": "medium_risk", "rationale": [
            {"signal": "ip_reputation", "score": 20.0, "detail": "1 malicious IP"},
        ]}
        assert "DE.AE-07" in derive_nist_phases(out, [])

    def test_quiet_ip_reputation_alone_is_not_intel(self) -> None:
        """A zero-score ip_reputation with no evidence ("No IPs") claims nothing."""
        assert "DE.AE-07" not in derive_nist_phases(_output(present=("ip_reputation",)), [])

    def test_file_reputation_means_intel_integrated(self) -> None:
        """A registered file_reputation signal is a VirusTotal verdict."""
        assert "DE.AE-07" in derive_nist_phases(_output(present=("file_reputation",)), [])

    def test_file_evidence_means_host_monitoring(self) -> None:
        """file_reputation exists only with file evidence, which FIM produced.

        Without this, a malware alert triaged on a path that skips
        llm_enrich (queue, CLI) claimed only identity monitoring.
        """
        phases = derive_nist_phases(_output(present=("file_reputation",)), [])
        assert phases == ["DE.CM-09", "DE.AE-02", "DE.AE-07"]

    def test_only_high_risk_declares_an_incident(self) -> None:
        """DE.AE-08 tracks the verdict, nothing else."""
        assert "DE.AE-08" in derive_nist_phases(_output(verdict="high_risk"), [])
        for verdict in ("medium_risk", "low_risk"):
            assert "DE.AE-08" not in derive_nist_phases(_output(verdict=verdict), [])

    def test_monitoring_comes_from_each_techniques_surface(self) -> None:
        """Identity, network and host techniques each add their own DE.CM."""
        phases = derive_nist_phases(_output(), ["T1621", "T1090.003", "T1204"])
        assert phases == ["DE.CM-01", "DE.CM-03", "DE.CM-09", "DE.AE-02"]

    def test_native_ids_from_llm_enrichment_count(self) -> None:
        """A Tor tag carried on the alert surfaces network monitoring."""
        out = _output(llm_enrichment={"technique_ids": ["T1090.003"]})
        assert derive_nist_phases(out, []) == ["DE.CM-01", "DE.AE-02"]

    def test_unmapped_technique_claims_nothing(self) -> None:
        """No map entry, no subcategory: never a guess."""
        assert derive_nist_phases(_output(), ["T9999"]) == ["DE.AE-02"]

    @pytest.mark.parametrize("enrich", [
        "not-a-dict",
        {"technique_ids": "T1090.003"},
        {"technique_ids": [None, 7, {"id": "T1090.003"}]},
        {},
    ])
    def test_malformed_enrichment_is_ignored(self, enrich: Any) -> None:
        """Odd llm_enrichment shapes contribute nothing and never raise."""
        assert derive_nist_phases(_output(llm_enrichment=enrich), []) == ["DE.AE-02"]

    def test_output_is_unique_ordered_and_known(self) -> None:
        """Deduplicated, DE.CM before DE.AE, every ID in the CSF table."""
        out = _output(
            verdict="high_risk",
            fired=("cluster_context", "ip_reputation"),
            present=("file_reputation",),
            threat_intel={"198.51.100.1": {"is_malicious": True}},
            llm_enrichment={"technique_ids": ["T1621", "T1078.004"]},
        )
        phases = derive_nist_phases(out, ["T1621", "T1071", "T1071"])
        assert phases == [
            "DE.CM-01", "DE.CM-03", "DE.CM-09",
            "DE.AE-02", "DE.AE-03", "DE.AE-07", "DE.AE-08",
        ]
        assert all(p in CSF_SUBCATEGORIES for p in phases)


# ---------------------------------------------------------------------------
# LLM path
# ---------------------------------------------------------------------------


class TestLlmPath:
    """The model is offered only real CSF 2.0 IDs, and held to them."""

    def test_prompt_offers_exactly_the_table(self) -> None:
        """Every ID ADTE cites is offered; no CSF 1.1 or RESPOND ID is."""
        for sub_id, text in CSF_SUBCATEGORIES.items():
            assert f"{sub_id}: {text}" in _SYSTEM_PROMPT
        assert not re.search(r"DE\.CM-\d(?!\d)|RS\.AN", _SYSTEM_PROMPT)

    def test_invented_and_legacy_ids_are_dropped(self) -> None:
        """A 1.1 ID, a RESPOND ID, junk and duplicates never reach the report."""
        raw = {
            "narrative": "n", "mitre_tactics": [], "mitre_techniques": [],
            "confidence_note": "c",
            "nist_phases": ["DE.CM-1", "DE.AE-02", "RS.AN-1", 7, "DE.AE-02", "DE.CM-03"],
        }
        parsed = _parse_llm_response(json.dumps(raw))
        assert parsed is not None
        assert parsed["nist_phases"] == ["DE.AE-02", "DE.CM-03"]

    def test_non_list_phases_become_empty(self) -> None:
        """A string where a list belongs is not iterated character by character."""
        raw = {
            "narrative": "n", "mitre_tactics": [], "mitre_techniques": [],
            "confidence_note": "c", "nist_phases": "DE.AE-02",
        }
        parsed = _parse_llm_response(json.dumps(raw))
        assert parsed is not None and parsed["nist_phases"] == []


# ---------------------------------------------------------------------------
# Enrichment fallback
# ---------------------------------------------------------------------------


def test_enrichment_does_not_invent_a_subcategory_for_an_unmapped_tag() -> None:
    """A native ID outside the map gets no CSF subcategory, not a guessed one."""
    incident = {"events": [{"technique_ids": ["T9999"]}]}
    result = enrichment.enrich_alert(incident)
    assert result is not None
    assert result["source"] == "native_log"
    assert result["nist_category"] == ""


def test_enrichment_mapped_tag_carries_its_csf2_subcategory() -> None:
    """A mapped native ID carries the YAML's CSF 2.0 ID."""
    incident = {"events": [{"technique_ids": ["T1090.003"]}]}
    result = enrichment.enrich_alert(incident)
    assert result is not None and result["nist_category"] == "DE.CM-01"


# ---------------------------------------------------------------------------
# Full route: the list is no longer a constant
# ---------------------------------------------------------------------------


@pytest.fixture()
def triage_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Flask test client with DB_PATH redirected to an isolated tmp database."""
    import adte.server as srv

    db_path = tmp_path / "test_nist_csf.db"
    monkeypatch.setattr(srv, "DB_PATH", db_path)
    init_db(db_path)
    srv.app.config["TESTING"] = True
    with srv.app.test_client() as client:
        yield client


def _route_phases(client, key: str) -> list[str]:
    """Triage one bundled example through /api/triage; return report.nist_phases."""
    examples = client.get("/api/examples").get_json()
    resp = client.post("/api/triage", json=examples[key])
    assert resp.status_code == 200
    return resp.get_json()["report"]["nist_phases"]


def test_account_takeover_example_phases(triage_client) -> None:
    """Identity + network monitoring, intel integrated, incident declared."""
    assert _route_phases(triage_client, "critical") == [
        "DE.CM-01", "DE.CM-03", "DE.AE-02", "DE.AE-07", "DE.AE-08",
    ]


def test_benign_vpn_example_phases(triage_client) -> None:
    """Only the login-hour signal fires (5 points): no incident is declared.

    login_hour_anomaly maps to T1078.004, seen by identity monitoring.
    """
    assert _route_phases(triage_client, "low_risk") == ["DE.CM-03", "DE.AE-02", "DE.AE-07"]


def test_examples_no_longer_share_one_constant_list(triage_client) -> None:
    """The defect this phase fixes: every report used to get the same list."""
    examples = triage_client.get("/api/examples").get_json()
    lists = set()
    for key in ("critical", "low_risk"):
        resp = triage_client.post("/api/triage", json=examples[key])
        lists.add(tuple(resp.get_json()["report"]["nist_phases"]))
    assert len(lists) == 2
