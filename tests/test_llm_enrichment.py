"""Tests for adte.llm.enrichment — the wired advisory llm_enrichment path.

Covers the three resolution tiers (native IDs → keyword lookup → None) and
proves the advisory-only contract: wiring llm_enrich() into the pipeline
changes nothing about verdict, risk_score, or confidence.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from adte.adapters.wazuh import WazuhAdapter
from adte.engine import TriageEngine
from adte.intel.sigma_fp_registry import FPRegistry
from adte.llm.enrichment import enrich_alert
from adte.models import NormalizedIncident
from adte.store.audit_log import init_db
from adte.store.user_history import get_user_profile


def _wazuh_alert(
    description: str = "SSH brute force", mitre_ids: list[str] | None = None
) -> dict[str, Any]:
    """Build a raw Wazuh alert with the given rule description and MITRE IDs."""
    rule: dict[str, Any] = {"level": 10, "description": description}
    if mitre_ids is not None:
        rule["mitre"] = {"id": mitre_ids}
    return {
        "id": "alert-enrich",
        "@timestamp": "2024-01-15T10:30:00.000Z",
        "rule": rule,
        "agent": {"id": "001", "name": "host-01", "ip": "10.0.0.1"},
        "data": {"srcip": "198.51.100.23", "dstuser": "root-account"},
    }


def _dump(description: str = "SSH brute force", mitre_ids: list[str] | None = None) -> dict[str, Any]:
    """Normalize a Wazuh alert and dump it in the pipeline's JSON shape."""
    incident = WazuhAdapter.normalize_alert(_wazuh_alert(description, mitre_ids))
    return incident.model_dump(mode="json")


class TestKeywordPath:
    """Tier 2: rule text keyword lookup against the YAML map."""

    def test_matching_rule_text_returns_real_mapping(self) -> None:
        """Wazuh rule text with a known keyword maps to a real technique."""
        result = enrich_alert(_dump("sshd: brute force trying to get access"))
        assert result is not None
        assert result["source"] == "deterministic_mapping"
        assert result["mitre_technique_id"] == "T1110"
        assert result["confidence"] == 1.0

    def test_subtechnique_precision(self) -> None:
        """Password-spray text hits the T1110.003 sub-technique entry."""
        result = enrich_alert(_dump("Multiple failures: password spray suspected"))
        assert result is not None
        assert result["mitre_technique_id"] == "T1110.003"

    def test_multi_event_rule_text_aggregated(self) -> None:
        """Rule text is joined across events (distinct, in order)."""
        payload = _dump("normal app usage")
        payload["events"].append(dict(payload["events"][0]))
        payload["events"][1]["app_display_name"] = "ransomware behavior detected"
        result = enrich_alert(payload)
        assert result is not None
        assert result["mitre_technique_id"] == "T1486"

    def test_legacy_rule_description_still_honoured(self) -> None:
        """Pre-OCSF flat dicts with rule_description keep working."""
        result = enrich_alert({"rule_description": "brute force attempt"})
        assert result is not None
        assert result["mitre_technique_id"] == "T1110"


class TestNativePath:
    """Tier 1: native log MITRE IDs are authoritative."""

    def test_native_ids_produce_native_log_source(self) -> None:
        """Events carrying technique_ids yield a native_log enrichment."""
        result = enrich_alert(_dump("some unmapped text", mitre_ids=["T1110"]))
        assert result is not None
        assert result["source"] == "native_log"
        assert result["mitre_technique_id"] == "T1110"
        assert result["technique_ids"] == ["T1110"]
        assert result["mitre_tactic"] == "Credential Access"

    def test_native_ids_win_over_keyword_match(self) -> None:
        """Native IDs take precedence even when rule text would match."""
        result = enrich_alert(_dump("sshd: brute force attempt", mitre_ids=["T1486"]))
        assert result is not None
        assert result["source"] == "native_log"
        assert result["mitre_technique_id"] == "T1486"

    def test_unmapped_native_id_still_reported(self) -> None:
        """A native ID absent from the YAML map is reported with Unknown tactic."""
        result = enrich_alert(_dump("text", mitre_ids=["T9999"]))
        assert result is not None
        assert result["source"] == "native_log"
        assert result["mitre_technique_id"] == "T9999"
        assert result["mitre_tactic"] == "Unknown"


class TestNoMatchPath:
    """Tier 3: no native IDs + no keyword match → None (no T0000 blob)."""

    def test_unmatched_rule_text_returns_none(self) -> None:
        """App-name-style text (azure_ad case) yields None, not a mock blob."""
        assert enrich_alert(_dump("Microsoft 365")) is None

    def test_empty_incident_returns_none(self) -> None:
        """An incident with no events and no legacy key yields None."""
        assert enrich_alert({"events": []}) is None


class TestAdvisoryOnlyContract:
    """Wiring llm_enrich() must not move verdict/risk_score/confidence."""

    def test_scoring_identical_with_and_without_llm_enrich(
        self, incident_true_positive: NormalizedIncident
    ) -> None:
        """The scoring triple is byte-identical with and without llm_enrich()."""
        profile = get_user_profile(incident_true_positive.user)
        registry = FPRegistry.load()

        without = (
            TriageEngine(incident_true_positive, profile, registry)
            .enrich().score().decide().to_output(use_llm=False)
        )
        with_enrich = (
            TriageEngine(incident_true_positive, profile, registry)
            .enrich().score().decide().llm_enrich().to_output(use_llm=False)
        )
        for key in ("verdict", "risk_score", "confidence"):
            assert without[key] == with_enrich[key]


@pytest.fixture()
def triage_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Flask test client with DB_PATH redirected to an isolated tmp database."""
    db_path = tmp_path / "test_llm_enrichment.db"

    import adte.server as srv

    monkeypatch.setattr(srv, "DB_PATH", db_path)
    init_db(db_path)

    srv.app.config["TESTING"] = True
    with srv.app.test_client() as client:
        yield client


class TestRouteWiring:
    """POST /api/triage now populates llm_enrichment."""

    def test_wazuh_incident_gets_enrichment(self, triage_client) -> None:
        """A Wazuh-shaped incident with matching rule text → non-null enrichment."""
        payload = _dump("sshd: brute force trying to get access")
        resp = triage_client.post("/api/triage", json=payload)
        assert resp.status_code == 200
        enrichment = resp.get_json()["llm_enrichment"]
        assert enrichment is not None
        assert enrichment["mitre_technique_id"] == "T1110"

    def test_unmatched_incident_enrichment_stays_null(
        self, triage_client, incident_false_positive: NormalizedIncident
    ) -> None:
        """The benign azure_ad example (app-name text) keeps llm_enrichment null."""
        payload = incident_false_positive.model_dump(mode="json")
        resp = triage_client.post("/api/triage", json=payload)
        assert resp.status_code == 200
        assert resp.get_json()["llm_enrichment"] is None
