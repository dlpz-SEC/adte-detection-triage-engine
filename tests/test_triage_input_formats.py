"""Tests for /api/triage input-format tolerance.

The triage route must accept BOTH ADTE's canonical ``NormalizedIncident``
schema (what ``/api/examples`` emits and Quick Load posts) AND a raw Wazuh /
OpenSearch alert — the most common SIEM alert-export shape.  Regression guard
for the "Invalid incident schema — check required fields" 422 that a pasted
Wazuh alert used to trigger because the route validated the body directly
against ``NormalizedIncident`` with no adapter step.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from adte.models import NormalizedIncident
from adte.store.audit_log import init_db

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture()
def wazuh_hits() -> list[dict[str, Any]]:
    """The OpenSearch hits from the wazuh_alerts.json fixture (real alert shape)."""
    data = json.loads((FIXTURES_DIR / "wazuh_alerts.json").read_text(encoding="utf-8"))
    return data["hits"]["hits"]


@pytest.fixture()
def triage_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Flask test client with DB_PATH redirected to an isolated tmp database."""
    db_path = tmp_path / "test_triage_input_formats.db"

    import adte.server as srv

    monkeypatch.setattr(srv, "DB_PATH", db_path)
    init_db(db_path)

    srv.app.config["TESTING"] = True
    with srv.app.test_client() as client:
        yield client


class TestWazuhInputAccepted:
    """POST /api/triage accepts raw Wazuh alerts, not only NormalizedIncident."""

    def test_opensearch_hit_envelope_accepted(self, triage_client, wazuh_hits) -> None:
        """A full OpenSearch hit ({_id, _source}) triages successfully (200)."""
        hit = wazuh_hits[0]  # SSH brute force, level 10, rule.mitre.id == ["T1110"]
        resp = triage_client.post("/api/triage", json=hit)
        assert resp.status_code == 200, resp.get_data(as_text=True)
        body = resp.get_json()
        assert "verdict" in body
        assert "risk_score" in body

    def test_native_mitre_from_wazuh_surfaces(self, triage_client, wazuh_hits) -> None:
        """rule.mitre.id on the Wazuh alert appears in the output techniques."""
        hit = wazuh_hits[0]  # rule.mitre.id == ["T1110"]
        resp = triage_client.post("/api/triage", json=hit)
        assert resp.status_code == 200
        assert "T1110" in resp.get_json()["mitre_techniques"]

    def test_bare_source_document_accepted(self, triage_client, wazuh_hits) -> None:
        """A bare Wazuh _source doc (top-level `rule`, no envelope) triages (200)."""
        source = wazuh_hits[0]["_source"]
        assert "rule" in source and "_source" not in source
        resp = triage_client.post("/api/triage", json=source)
        assert resp.status_code == 200, resp.get_data(as_text=True)
        assert "verdict" in resp.get_json()


class TestBackwardCompatibility:
    """The canonical NormalizedIncident path must keep working unchanged."""

    def test_normalized_incident_still_accepted(
        self, triage_client, incident_false_positive: NormalizedIncident
    ) -> None:
        """A NormalizedIncident (as Quick Load posts) still triages (200)."""
        payload = incident_false_positive.model_dump(mode="json")
        resp = triage_client.post("/api/triage", json=payload)
        assert resp.status_code == 200, resp.get_data(as_text=True)
        assert "verdict" in resp.get_json()

    def test_top_level_severity_still_rejected(
        self, triage_client, incident_false_positive: NormalizedIncident
    ) -> None:
        """A NormalizedIncident carrying top-level severity is still rejected (422)."""
        payload = incident_false_positive.model_dump(mode="json")
        payload["severity"] = "high"
        resp = triage_client.post("/api/triage", json=payload)
        assert resp.status_code == 422


class TestMalformedInput:
    """Malformed alerts return a clean 422, never a 500."""

    def test_malformed_wazuh_timestamp_422(self, triage_client) -> None:
        """A Wazuh-shaped alert with a non-ISO timestamp is a clean 422."""
        bad = {"rule": {"level": 5, "description": "x"}, "@timestamp": "not-a-timestamp"}
        resp = triage_client.post("/api/triage", json=bad)
        assert resp.status_code == 422

    def test_non_object_body_422(self, triage_client) -> None:
        """A non-object JSON body (list) is rejected with 422, not a 500."""
        resp = triage_client.post("/api/triage", json=[1, 2, 3])
        assert resp.status_code == 422

    def test_unrecognised_object_422(self, triage_client) -> None:
        """An object matching no known shape (no rule/_source/events) is 422."""
        resp = triage_client.post("/api/triage", json={"foo": "bar"})
        assert resp.status_code == 422
