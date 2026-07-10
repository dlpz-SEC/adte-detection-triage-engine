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


class TestBatchWrappers:
    """Batch wrappers: single alert unwrapped, multi-alert rejected clearly."""

    def test_alerts_wrapper_single_unwrapped(self, triage_client, wazuh_hits) -> None:
        """{"alerts": [one hit]} is unwrapped and triaged (200)."""
        resp = triage_client.post("/api/triage", json={"alerts": [wazuh_hits[0]]})
        assert resp.status_code == 200, resp.get_data(as_text=True)
        assert "verdict" in resp.get_json()

    def test_alerts_wrapper_multiple_rejected_with_count(
        self, triage_client, wazuh_hits
    ) -> None:
        """A multi-alert {"alerts": [...]} doc gets a 422 naming the count."""
        resp = triage_client.post("/api/triage", json={"alerts": wazuh_hits})
        assert resp.status_code == 422
        err = resp.get_json()["error"]
        assert f"{len(wazuh_hits)} alerts" in err
        assert "one alert at a time" in err

    def test_search_response_single_hit_unwrapped(self, triage_client, wazuh_hits) -> None:
        """A full _search response holding one hit is unwrapped and triaged."""
        body = {"took": 3, "hits": {"total": {"value": 1}, "hits": [wazuh_hits[0]]}}
        resp = triage_client.post("/api/triage", json=body)
        assert resp.status_code == 200, resp.get_data(as_text=True)

    def test_search_response_multiple_hits_rejected(self, triage_client) -> None:
        """The raw wazuh_alerts.json search response (4 hits) is a counted 422."""
        data = json.loads((FIXTURES_DIR / "wazuh_alerts.json").read_text(encoding="utf-8"))
        resp = triage_client.post("/api/triage", json=data)
        assert resp.status_code == 422
        assert "4 alerts" in resp.get_json()["error"]

    def test_bare_array_single_unwrapped(self, triage_client, wazuh_hits) -> None:
        """A bare JSON array with one hit is unwrapped and triaged (200)."""
        resp = triage_client.post("/api/triage", json=[wazuh_hits[0]])
        assert resp.status_code == 200, resp.get_data(as_text=True)

    def test_bare_array_multiple_rejected(self, triage_client, wazuh_hits) -> None:
        """A bare JSON array with several hits is a counted 422."""
        resp = triage_client.post("/api/triage", json=wazuh_hits)
        assert resp.status_code == 422
        assert f"{len(wazuh_hits)} alerts" in resp.get_json()["error"]


class TestHardening:
    """Adversarial shapes must return clean 422s (or route correctly), never 500."""

    def test_modest_wrapper_nesting_unwrapped(self, triage_client, wazuh_hits) -> None:
        """A two-level nest ({"alerts": [{"alerts": [hit]}]}) still unwraps (200)."""
        body = {"alerts": [{"alerts": [wazuh_hits[0]]}]}
        resp = triage_client.post("/api/triage", json=body)
        assert resp.status_code == 200, resp.get_data(as_text=True)

    def test_deep_wrapper_nesting_422_not_500(self, triage_client, wazuh_hits) -> None:
        """A deeply nested wrapper chain is rejected 422, not a RecursionError 500."""
        body: dict[str, Any] = wazuh_hits[0]
        for _ in range(50):
            body = {"alerts": [body]}
        resp = triage_client.post("/api/triage", json=body)
        assert resp.status_code == 422

    def test_sentinel_malformed_alert_events_422_not_500(self, triage_client) -> None:
        """Sentinel-shaped doc with wrong-typed nested events is a clean 422."""
        body = {
            "incident_id": "inc-1",
            "title": "Suspicious sign-in",
            "created_time": "2026-07-10T12:00:00Z",
            "alerts": [{"events": "boom"}],
        }
        resp = triage_client.post("/api/triage", json=body)
        assert resp.status_code == 422

    def test_wazuh_nonstring_timestamp_422_not_500(self, triage_client) -> None:
        """Wazuh-shaped doc with an integer @timestamp is a clean 422."""
        resp = triage_client.post(
            "/api/triage", json={"rule": {"level": 5}, "@timestamp": 123}
        )
        assert resp.status_code == 422

    def test_canonical_with_stray_title_keeps_user(
        self, triage_client, incident_false_positive: NormalizedIncident
    ) -> None:
        """A canonical payload with an extra `title` and no `events` stays canonical.

        Regression: this shape must not be misrouted to the Sentinel path,
        which would silently drop the supplied `user`.
        """
        payload = incident_false_positive.model_dump(mode="json")
        del payload["events"]
        payload["title"] = "stray display title"
        resp = triage_client.post("/api/triage", json=payload)
        assert resp.status_code == 200, resp.get_data(as_text=True)
        assert resp.get_json()["report"]["user"] == incident_false_positive.user


class TestSentinelInputAccepted:
    """Raw Sentinel incident JSON (the examples/*.json shape) is accepted."""

    def test_raw_sentinel_incident_accepted(
        self, triage_client, raw_false_positive: dict[str, Any]
    ) -> None:
        """A raw SentinelIncident document triages successfully (200)."""
        # Sentinel shape: incident_id + title + alerts — must NOT be treated
        # as a batch wrapper even though it carries an `alerts` list.
        assert "title" in raw_false_positive and "alerts" in raw_false_positive
        resp = triage_client.post("/api/triage", json=raw_false_positive)
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
