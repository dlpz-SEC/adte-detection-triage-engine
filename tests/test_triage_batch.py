"""Tests for POST /api/triage/batch — bulk triage of an OpenSearch export.

An analyst pastes a whole indexer export (a bare JSON array of hits, an
``{"alerts": [...]}`` document, or a full ``_search`` response) and every
alert is triaged with per-alert error isolation.  Success entries carry the
full single-triage output dict so the frontend reuses its result rendering.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from adte.store.audit_log import init_db, query_verdicts

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture()
def wazuh_hits() -> list[dict[str, Any]]:
    """The OpenSearch hits from the wazuh_alerts.json fixture (real alert shape)."""
    data = json.loads((FIXTURES_DIR / "wazuh_alerts.json").read_text(encoding="utf-8"))
    return data["hits"]["hits"]


@pytest.fixture()
def batch_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Flask test client with DB_PATH redirected to an isolated tmp database."""
    db_path = tmp_path / "test_triage_batch.db"

    import adte.server as srv

    monkeypatch.setattr(srv, "DB_PATH", db_path)
    init_db(db_path)

    srv.app.config["TESTING"] = True
    with srv.app.test_client() as client:
        yield client


_OUTPUT_FIELDS = (
    "verdict",
    "risk_score",
    "rationale",
    "report",
    "mitre_techniques",
    "mitre_details",
    "nist_phase",
)


class TestBatchHappyPath:
    """Well-formed batches triage every element."""

    def test_bare_array_all_triaged(self, batch_client, wazuh_hits) -> None:
        """A bare array of hits returns one full success entry per hit."""
        resp = batch_client.post("/api/triage/batch", json=wazuh_hits)
        assert resp.status_code == 200, resp.get_data(as_text=True)
        body = resp.get_json()
        assert body["count"] == len(wazuh_hits)
        assert body["succeeded"] == len(wazuh_hits)
        assert body["failed"] == 0
        for entry in body["results"]:
            assert entry["ok"] is True
            for field in _OUTPUT_FIELDS:
                assert field in entry, f"missing {field}"

    def test_alerts_wrapper_accepted(self, batch_client, wazuh_hits) -> None:
        """{"alerts": [...]} triages every element."""
        resp = batch_client.post("/api/triage/batch", json={"alerts": wazuh_hits})
        assert resp.status_code == 200
        assert resp.get_json()["succeeded"] == len(wazuh_hits)

    def test_search_response_accepted(self, batch_client) -> None:
        """The raw wazuh_alerts.json _search response triages verbatim."""
        data = json.loads(
            (FIXTURES_DIR / "wazuh_alerts.json").read_text(encoding="utf-8")
        )
        resp = batch_client.post("/api/triage/batch", json=data)
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["count"] == len(data["hits"]["hits"])
        assert body["failed"] == 0

    def test_order_preserved(self, batch_client, wazuh_hits) -> None:
        """results[k].index == k and incident ids match input order."""
        resp = batch_client.post("/api/triage/batch", json=wazuh_hits)
        body = resp.get_json()
        for k, entry in enumerate(body["results"]):
            assert entry["index"] == k
            # Inner _source.id wins when present; else the envelope _id.
            expected = wazuh_hits[k]["_source"].get("id") or wazuh_hits[k]["_id"]
            assert entry["report"]["incident_id"] == expected

    def test_single_element_batch_ok(self, batch_client, wazuh_hits) -> None:
        """A one-element array is a valid (trivial) batch."""
        resp = batch_client.post("/api/triage/batch", json=[wazuh_hits[0]])
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["count"] == 1 and body["succeeded"] == 1

    def test_native_mitre_union_applied_per_entry(
        self, batch_client, wazuh_hits
    ) -> None:
        """Each entry carries its own hit's rule.mitre.id (finalise runs per alert)."""
        resp = batch_client.post("/api/triage/batch", json=wazuh_hits)
        results = resp.get_json()["results"]
        for k, hit in enumerate(wazuh_hits):
            native = (hit["_source"]["rule"].get("mitre") or {}).get("id", [])
            for tid in native:
                assert tid in results[k]["mitre_techniques"], (
                    f"entry {k} missing native {tid}"
                )

    def test_use_llm_param_ignored(self, batch_client, wazuh_hits) -> None:
        """?use_llm=true is ignored — batch stays deterministic (still 200)."""
        resp = batch_client.post(
            "/api/triage/batch?use_llm=true", json=[wazuh_hits[0]]
        )
        assert resp.status_code == 200
        assert resp.get_json()["succeeded"] == 1


class TestBatchErrorIsolation:
    """One bad element must not sink the batch."""

    def test_mixed_good_and_bad_elements(self, batch_client, wazuh_hits) -> None:
        """Garbage in the middle yields an error entry; neighbours triage."""
        payload = [wazuh_hits[0], {"garbage": True}, wazuh_hits[1]]
        resp = batch_client.post("/api/triage/batch", json=payload)
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["count"] == 3
        assert body["succeeded"] == 2
        assert body["failed"] == 1
        bad = body["results"][1]
        assert bad["ok"] is False and bad["index"] == 1
        assert "error" in bad
        assert body["results"][0]["ok"] is True
        assert body["results"][2]["ok"] is True

    def test_audit_rows_written_for_successes_only(
        self, batch_client, wazuh_hits, tmp_path: Path
    ) -> None:
        """log_verdict fires once per SUCCESS, not per element."""
        import adte.server as srv

        before = len(query_verdicts(srv.DB_PATH, limit=500))
        payload = [wazuh_hits[0], {"garbage": True}, wazuh_hits[1]]
        batch_client.post("/api/triage/batch", json=payload)
        after = len(query_verdicts(srv.DB_PATH, limit=500))
        assert after - before == 2


class TestBatchValidation:
    """Malformed batch envelopes get clean 4xx responses."""

    def test_empty_array_422(self, batch_client) -> None:
        """[] is rejected with an explanatory 422."""
        resp = batch_client.post("/api/triage/batch", json=[])
        assert resp.status_code == 422
        assert "no alerts" in resp.get_json()["error"].lower()

    def test_empty_alerts_wrapper_422(self, batch_client) -> None:
        """{"alerts": []} is rejected with an explanatory 422."""
        resp = batch_client.post("/api/triage/batch", json={"alerts": []})
        assert resp.status_code == 422

    def test_oversize_batch_422_names_cap(self, batch_client, wazuh_hits) -> None:
        """26 alerts exceeds the cap and the error names the maximum."""
        import adte.server as srv

        payload = [wazuh_hits[0]] * (srv._BATCH_MAX_ALERTS + 1)
        resp = batch_client.post("/api/triage/batch", json=payload)
        assert resp.status_code == 422
        err = resp.get_json()["error"]
        assert f"max {srv._BATCH_MAX_ALERTS}" in err

    def test_non_json_content_type_415(self, batch_client) -> None:
        """A non-JSON body is a 415, mirroring /api/triage."""
        resp = batch_client.post(
            "/api/triage/batch", data="not json", content_type="text/plain"
        )
        assert resp.status_code == 415

    def test_malformed_json_400(self, batch_client) -> None:
        """Unparseable JSON is a 400, mirroring /api/triage."""
        resp = batch_client.post(
            "/api/triage/batch", data="{broken", content_type="application/json"
        )
        assert resp.status_code == 400

    def test_scalar_body_422(self, batch_client) -> None:
        """A bare JSON scalar is a 422."""
        resp = batch_client.post("/api/triage/batch", json=42)
        assert resp.status_code == 422

    def test_single_dict_treated_as_one_element_batch(
        self, batch_client, wazuh_hits
    ) -> None:
        """A plain single hit posted to /batch still works (one-element batch)."""
        resp = batch_client.post("/api/triage/batch", json=wazuh_hits[0])
        assert resp.status_code == 200
        assert resp.get_json()["count"] == 1


class TestSingleRoutePointsAtBatch:
    """/api/triage's multi-alert 422 now advertises the batch endpoint."""

    def test_batch_422_mentions_batch_endpoint(self, batch_client, wazuh_hits) -> None:
        """The single-route rejection tells the caller where batches go."""
        resp = batch_client.post("/api/triage", json=wazuh_hits)
        assert resp.status_code == 422
        assert "/api/triage/batch" in resp.get_json()["error"]
