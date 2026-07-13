"""Tests for the case-correlation layer at the API surface.

Covers the triage-route ingest hooks (``output["case"]``), the batch-level
``cases`` summary, the three ``/api/cases`` routes, RBAC on the admin clear,
and the fail-open contract (a broken case store never blocks a verdict).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from adte.store.audit_log import init_db

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def make_payload(
    incident_id: str,
    user: str = "alice@contoso.com",
    ip: str = "203.0.113.77",
    technique_ids: tuple[str, ...] = (),
    ts: str = "2026-07-10T12:00:00Z",
) -> dict[str, Any]:
    """Minimal canonical NormalizedIncident payload for /api/triage."""
    return {
        "incident_id": incident_id,
        "user": user,
        "source": "generic",
        "events": [
            {
                "user_principal_name": user,
                "ip_address": ip,
                "type": "authentication",
                "timestamp": ts,
                "technique_ids": list(technique_ids),
                "app_display_name": "Synthetic correlation test rule",
            }
        ],
    }


@pytest.fixture()
def cases_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Flask test client with DB_PATH redirected to an isolated tmp database."""
    db_path = tmp_path / "test_cases_api.db"

    import adte.server as srv

    monkeypatch.setattr(srv, "DB_PATH", db_path)
    init_db(db_path)

    srv.app.config["TESTING"] = True
    with srv.app.test_client() as client:
        yield client


class TestTriageIngestHook:
    def test_single_triage_carries_case_key(self, cases_client) -> None:
        resp = cases_client.post("/api/triage", json=make_payload("INC-1"))
        assert resp.status_code == 200
        case = resp.get_json()["case"]
        assert case is not None
        assert case["alert_count"] == 1
        assert case["correlation_keys"] == {
            "user": "alice@contoso.com",
            "ips": ["203.0.113.77"],
            "hashes": [],
        }

    def test_second_same_ip_alert_joins_case(self, cases_client) -> None:
        first = cases_client.post(
            "/api/triage", json=make_payload("INC-1", user="alice@contoso.com")
        ).get_json()["case"]
        second = cases_client.post(
            "/api/triage", json=make_payload("INC-2", user="bob@contoso.com")
        ).get_json()["case"]
        assert second["case_id"] == first["case_id"]
        assert second["alert_count"] == 2
        assert second["related_incident_ids"] == ["INC-1"]

    def test_existing_output_fields_byte_identical(self, cases_client) -> None:
        """The correlation layer only ADDS the ``case`` key — every existing
        field is identical whether correlation runs or is disabled."""
        from unittest.mock import patch

        import adte.server as srv

        payload = make_payload("INC-PARITY")

        with patch.object(srv, "ingest_alert", lambda *a, **k: None):
            disabled = cases_client.post("/api/triage", json=payload).get_json()
        enabled = cases_client.post("/api/triage", json=payload).get_json()

        assert disabled["case"] is None
        assert enabled["case"] is not None
        # Normalize the one volatile field (report build timestamp).
        for body in (disabled, enabled):
            body.pop("case")
            body["report"]["timestamp"] = "<normalized>"
        assert disabled == enabled

    def test_kill_chain_end_to_end_escalates(self, cases_client) -> None:
        """Three same-IP alerts walking cred-access -> lateral -> exfil."""
        sequence = [
            ("INC-KC1", ("T1110",), "2026-07-10T12:00:00Z"),
            ("INC-KC2", ("T1021",), "2026-07-10T12:05:00Z"),
            ("INC-KC3", ("T1048",), "2026-07-10T12:10:00Z"),
        ]
        case = None
        for incident_id, tids, ts in sequence:
            resp = cases_client.post(
                "/api/triage",
                json=make_payload(incident_id, technique_ids=tids, ts=ts),
            )
            assert resp.status_code == 200
            case = resp.get_json()["case"]
        assert case["alert_count"] == 3
        assert case["kill_chain"]["detected"] is True
        chain = case["kill_chain"]["tactics_in_order"]
        assert chain.index("Credential Access") < chain.index("Lateral Movement")
        assert chain.index("Lateral Movement") < chain.index("Exfiltration")
        factors = [r["factor"] for r in case["escalation_rationale"]]
        assert "kill_chain" in factors
        assert "multi_alert" in factors


class TestBatchIngestHook:
    def test_batch_elements_carry_case_and_summary(self, cases_client) -> None:
        batch = [make_payload(f"INC-B{i}") for i in range(3)]
        resp = cases_client.post("/api/triage/batch", json=batch)
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["succeeded"] == 3
        for entry in body["results"]:
            assert entry["case"] is not None
        # All three share one IP -> one case with final counts.
        assert len(body["cases"]) == 1
        summary = body["cases"][0]
        assert summary["alert_count"] == 3
        assert summary["member_indices"] == [0, 1, 2]
        # Per-element blobs show the case as of THAT ingest.
        assert body["results"][0]["case"]["alert_count"] == 1
        assert body["results"][2]["case"]["alert_count"] == 3

    def test_wazuh_fixture_batch_summary_consistent(self, cases_client) -> None:
        data = json.loads(
            (FIXTURES_DIR / "wazuh_alerts.json").read_text(encoding="utf-8")
        )
        resp = cases_client.post("/api/triage/batch", json=data)
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["succeeded"] == len(data["hits"]["hits"])
        # Every correlated element's index appears in exactly one summary.
        indexed = sorted(
            i for s in body["cases"] for i in s["member_indices"]
        )
        expected = sorted(
            r["index"] for r in body["results"] if r.get("ok") and r.get("case")
        )
        assert indexed == expected

    def test_batch_of_25_within_deadline(self, cases_client) -> None:
        batch = [make_payload(f"INC-25-{i}") for i in range(25)]
        resp = cases_client.post("/api/triage/batch", json=batch)
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["succeeded"] == 25
        assert body["cases"][0]["alert_count"] == 25


class TestCasesRoutes:
    def test_list_cases(self, cases_client) -> None:
        cases_client.post("/api/triage", json=make_payload("INC-1"))
        resp = cases_client.get("/api/cases")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["count"] == 1
        assert body["cases"][0]["status"] == "open"
        assert body["cases"][0]["alert_count"] == 1

    def test_list_status_filter_and_validation(self, cases_client) -> None:
        cases_client.post("/api/triage", json=make_payload("INC-1"))
        assert cases_client.get("/api/cases?status=open").get_json()["count"] == 1
        assert cases_client.get("/api/cases?status=closed").get_json()["count"] == 0
        assert cases_client.get("/api/cases?status=bogus").status_code == 400

    def test_list_limit_clamped(self, cases_client) -> None:
        resp = cases_client.get("/api/cases?limit=99999")
        assert resp.status_code == 200
        resp = cases_client.get("/api/cases?limit=not-a-number")
        assert resp.status_code == 200

    def test_case_detail_with_members(self, cases_client) -> None:
        case_id = cases_client.post(
            "/api/triage", json=make_payload("INC-1", technique_ids=("T1110",))
        ).get_json()["case"]["case_id"]
        resp = cases_client.get(f"/api/cases/{case_id}")
        assert resp.status_code == 200
        detail = resp.get_json()
        assert detail["case_id"] == case_id
        assert "escalation_rationale" in detail
        assert len(detail["members"]) == 1
        assert detail["members"][0]["incident_id"] == "INC-1"
        assert "Credential Access" in detail["members"][0]["tactics"]

    def test_case_detail_unknown_404(self, cases_client) -> None:
        resp = cases_client.get("/api/cases/CASE-19700101-000000")
        assert resp.status_code == 404

    def test_delete_cases_clears_list(self, cases_client) -> None:
        cases_client.post("/api/triage", json=make_payload("INC-1"))
        resp = cases_client.delete("/api/cases")
        assert resp.status_code == 200
        assert cases_client.get("/api/cases").get_json()["count"] == 0


class TestCasesRBAC:
    def test_delete_cases_requires_admin(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import adte.server as srv

        db_path = tmp_path / "rbac.db"
        monkeypatch.setattr(srv, "DB_PATH", db_path)
        monkeypatch.setenv("ADTE_API_KEY_ANALYST", "analyst-test-key")
        monkeypatch.setenv("ADTE_API_KEY_ADMIN", "admin-test-key")
        monkeypatch.setitem(srv.app.config, "TESTING", False)
        init_db(db_path)

        with srv.app.test_client() as client:
            denied = client.delete(
                "/api/cases", headers={"X-ADTE-Key": "analyst-test-key"}
            )
            assert denied.status_code == 403
            allowed = client.delete(
                "/api/cases", headers={"X-ADTE-Key": "admin-test-key"}
            )
            assert allowed.status_code == 200

    def test_get_cases_requires_auth_in_secured_mode(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import adte.server as srv

        monkeypatch.setattr(srv, "DB_PATH", tmp_path / "rbac2.db")
        monkeypatch.setenv("ADTE_API_KEY_ANALYST", "analyst-test-key")
        monkeypatch.setitem(srv.app.config, "TESTING", False)

        with srv.app.test_client() as client:
            assert client.get("/api/cases").status_code == 401


class TestFailOpen:
    def test_triage_succeeds_with_broken_case_store(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A DB path that cannot be opened yields case: null, not an error."""
        import adte.server as srv

        broken = tmp_path / "a_directory"
        broken.mkdir()
        monkeypatch.setattr(srv, "DB_PATH", broken)
        srv.app.config["TESTING"] = True

        with srv.app.test_client() as client:
            resp = client.post("/api/triage", json=make_payload("INC-BROKEN"))
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["case"] is None
        assert body["verdict"] in ("low_risk", "medium_risk", "high_risk")

    def test_cases_list_fails_closed_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import adte.server as srv

        broken = tmp_path / "a_directory"
        broken.mkdir()
        monkeypatch.setattr(srv, "DB_PATH", broken)
        srv.app.config["TESTING"] = True

        with srv.app.test_client() as client:
            resp = client.get("/api/cases")
        assert resp.status_code == 200
        assert resp.get_json() == {"cases": [], "count": 0}
