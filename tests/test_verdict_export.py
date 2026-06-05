"""Tests for the GET /api/verdicts/export endpoint.

Exercises the Flask route end-to-end with a real (temporary) SQLite
audit database.  Mirrors the test-client fixture pattern used in
tests/test_feedback.py: TESTING=True bypasses RBAC, and DB_PATH is
monkeypatched to an isolated tmp_path database seeded via log_verdict.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

import pytest

from adte.store.audit_log import init_db, log_verdict

_HIGH_OUTPUT: dict[str, Any] = {
    "verdict": "high_risk",
    "risk_score": 87.0,
    "confidence": 82,
    "recommended_action": "Immediately disable account, revoke sessions",
    "mitre_techniques": ["T1078.004", "T1621"],
    "nist_phase": "Containment",
    "source": "wazuh",
    "evidence": {"incident_id": "INC-001", "user": "alice@example.com"},
    "report": {"incident_id": "INC-001", "timestamp": "2026-04-29T14:00:00+00:00"},
}

_LOW_OUTPUT: dict[str, Any] = {
    "verdict": "low_risk",
    "risk_score": 5.0,
    "confidence": 40,
    "recommended_action": "Auto-close, update baseline",
    "mitre_techniques": [],
    "nist_phase": "Detection & Analysis",
    "source": "mock",
    "evidence": {"incident_id": "INC-002", "user": "bob@example.com"},
    "report": {"incident_id": "INC-002", "timestamp": "2026-04-29T15:00:00+00:00"},
}


@pytest.fixture()
def export_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Flask test client with DB_PATH redirected to an isolated tmp database."""
    db_path = tmp_path / "test_export.db"

    import adte.server as srv

    monkeypatch.setattr(srv, "DB_PATH", db_path)
    init_db(db_path)

    srv.app.config["TESTING"] = True
    with srv.app.test_client() as client:
        yield client, db_path


def _seed(db_path: Path) -> None:
    """Insert two high_risk rows and one low_risk row into the audit log."""
    log_verdict(_HIGH_OUTPUT, db_path)
    log_verdict(_HIGH_OUTPUT, db_path)
    log_verdict(_LOW_OUTPUT, db_path)


def _parse_csv(body: str) -> list[dict[str, str]]:
    """Parse a CSV response body into a list of row dicts."""
    return list(csv.DictReader(io.StringIO(body)))


def test_export_default_format_is_csv(export_client) -> None:
    """No format param returns a text/csv attachment with header + rows."""
    client, db_path = export_client
    _seed(db_path)

    resp = client.get("/api/verdicts/export")

    assert resp.status_code == 200
    assert resp.mimetype == "text/csv"
    assert "attachment" in resp.headers["Content-Disposition"]
    assert ".csv" in resp.headers["Content-Disposition"]

    rows = _parse_csv(resp.get_data(as_text=True))
    assert len(rows) == 3
    assert {"incident_id", "verdict", "risk_score", "logged_at"} <= set(rows[0].keys())


def test_export_csv_contains_expected_data(export_client) -> None:
    """CSV rows carry through the seeded verdict values."""
    client, db_path = export_client
    _seed(db_path)

    resp = client.get("/api/verdicts/export?format=csv")
    rows = _parse_csv(resp.get_data(as_text=True))

    verdicts = sorted(r["verdict"] for r in rows)
    assert verdicts == ["high_risk", "high_risk", "low_risk"]
    high = next(r for r in rows if r["verdict"] == "high_risk")
    assert high["incident_id"] == "INC-001"
    assert high["source"] == "wazuh"
    # mitre_techniques is persisted as a JSON string in the audit table.
    assert "T1621" in high["mitre_techniques"]


def test_export_json_format(export_client) -> None:
    """format=json returns an application/json attachment with verdicts + count."""
    client, db_path = export_client
    _seed(db_path)

    resp = client.get("/api/verdicts/export?format=json")

    assert resp.status_code == 200
    assert resp.mimetype == "application/json"
    assert "attachment" in resp.headers["Content-Disposition"]
    assert ".json" in resp.headers["Content-Disposition"]

    body = json.loads(resp.get_data(as_text=True))
    assert body["count"] == 3
    assert len(body["verdicts"]) == 3


def test_export_format_is_case_insensitive(export_client) -> None:
    """format=CSV (uppercase) is accepted and returns csv."""
    client, db_path = export_client
    _seed(db_path)

    resp = client.get("/api/verdicts/export?format=CSV")

    assert resp.status_code == 200
    assert resp.mimetype == "text/csv"


def test_export_verdict_filter_passthrough(export_client) -> None:
    """verdict filter narrows the export to matching rows only."""
    client, db_path = export_client
    _seed(db_path)

    resp = client.get("/api/verdicts/export?verdict=high_risk")
    rows = _parse_csv(resp.get_data(as_text=True))

    assert len(rows) == 2
    assert all(r["verdict"] == "high_risk" for r in rows)


def test_export_invalid_format_returns_400(export_client) -> None:
    """An unsupported format value is rejected with 400."""
    client, db_path = export_client

    resp = client.get("/api/verdicts/export?format=xml")

    assert resp.status_code == 400
    assert "format" in resp.get_json()["error"]


def test_export_invalid_since_returns_400(export_client) -> None:
    """A non-ISO since value is rejected with 400."""
    client, db_path = export_client

    resp = client.get("/api/verdicts/export?since=not-a-date")

    assert resp.status_code == 400
    assert "since" in resp.get_json()["error"]


def test_export_empty_db_returns_header_only_csv(export_client) -> None:
    """With no rows, the CSV export still returns a valid header-only file."""
    client, db_path = export_client  # no _seed

    resp = client.get("/api/verdicts/export")

    assert resp.status_code == 200
    assert resp.mimetype == "text/csv"
    rows = _parse_csv(resp.get_data(as_text=True))
    assert rows == []
    # Header line is still present even with zero data rows.
    first_line = resp.get_data(as_text=True).splitlines()[0]
    assert "incident_id" in first_line
