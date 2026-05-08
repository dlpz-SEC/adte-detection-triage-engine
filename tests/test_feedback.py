"""Tests for the analyst feedback loop.

Covers:
  - adte.store.audit_log: log_feedback, query_feedback
  - adte.intel.sigma_fp_registry: add_fp_entry
  - adte.server: POST /api/feedback

All SQLite tests use pytest's tmp_path fixture.  No mocking of sqlite3 or
the filesystem — tests exercise real behaviour.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path

import pytest
import yaml

from adte.store.audit_log import init_db, log_feedback, query_feedback
from adte.intel.sigma_fp_registry import add_fp_entry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MINIMAL_REGISTRY = [
    {
        "pattern_type": "corporate_vpn",
        "description": "Test VPN ranges",
        "cidrs": ["10.0.0.0/8"],
    }
]


def _make_registry(tmp_path: Path) -> Path:
    path = tmp_path / "fp_registry.yaml"
    path.write_text(
        yaml.dump(_MINIMAL_REGISTRY, default_flow_style=False),
        encoding="utf-8",
    )
    return path


# ---------------------------------------------------------------------------
# log_feedback
# ---------------------------------------------------------------------------


def test_log_feedback_inserts_row_with_all_fields(tmp_path: Path) -> None:
    """log_feedback persists all fields including ip."""
    db = tmp_path / "test.db"
    init_db(db)
    log_feedback("INC-001", "fp", "192.0.2.1", db)

    with sqlite3.connect(str(db)) as conn:
        conn.row_factory = sqlite3.Row
        row = dict(conn.execute("SELECT * FROM feedback").fetchone())

    assert row["incident_id"] == "INC-001"
    assert row["label"] == "fp"
    assert row["ip"] == "192.0.2.1"
    assert row["submitted_at"] is not None


def test_log_feedback_null_ip_stores_none(tmp_path: Path) -> None:
    """log_feedback with ip=None stores NULL without raising."""
    db = tmp_path / "test.db"
    init_db(db)
    log_feedback("INC-002", "tp", None, db)

    with sqlite3.connect(str(db)) as conn:
        conn.row_factory = sqlite3.Row
        row = dict(conn.execute("SELECT * FROM feedback").fetchone())

    assert row["ip"] is None
    assert row["label"] == "tp"


def test_log_feedback_invalid_db_path_logs_warning_without_raising(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """log_feedback with a corrupt DB path logs a warning and never raises."""
    corrupt = tmp_path / "corrupt.db"
    corrupt.write_bytes(b"this is not a sqlite database")

    with caplog.at_level(logging.WARNING, logger="adte.store.audit_log"):
        log_feedback("INC-001", "fp", "1.2.3.4", corrupt)

    assert any("audit_log.log_feedback failed" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# query_feedback
# ---------------------------------------------------------------------------


def test_query_feedback_returns_rows_newest_first(tmp_path: Path) -> None:
    """Rows are returned in reverse insertion order (newest first)."""
    db = tmp_path / "test.db"
    init_db(db)
    log_feedback("INC-001", "fp", "1.2.3.4", db)
    log_feedback("INC-002", "tp", None, db)

    rows = query_feedback(db)

    assert len(rows) == 2
    assert rows[0]["incident_id"] == "INC-002"
    assert rows[1]["incident_id"] == "INC-001"


def test_query_feedback_filtered_by_label(tmp_path: Path) -> None:
    """label filter returns only rows with the matching label."""
    db = tmp_path / "test.db"
    init_db(db)
    log_feedback("INC-001", "fp", "1.2.3.4", db)
    log_feedback("INC-002", "tp", None, db)
    log_feedback("INC-001", "tp", None, db)

    fp_rows = query_feedback(db, label="fp")
    assert len(fp_rows) == 1
    assert fp_rows[0]["label"] == "fp"

    tp_rows = query_feedback(db, label="tp")
    assert len(tp_rows) == 2
    assert all(r["label"] == "tp" for r in tp_rows)


def test_query_feedback_nonexistent_db_returns_empty(tmp_path: Path) -> None:
    """query_feedback returns [] when the database file does not exist."""
    missing = tmp_path / "does_not_exist.db"
    assert query_feedback(missing) == []


# ---------------------------------------------------------------------------
# add_fp_entry
# ---------------------------------------------------------------------------


def test_add_fp_entry_appends_entry_and_returns_true(tmp_path: Path) -> None:
    """add_fp_entry writes a new YAML entry and returns True."""
    registry = _make_registry(tmp_path)

    result = add_fp_entry("192.0.2.1", "Auto-added by ADTE feedback loop", registry)

    assert result is True
    loaded = yaml.safe_load(registry.read_text(encoding="utf-8"))
    analyst_entries = [e for e in loaded if e.get("pattern_type") == "analyst_feedback"]
    assert len(analyst_entries) == 1
    assert "192.0.2.1/32" in analyst_entries[0]["cidrs"]


def test_add_fp_entry_nonexistent_path_returns_false(tmp_path: Path) -> None:
    """add_fp_entry returns False without raising when path does not exist."""
    missing = tmp_path / "no_registry.yaml"
    result = add_fp_entry("1.2.3.4", "test comment", missing)
    assert result is False


# ---------------------------------------------------------------------------
# POST /api/feedback — Flask integration tests
# ---------------------------------------------------------------------------


@pytest.fixture()
def _feedback_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Flask test client with DB_PATH and REGISTRY_PATH redirected to tmp_path."""
    db_path = tmp_path / "test.db"
    registry_path = _make_registry(tmp_path)

    import adte.server as srv

    monkeypatch.setattr(srv, "DB_PATH", db_path)
    monkeypatch.setattr(srv, "REGISTRY_PATH", registry_path)

    init_db(db_path)

    srv.app.config["TESTING"] = True
    with srv.app.test_client() as client:
        yield client, registry_path


def test_post_feedback_fp_with_ip_updates_registry(_feedback_client) -> None:
    """FP label + IP returns registry_updated: true and adds entry to YAML."""
    client, registry_path = _feedback_client
    resp = client.post(
        "/api/feedback",
        data=json.dumps({"incident_id": "INC-001", "label": "fp", "ip": "203.0.113.5"}),
        content_type="application/json",
    )

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["status"] == "ok"
    assert body["label"] == "fp"
    assert body["registry_updated"] is True

    loaded = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
    assert any(e.get("pattern_type") == "analyst_feedback" for e in loaded)


def test_post_feedback_tp_does_not_update_registry(_feedback_client) -> None:
    """TP label returns registry_updated: false and leaves YAML unchanged."""
    client, registry_path = _feedback_client
    before = registry_path.read_text(encoding="utf-8")

    resp = client.post(
        "/api/feedback",
        data=json.dumps({"incident_id": "INC-002", "label": "tp", "ip": "203.0.113.5"}),
        content_type="application/json",
    )

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["registry_updated"] is False
    assert registry_path.read_text(encoding="utf-8") == before


def test_post_feedback_invalid_label_returns_400(_feedback_client) -> None:
    """Invalid label value returns HTTP 400."""
    client, _ = _feedback_client
    resp = client.post(
        "/api/feedback",
        data=json.dumps({"incident_id": "INC-001", "label": "unknown"}),
        content_type="application/json",
    )

    assert resp.status_code == 400
    body = resp.get_json()
    assert "label" in body["error"]


# ---------------------------------------------------------------------------
# FP registry promotion — role enforcement
# ---------------------------------------------------------------------------


def test_fp_registry_promotion_blocked_for_analyst_role(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Analyst role receives 403 when attempting to promote an IP to the FP registry."""
    import adte.server as srv

    db_path = tmp_path / "test.db"
    registry_path = _make_registry(tmp_path)

    monkeypatch.setattr(srv, "DB_PATH", db_path)
    monkeypatch.setattr(srv, "REGISTRY_PATH", registry_path)
    monkeypatch.setenv("ADTE_API_KEY_ANALYST", "analyst-test-key")
    monkeypatch.setenv("ADTE_API_KEY_SENIOR", "senior-test-key")
    monkeypatch.setitem(srv.app.config, "TESTING", False)

    init_db(db_path)
    with srv.app.test_client() as client:
        resp = client.post(
            "/api/feedback",
            data=json.dumps({"incident_id": "INC-H3", "label": "fp", "ip": "203.0.113.5"}),
            content_type="application/json",
            headers={"X-ADTE-Key": "analyst-test-key"},
        )

    assert resp.status_code == 403
    assert "senior_analyst" in resp.get_json()["error"]


def test_fp_registry_promotion_allowed_for_senior_analyst_role(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """senior_analyst role can promote an IP to the FP registry."""
    import adte.server as srv

    db_path = tmp_path / "test.db"
    registry_path = _make_registry(tmp_path)

    monkeypatch.setattr(srv, "DB_PATH", db_path)
    monkeypatch.setattr(srv, "REGISTRY_PATH", registry_path)
    monkeypatch.setenv("ADTE_API_KEY_SENIOR", "senior-test-key")
    monkeypatch.setitem(srv.app.config, "TESTING", False)

    init_db(db_path)
    with srv.app.test_client() as client:
        resp = client.post(
            "/api/feedback",
            data=json.dumps({"incident_id": "INC-H3", "label": "fp", "ip": "203.0.113.5"}),
            content_type="application/json",
            headers={"X-ADTE-Key": "senior-test-key"},
        )

    assert resp.status_code == 200
    assert resp.get_json()["registry_updated"] is True


def test_fp_label_without_ip_allowed_for_analyst_role(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Analyst can submit an FP label without an IP — no registry promotion, no role escalation."""
    import adte.server as srv

    db_path = tmp_path / "test.db"
    registry_path = _make_registry(tmp_path)

    monkeypatch.setattr(srv, "DB_PATH", db_path)
    monkeypatch.setattr(srv, "REGISTRY_PATH", registry_path)
    monkeypatch.setenv("ADTE_API_KEY_ANALYST", "analyst-test-key")
    monkeypatch.setitem(srv.app.config, "TESTING", False)

    init_db(db_path)
    with srv.app.test_client() as client:
        resp = client.post(
            "/api/feedback",
            data=json.dumps({"incident_id": "INC-H3-b", "label": "fp"}),
            content_type="application/json",
            headers={"X-ADTE-Key": "analyst-test-key"},
        )

    assert resp.status_code == 200
    assert resp.get_json()["registry_updated"] is False
