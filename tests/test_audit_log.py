"""Tests for adte.store.audit_log — SQLite verdict persistence.

Uses pytest's tmp_path fixture for isolated, temporary database files.
No mocking of sqlite3 — all tests exercise real SQLite behaviour.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from adte.store.audit_log import (
    clear_feedback,
    clear_verdicts,
    init_db,
    log_feedback,
    log_verdict,
    query_feedback,
    query_verdicts,
)

# ---------------------------------------------------------------------------
# Shared fixtures and helpers
# ---------------------------------------------------------------------------

_FULL_OUTPUT: dict[str, Any] = {
    "verdict": "high_risk",
    "risk_score": 87.0,
    "confidence": 82,
    "recommended_action": "Immediately disable account, revoke sessions",
    "mitre_techniques": ["T1078.004", "T1621"],
    "nist_phase": "Containment",
    "rationale": [
        {"signal": "impossible_travel", "score": 30, "detail": "800 km in 10 min"},
        {"signal": "mfa_fatigue", "score": 25, "detail": "5 denials"},
    ],
    "evidence": {"incident_id": "INC-001", "user": "alice@example.com"},
    "report": {
        "incident_id": "INC-001",
        "timestamp": "2026-04-29T14:00:00+00:00",
    },
}

_MINIMAL_OUTPUT: dict[str, Any] = {
    "verdict": "low_risk",
    "risk_score": 5.0,
}


def _row_count(db_path: Path) -> int:
    """Return total row count in the verdicts table."""
    with sqlite3.connect(str(db_path)) as conn:
        return conn.execute("SELECT COUNT(*) FROM verdicts").fetchone()[0]


# ---------------------------------------------------------------------------
# init_db
# ---------------------------------------------------------------------------


def test_init_db_creates_file_and_table(tmp_path: Path) -> None:
    """init_db creates the database file and verdicts table."""
    db = tmp_path / "audit.db"
    assert not db.exists()

    init_db(db)

    assert db.exists()
    with sqlite3.connect(str(db)) as conn:
        result = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='verdicts'"
        ).fetchone()
    assert result is not None


def test_init_db_is_idempotent(tmp_path: Path) -> None:
    """Calling init_db twice does not raise or duplicate the table."""
    db = tmp_path / "audit.db"
    init_db(db)
    init_db(db)  # must not raise

    with sqlite3.connect(str(db)) as conn:
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='verdicts'"
        ).fetchall()
    assert len(tables) == 1


# ---------------------------------------------------------------------------
# log_verdict
# ---------------------------------------------------------------------------


def test_log_verdict_inserts_row_with_all_fields(tmp_path: Path) -> None:
    """log_verdict persists all populated fields correctly."""
    db = tmp_path / "audit.db"
    init_db(db)
    log_verdict(_FULL_OUTPUT, db)

    assert _row_count(db) == 1
    with sqlite3.connect(str(db)) as conn:
        conn.row_factory = sqlite3.Row
        row = dict(conn.execute("SELECT * FROM verdicts").fetchone())

    assert row["incident_id"] == "INC-001"
    assert row["verdict"] == "high_risk"
    assert row["risk_score"] == 87.0
    assert row["confidence"] == 82
    assert row["recommended_action"] == "Immediately disable account, revoke sessions"
    assert row["nist_phase"] == "Containment"
    assert row["timestamp"] == "2026-04-29T14:00:00+00:00"
    assert row["logged_at"] is not None


def test_log_verdict_missing_optional_fields_default_to_none(tmp_path: Path) -> None:
    """log_verdict accepts a minimal dict — optional fields default to None."""
    db = tmp_path / "audit.db"
    init_db(db)
    log_verdict(_MINIMAL_OUTPUT, db)

    assert _row_count(db) == 1
    with sqlite3.connect(str(db)) as conn:
        conn.row_factory = sqlite3.Row
        row = dict(conn.execute("SELECT * FROM verdicts").fetchone())

    assert row["verdict"] == "low_risk"
    assert row["risk_score"] == 5.0
    assert row["confidence"] is None
    assert row["recommended_action"] is None
    assert row["mitre_techniques"] is None
    assert row["nist_phase"] is None
    assert row["source"] is None
    assert row["timestamp"] is None


def test_log_verdict_corrupt_db_path_logs_warning_without_raising(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """log_verdict does not raise when the db path is unusable."""
    corrupt = tmp_path / "corrupt.db"
    corrupt.write_bytes(b"this is not a sqlite database")

    import logging
    with caplog.at_level(logging.WARNING, logger="adte.store.audit_log"):
        log_verdict(_FULL_OUTPUT, corrupt)  # must not raise

    assert any("audit_log.log_verdict failed" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# query_verdicts
# ---------------------------------------------------------------------------


def test_query_verdicts_returns_rows_newest_first(tmp_path: Path) -> None:
    """Rows are returned in reverse insertion order (newest first)."""
    db = tmp_path / "audit.db"
    init_db(db)

    first = {**_FULL_OUTPUT, "evidence": {"incident_id": "INC-001"}}
    second = {**_FULL_OUTPUT, "verdict": "medium_risk", "risk_score": 45.0,
              "evidence": {"incident_id": "INC-002"}}
    log_verdict(first, db)
    log_verdict(second, db)

    rows = query_verdicts(db)

    assert len(rows) == 2
    assert rows[0]["incident_id"] == "INC-002"
    assert rows[1]["incident_id"] == "INC-001"


def test_query_verdicts_filters_by_verdict(tmp_path: Path) -> None:
    """verdict_filter returns only rows matching that verdict string."""
    db = tmp_path / "audit.db"
    init_db(db)

    log_verdict(_FULL_OUTPUT, db)                                          # high_risk
    log_verdict({**_MINIMAL_OUTPUT, "verdict": "medium_risk", "risk_score": 45.0}, db)
    log_verdict({**_MINIMAL_OUTPUT}, db)                                   # low_risk

    high = query_verdicts(db, verdict_filter="high_risk")
    assert len(high) == 1
    assert high[0]["verdict"] == "high_risk"

    medium = query_verdicts(db, verdict_filter="medium_risk")
    assert len(medium) == 1
    assert medium[0]["verdict"] == "medium_risk"


def test_query_verdicts_limit_caps_results(tmp_path: Path) -> None:
    """limit parameter caps the number of returned rows."""
    db = tmp_path / "audit.db"
    init_db(db)

    for i in range(10):
        log_verdict({**_MINIMAL_OUTPUT, "evidence": {"incident_id": f"INC-{i:03d}"}}, db)

    rows = query_verdicts(db, limit=3)
    assert len(rows) == 3


def test_query_verdicts_nonexistent_db_returns_empty(tmp_path: Path) -> None:
    """query_verdicts returns [] when the database file does not exist."""
    missing = tmp_path / "does_not_exist.db"
    result = query_verdicts(missing)
    assert result == []


# ---------------------------------------------------------------------------
# query_feedback
# ---------------------------------------------------------------------------


def test_query_feedback_returns_all_rows_when_no_label(tmp_path: Path) -> None:
    """query_feedback with label=None returns all rows regardless of label."""
    db = tmp_path / "audit.db"
    init_db(db)
    log_feedback("INC-001", "fp", "1.2.3.4", db)
    log_feedback("INC-002", "tp", None, db)

    rows = query_feedback(db, label=None)
    assert len(rows) == 2


def test_query_feedback_filters_fp(tmp_path: Path) -> None:
    """query_feedback with label='fp' returns only FP rows."""
    db = tmp_path / "audit.db"
    init_db(db)
    log_feedback("INC-001", "fp", "1.2.3.4", db)
    log_feedback("INC-002", "tp", None, db)
    log_feedback("INC-003", "fp", "5.6.7.8", db)

    rows = query_feedback(db, label="fp")
    assert len(rows) == 2
    assert all(r["label"] == "fp" for r in rows)


def test_query_feedback_filters_tp(tmp_path: Path) -> None:
    """query_feedback with label='tp' returns only TP rows."""
    db = tmp_path / "audit.db"
    init_db(db)
    log_feedback("INC-001", "fp", "1.2.3.4", db)
    log_feedback("INC-002", "tp", None, db)

    rows = query_feedback(db, label="tp")
    assert len(rows) == 1
    assert rows[0]["label"] == "tp"
    assert rows[0]["incident_id"] == "INC-002"


def test_query_feedback_label_returns_empty_when_none_match(tmp_path: Path) -> None:
    """query_feedback returns [] when no rows match the requested label."""
    db = tmp_path / "audit.db"
    init_db(db)
    log_feedback("INC-001", "fp", "1.2.3.4", db)

    rows = query_feedback(db, label="tp")
    assert rows == []


def test_query_feedback_newest_first(tmp_path: Path) -> None:
    """Feedback rows are returned newest first (by id DESC)."""
    db = tmp_path / "audit.db"
    init_db(db)
    log_feedback("INC-001", "fp", None, db)
    log_feedback("INC-002", "fp", None, db)

    rows = query_feedback(db, label="fp")
    assert rows[0]["incident_id"] == "INC-002"
    assert rows[1]["incident_id"] == "INC-001"


def test_mitre_techniques_round_trips_through_json(tmp_path: Path) -> None:
    """mitre_techniques is stored as a JSON string and parses back correctly."""
    db = tmp_path / "audit.db"
    init_db(db)
    log_verdict(_FULL_OUTPUT, db)

    rows = query_verdicts(db)
    assert len(rows) == 1
    stored = rows[0]["mitre_techniques"]
    assert isinstance(stored, str)
    decoded = json.loads(stored)
    assert decoded == ["T1078.004", "T1621"]


# ---------------------------------------------------------------------------
# query_verdicts — since filter
# ---------------------------------------------------------------------------


def test_query_verdicts_since_filters_old_rows(tmp_path: Path) -> None:
    """since filter excludes rows whose logged_at is before the cutoff."""
    import sqlite3 as _sql
    db = tmp_path / "audit.db"
    init_db(db)
    log_verdict(_FULL_OUTPUT, db)

    # Back-date the inserted row so it falls before the cutoff.
    with _sql.connect(str(db)) as conn:
        conn.execute("UPDATE verdicts SET logged_at = '2000-01-01T00:00:00+00:00'")

    rows = query_verdicts(db, since="2025-01-01T00:00:00+00:00")
    assert rows == []


def test_query_verdicts_since_with_verdict_filter(tmp_path: Path) -> None:
    """since and verdict_filter compose correctly — both clauses must match."""
    import sqlite3 as _sql
    db = tmp_path / "audit.db"
    init_db(db)
    log_verdict(_FULL_OUTPUT, db)                                    # high_risk, recent
    log_verdict({**_MINIMAL_OUTPUT, "verdict": "medium_risk", "risk_score": 45.0}, db)  # medium, recent

    # Back-date the high_risk row only.
    with _sql.connect(str(db)) as conn:
        conn.execute(
            "UPDATE verdicts SET logged_at = '2000-01-01T00:00:00+00:00' WHERE verdict = 'high_risk'"
        )

    rows = query_verdicts(db, verdict_filter="high_risk", since="2025-01-01T00:00:00+00:00")
    assert rows == []

    medium_rows = query_verdicts(db, verdict_filter="medium_risk", since="2025-01-01T00:00:00+00:00")
    assert len(medium_rows) == 1
    assert medium_rows[0]["verdict"] == "medium_risk"


# ---------------------------------------------------------------------------
# Soft-delete — clear_verdicts / clear_feedback
# ---------------------------------------------------------------------------


def test_clear_verdicts_hides_rows_from_query(tmp_path: Path) -> None:
    """After clear_verdicts, query_verdicts returns no rows."""
    db = tmp_path / "audit.db"
    init_db(db)
    log_verdict(_FULL_OUTPUT, db)
    assert len(query_verdicts(db)) == 1

    ok = clear_verdicts(db)
    assert ok is True
    assert query_verdicts(db) == []


def test_clear_verdicts_preserves_rows_in_database(tmp_path: Path) -> None:
    """clear_verdicts does not physically remove rows — deleted_at is stamped."""
    db = tmp_path / "audit.db"
    init_db(db)
    log_verdict(_FULL_OUTPUT, db)

    clear_verdicts(db)

    # Raw count must still be 1 — the row exists but is soft-deleted.
    with sqlite3.connect(str(db)) as conn:
        total = conn.execute("SELECT COUNT(*) FROM verdicts").fetchone()[0]
        deleted = conn.execute(
            "SELECT COUNT(*) FROM verdicts WHERE deleted_at IS NOT NULL"
        ).fetchone()[0]
    assert total == 1
    assert deleted == 1


def test_clear_verdicts_does_not_restamp_already_deleted_rows(tmp_path: Path) -> None:
    """Calling clear_verdicts twice keeps the original deleted_at timestamp."""
    db = tmp_path / "audit.db"
    init_db(db)
    log_verdict(_FULL_OUTPUT, db)

    clear_verdicts(db)
    with sqlite3.connect(str(db)) as conn:
        first_ts = conn.execute("SELECT deleted_at FROM verdicts").fetchone()[0]

    clear_verdicts(db)
    with sqlite3.connect(str(db)) as conn:
        second_ts = conn.execute("SELECT deleted_at FROM verdicts").fetchone()[0]

    assert first_ts == second_ts


def test_clear_feedback_hides_rows_from_query(tmp_path: Path) -> None:
    """After clear_feedback, query_feedback returns no rows."""
    db = tmp_path / "audit.db"
    init_db(db)
    log_feedback("INC-001", "fp", "1.2.3.4", db)
    assert len(query_feedback(db)) == 1

    ok = clear_feedback(db)
    assert ok is True
    assert query_feedback(db) == []


def test_clear_feedback_preserves_rows_in_database(tmp_path: Path) -> None:
    """clear_feedback does not physically remove rows — deleted_at is stamped."""
    db = tmp_path / "audit.db"
    init_db(db)
    log_feedback("INC-001", "tp", None, db)

    clear_feedback(db)

    with sqlite3.connect(str(db)) as conn:
        total = conn.execute("SELECT COUNT(*) FROM feedback").fetchone()[0]
        deleted = conn.execute(
            "SELECT COUNT(*) FROM feedback WHERE deleted_at IS NOT NULL"
        ).fetchone()[0]
    assert total == 1
    assert deleted == 1


def test_new_verdicts_visible_after_clear(tmp_path: Path) -> None:
    """Rows logged after clear_verdicts are visible; soft-deleted ones are not."""
    db = tmp_path / "audit.db"
    init_db(db)
    log_verdict(_FULL_OUTPUT, db)
    clear_verdicts(db)

    log_verdict({**_MINIMAL_OUTPUT, "verdict": "medium_risk", "risk_score": 45.0}, db)

    rows = query_verdicts(db)
    assert len(rows) == 1
    assert rows[0]["verdict"] == "medium_risk"
