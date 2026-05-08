"""SQLite audit log for ADTE triage verdicts.

Provides three public functions:
  ``init_db``        — create database and verdicts table if not present.
  ``log_verdict``    — insert one row from a triage output dict.
  ``query_verdicts`` — retrieve rows as dicts, newest first.

All three functions swallow exceptions and log them as warnings so that
audit log failures never affect the triage response pipeline.

Connections use ``check_same_thread=False`` so the module is safe to call
from a multi-threaded Flask context where multiple requests may share the
same process.

NIST 800-61 Phase: Detection & Analysis — maintains a persistent audit
trail capturing who/what/when/why for every automated triage decision.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

_CREATE_TABLE_SQL: str = """
CREATE TABLE IF NOT EXISTS verdicts (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id        TEXT NOT NULL,
    verdict            TEXT NOT NULL,
    risk_score         REAL NOT NULL,
    confidence         REAL,
    recommended_action TEXT,
    mitre_techniques   TEXT,
    nist_phase         TEXT,
    source             TEXT,
    timestamp          TEXT,
    logged_at          TEXT NOT NULL,
    deleted_at         TEXT
)
"""

_CREATE_FEEDBACK_TABLE_SQL: str = """
CREATE TABLE IF NOT EXISTS feedback (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id  TEXT NOT NULL,
    label        TEXT NOT NULL CHECK(label IN ('fp','tp')),
    ip           TEXT,
    submitted_at TEXT NOT NULL,
    deleted_at   TEXT
)
"""

_INSERT_SQL: str = """
INSERT INTO verdicts
    (incident_id, verdict, risk_score, confidence,
     recommended_action, mitre_techniques, nist_phase,
     source, timestamp, logged_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

_INSERT_FEEDBACK_SQL: str = """
INSERT INTO feedback (incident_id, label, ip, submitted_at)
VALUES (?, ?, ?, ?)
"""

_CREATE_INDEXES_SQL: list[str] = [
    "CREATE INDEX IF NOT EXISTS idx_verdicts_verdict ON verdicts(verdict)",
    "CREATE INDEX IF NOT EXISTS idx_verdicts_incident_id ON verdicts(incident_id)",
    "CREATE INDEX IF NOT EXISTS idx_feedback_incident_id ON feedback(incident_id)",
]


def init_db(path: str | Path) -> None:
    """Create the database file and verdicts table if they do not exist.

    Uses ``CREATE TABLE IF NOT EXISTS`` so calling this multiple times is
    safe and idempotent.

    Args:
        path: Filesystem path to the SQLite database file.  The file is
            created by SQLite if it does not already exist.
    """
    # SQLite data is unencrypted at rest; restrict the file to the owning
    # user (rw-------) as a minimum access-control layer.
    # os.chmod is a no-op on Windows (ACL-based model), but is effective
    # on Linux/macOS deployments where file mode bits are enforced.
    try:
        with sqlite3.connect(str(path), check_same_thread=False) as conn:
            conn.execute(_CREATE_TABLE_SQL)
            conn.execute(_CREATE_FEEDBACK_TABLE_SQL)
            for idx_sql in _CREATE_INDEXES_SQL:
                conn.execute(idx_sql)
            # Migration: add deleted_at to pre-existing databases that lack it.
            for table in ("verdicts", "feedback"):
                try:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN deleted_at TEXT")
                except sqlite3.OperationalError:
                    pass  # Column already exists — safe to ignore.
            conn.commit()
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass  # Windows or permission-restricted environment — best effort.
    except Exception as exc:
        _log.warning("audit_log.init_db failed: %s", exc)


def log_verdict(output: dict[str, Any], db_path: str | Path) -> None:
    """Insert one verdict row into the audit log.

    Extracts fields from the triage output dict defensively — missing keys
    default to ``None``.  ``mitre_techniques`` is serialised as a JSON
    string.  ``logged_at`` is set to the current UTC timestamp at insert
    time.

    Never raises; all exceptions are logged as warnings.

    Args:
        output: Canonical triage output dict from ``TriageEngine.to_output()``
            (with ``mitre_techniques`` and ``nist_phase`` already injected).
        db_path: Path to the SQLite database file.
    """
    try:
        # incident_id can live at three different nesting levels depending on
        # which engine path produced the output — try all three before defaulting.
        incident_id: str = (
            output.get("incident_id")
            or (output.get("evidence") or {}).get("incident_id")
            or (output.get("report") or {}).get("incident_id")
            or "unknown"
        )
        verdict: str = output.get("verdict") or "unknown"
        risk_score: float = float(output.get("risk_score") or 0.0)
        confidence: float | None = output.get("confidence")
        recommended_action: str | None = output.get("recommended_action")
        mitre_raw: list[str] | None = output.get("mitre_techniques")
        mitre_techniques: str | None = (
            json.dumps(mitre_raw) if mitre_raw is not None else None
        )
        nist_phase: str | None = output.get("nist_phase")
        source: str | None = output.get("source")
        timestamp: str | None = (
            (output.get("report") or {}).get("timestamp")
            or output.get("timestamp")
        )
        logged_at: str = datetime.now(timezone.utc).isoformat()

        with sqlite3.connect(str(db_path), check_same_thread=False) as conn:
            conn.execute(
                _INSERT_SQL,
                (
                    incident_id, verdict, risk_score, confidence,
                    recommended_action, mitre_techniques, nist_phase,
                    source, timestamp, logged_at,
                ),
            )
            conn.commit()
    except Exception as exc:
        _log.warning("audit_log.log_verdict failed: %s", exc)


def query_verdicts(
    db_path: str | Path,
    verdict_filter: str | None = None,
    limit: int = 100,
    since: str | None = None,
) -> list[dict[str, Any]]:
    """Return verdict rows from the audit log as dicts, newest first.

    Args:
        db_path: Path to the SQLite database file.
        verdict_filter: When provided, return only rows whose ``verdict``
            column matches this string exactly.
        limit: Maximum number of rows to return.  Defaults to 100.
        since: ISO-8601 timestamp string.  When provided, only rows whose
            ``logged_at`` is >= this value are returned.

    Returns:
        List of row dicts.  Empty list on any error or if the database
        file does not contain the verdicts table.
    """
    try:
        with sqlite3.connect(str(db_path), check_same_thread=False) as conn:
            conn.row_factory = sqlite3.Row  # makes rows subscriptable so dict(row) works
            clauses: list[str] = ["deleted_at IS NULL"]
            params: list[Any] = []
            if verdict_filter is not None:
                clauses.append("verdict = ?")
                params.append(verdict_filter)
            if since is not None:
                clauses.append("logged_at >= ?")
                params.append(since)
            where = "WHERE " + " AND ".join(clauses)
            params.append(limit)
            cursor = conn.execute(
                f"SELECT * FROM verdicts {where} ORDER BY id DESC LIMIT ?",
                params,
            )
            return [dict(row) for row in cursor.fetchall()]
    except Exception as exc:
        _log.warning("audit_log.query_verdicts failed: %s", exc)
        return []


def log_feedback(
    incident_id: str,
    label: str,
    ip: str | None,
    db_path: str | Path,
) -> None:
    """Insert one analyst feedback row into the audit log.

    Never raises; all exceptions are logged as warnings.

    Args:
        incident_id: The incident this feedback applies to.
        label: ``"fp"`` (false positive) or ``"tp"`` (true positive).
        ip: Source IP associated with the incident, or ``None``.
        db_path: Path to the SQLite database file.
    """
    try:
        submitted_at: str = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(str(db_path), check_same_thread=False) as conn:
            conn.execute(_INSERT_FEEDBACK_SQL, (incident_id, label, ip, submitted_at))
            conn.commit()
    except Exception as exc:
        _log.warning("audit_log.log_feedback failed: %s", exc)


def query_feedback(
    db_path: str | Path,
    label: str | None = None,
) -> list[dict[str, Any]]:
    """Return feedback rows from the audit log as dicts, newest first.

    Args:
        db_path: Path to the SQLite database file.
        label: When provided (``"fp"`` or ``"tp"``), return only rows with
            that label.  ``None`` returns all rows.

    Returns:
        List of row dicts.  Empty list on any error or missing database.
    """
    try:
        with sqlite3.connect(str(db_path), check_same_thread=False) as conn:
            conn.row_factory = sqlite3.Row  # makes rows subscriptable so dict(row) works
            if label is not None:
                cursor = conn.execute(
                    "SELECT * FROM feedback WHERE deleted_at IS NULL AND label = ? ORDER BY id DESC",
                    (label,),
                )
            else:
                cursor = conn.execute(
                    "SELECT * FROM feedback WHERE deleted_at IS NULL ORDER BY id DESC"
                )
            return [dict(row) for row in cursor.fetchall()]
    except Exception as exc:
        _log.warning("audit_log.query_feedback failed: %s", exc)
        return []


def clear_verdicts(db_path: str | Path) -> bool:
    """Soft-delete all active verdict rows, preserving the forensic audit trail.

    Rows are stamped with ``deleted_at`` rather than physically removed.
    ``query_verdicts`` filters them out of all normal views, but the raw
    data remains in the database for forensic recovery.  Hard DELETE is
    intentionally absent — NIST 800-61 requires a tamper-evident audit
    trail; destroying evidence violates non-repudiation requirements.

    Args:
        db_path: Path to the SQLite database file.

    Returns:
        ``True`` on success, ``False`` on any error.  Never raises.
    """
    try:
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(str(db_path), check_same_thread=False) as conn:
            conn.execute(
                "UPDATE verdicts SET deleted_at = ? WHERE deleted_at IS NULL",
                (now,),
            )
            conn.commit()
        return True
    except Exception as exc:
        _log.warning("audit_log.clear_verdicts failed: %s", type(exc).__name__)
        return False


def clear_feedback(db_path: str | Path) -> bool:
    """Soft-delete all active feedback rows, preserving the forensic audit trail.

    Rows are stamped with ``deleted_at`` rather than physically removed.
    ``query_feedback`` filters them out of all normal views, but the raw
    data remains in the database for forensic recovery.

    Args:
        db_path: Path to the SQLite database file.

    Returns:
        ``True`` on success, ``False`` on any error.  Never raises.
    """
    try:
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(str(db_path), check_same_thread=False) as conn:
            conn.execute(
                "UPDATE feedback SET deleted_at = ? WHERE deleted_at IS NULL",
                (now,),
            )
            conn.commit()
        return True
    except Exception as exc:
        _log.warning("audit_log.clear_feedback failed: %s", type(exc).__name__)
        return False
