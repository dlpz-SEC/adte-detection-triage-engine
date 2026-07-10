"""Tests for the /api/stats/* aggregation endpoints (P13 debt, shipped in C1).

Covers the three store aggregations (verdicts, MITRE frequency, feedback
ratio) and their routes: correct counts, `since` filtering, soft-delete
exclusion, empty-database behavior, malformed MITRE JSON tolerance, and
the shared since-validation error.
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
    stats_feedback,
    stats_mitre,
    stats_verdicts,
)


def _verdict_output(
    incident_id: str = "INC-1",
    verdict: str = "high_risk",
    techniques: list[str] | None = None,
) -> dict[str, Any]:
    """Build a minimal TriageEngine-style output for log_verdict."""
    return {
        "incident_id": incident_id,
        "verdict": verdict,
        "risk_score": 90,
        "confidence": 80,
        "recommended_action": "escalate",
        "mitre_techniques": techniques if techniques is not None else ["T1110"],
        "nist_phase": "Containment",
        "source": "wazuh",
        "timestamp": "2025-01-15T10:00:00+00:00",
    }


@pytest.fixture()
def stats_db(tmp_path: Path) -> Path:
    """Fresh isolated database file."""
    db_path = tmp_path / "test_stats.db"
    init_db(db_path)
    return db_path


@pytest.fixture()
def stats_client(stats_db: Path, monkeypatch: pytest.MonkeyPatch):
    """Flask test client with DB_PATH redirected to the isolated database."""
    import adte.server as srv

    monkeypatch.setattr(srv, "DB_PATH", stats_db)
    srv.app.config["TESTING"] = True
    with srv.app.test_client() as client:
        yield client, stats_db


class TestStatsVerdictsStore:
    """stats_verdicts() aggregation semantics."""

    def test_counts_by_verdict(self, stats_db: Path) -> None:
        """GROUP BY verdict returns per-label counts and the total."""
        log_verdict(_verdict_output("a", "high_risk"), stats_db)
        log_verdict(_verdict_output("b", "high_risk"), stats_db)
        log_verdict(_verdict_output("c", "low_risk"), stats_db)
        result = stats_verdicts(stats_db)
        assert result["counts"] == {"high_risk": 2, "low_risk": 1}
        assert result["total"] == 3

    def test_soft_deleted_rows_excluded(self, stats_db: Path) -> None:
        """Cleared verdicts disappear from the aggregation."""
        log_verdict(_verdict_output("a"), stats_db)
        assert clear_verdicts(stats_db) is True
        result = stats_verdicts(stats_db)
        assert result["total"] == 0

    def test_since_filters_old_rows(self, stats_db: Path) -> None:
        """Rows logged before `since` are not counted."""
        log_verdict(_verdict_output("a"), stats_db)
        result = stats_verdicts(stats_db, since="2999-01-01T00:00:00+00:00")
        assert result["total"] == 0

    def test_empty_database(self, stats_db: Path) -> None:
        """No rows → zeroed shape, no error."""
        assert stats_verdicts(stats_db) == {"counts": {}, "total": 0}


class TestStatsMitreStore:
    """stats_mitre() JSON-column aggregation semantics."""

    def test_technique_frequency_sorted_desc(self, stats_db: Path) -> None:
        """Counts aggregate across rows, sorted by count then ID."""
        log_verdict(_verdict_output("a", techniques=["T1110", "T1621"]), stats_db)
        log_verdict(_verdict_output("b", techniques=["T1110"]), stats_db)
        result = stats_mitre(stats_db)
        assert result["techniques"][0] == {"technique_id": "T1110", "count": 2}
        assert result["techniques"][1] == {"technique_id": "T1621", "count": 1}
        assert result["total_rows"] == 2

    def test_malformed_json_rows_skipped(self, stats_db: Path) -> None:
        """A corrupted mitre_techniques cell is skipped, not fatal."""
        log_verdict(_verdict_output("a", techniques=["T1110"]), stats_db)
        with sqlite3.connect(str(stats_db)) as conn:
            conn.execute(
                "UPDATE verdicts SET mitre_techniques = ? WHERE incident_id = ?",
                ("{not-json", "a"),
            )
            conn.execute(
                "INSERT INTO verdicts (incident_id, verdict, risk_score, mitre_techniques, logged_at) "
                "VALUES (?, ?, ?, ?, ?)",
                ("b", "low_risk", 5.0, json.dumps(["T1621"]), "2025-01-15T10:00:00+00:00"),
            )
            conn.commit()
        result = stats_mitre(stats_db)
        assert result["techniques"] == [{"technique_id": "T1621", "count": 1}]
        assert result["total_rows"] == 2

    def test_empty_database(self, stats_db: Path) -> None:
        """No rows → empty ranking."""
        assert stats_mitre(stats_db) == {"techniques": [], "total_rows": 0}


class TestStatsFeedbackStore:
    """stats_feedback() FP/TP ratio semantics."""

    def test_ratio_computed(self, stats_db: Path) -> None:
        """fp_ratio = fp / (fp + tp), rounded."""
        log_feedback("a", "fp", None, stats_db)
        log_feedback("b", "fp", None, stats_db)
        log_feedback("c", "tp", None, stats_db)
        result = stats_feedback(stats_db)
        assert result == {"fp": 2, "tp": 1, "total": 3, "fp_ratio": 0.6667}

    def test_empty_database_ratio_zero(self, stats_db: Path) -> None:
        """No feedback → zero ratio, not a division error."""
        assert stats_feedback(stats_db) == {
            "fp": 0, "tp": 0, "total": 0, "fp_ratio": 0.0,
        }

    def test_soft_deleted_feedback_excluded(self, stats_db: Path) -> None:
        """Cleared feedback rows do not count."""
        log_feedback("a", "fp", None, stats_db)
        assert clear_feedback(stats_db) is True
        assert stats_feedback(stats_db)["total"] == 0


class TestStatsRoutes:
    """The three GET /api/stats/* routes."""

    def test_verdicts_route_shape(self, stats_client) -> None:
        """Route returns counts, total, and echoes the window."""
        client, db = stats_client
        log_verdict(_verdict_output("a", "medium_risk"), db)
        resp = client.get("/api/stats/verdicts")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["counts"] == {"medium_risk": 1}
        assert body["total"] == 1
        assert body["since"] is None

    def test_mitre_route_shape(self, stats_client) -> None:
        """Route returns the ranked technique list."""
        client, db = stats_client
        log_verdict(_verdict_output("a", techniques=["T1621", "T1090.003"]), db)
        resp = client.get("/api/stats/mitre")
        assert resp.status_code == 200
        body = resp.get_json()
        assert {"technique_id": "T1621", "count": 1} in body["techniques"]
        assert body["total_rows"] == 1

    def test_feedback_route_shape(self, stats_client) -> None:
        """Route returns the fp/tp split."""
        client, db = stats_client
        log_feedback("a", "tp", None, db)
        resp = client.get("/api/stats/feedback")
        assert resp.status_code == 200
        assert resp.get_json()["tp"] == 1

    def test_since_route_filter(self, stats_client) -> None:
        """A future `since` excludes existing rows."""
        client, db = stats_client
        log_verdict(_verdict_output("a"), db)
        resp = client.get("/api/stats/verdicts?since=2999-01-01T00:00:00")
        assert resp.status_code == 200
        assert resp.get_json()["total"] == 0

    def test_invalid_since_rejected(self, stats_client) -> None:
        """Malformed `since` → 400 with the standard message."""
        client, _ = stats_client
        resp = client.get("/api/stats/verdicts?since=not-a-date")
        assert resp.status_code == 400
        assert "ISO 8601" in resp.get_json()["error"]
