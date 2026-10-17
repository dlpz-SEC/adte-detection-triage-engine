"""Incident Drill rows are hidden from audit reads unless asked for.

The filter runs in SQL before LIMIT, so drills can never push real rows out
of a page, and it is case-sensitive (SQLite's LIKE would also hide a real
incident named "drill-…").
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from adte.store.audit_log import (
    init_db,
    log_verdict,
    query_verdicts,
    stats_mitre,
    stats_verdicts,
)


def _row(incident_id: str, verdict: str = "high_risk", tech: str = "T1078") -> dict:
    return {
        "incident_id": incident_id,
        "verdict": verdict,
        "risk_score": 80,
        "confidence": 70,
        "mitre_techniques": [tech],
    }


# The prefix is the contract (audit_log.DRILL_ID_PREFIX); spelled out so this
# file imports on a tree that predates it and fails test by test there.
DRILL_ID_PREFIX = "DRILL-"


@pytest.fixture()
def db(tmp_path: Path) -> Path:
    path = tmp_path / "filter.db"
    init_db(path)
    for i in range(5):
        log_verdict(_row(f"{DRILL_ID_PREFIX}IX-1-{i:02d}", tech="T1048"), path)
    for i in range(3):
        log_verdict(_row(f"REAL-{i}", verdict="low_risk"), path)
    log_verdict(_row("drill-lowercase-is-real"), path)  # case-sensitive: stays visible
    return path


class TestStore:
    def test_query_hides_drills_by_default(self, db: Path) -> None:
        ids = [r["incident_id"] for r in query_verdicts(db)]
        assert ids == ["drill-lowercase-is-real", "REAL-2", "REAL-1", "REAL-0"]

    def test_query_includes_drills_on_request(self, db: Path) -> None:
        assert len(query_verdicts(db, include_drills=True)) == 9

    def test_limit_applies_after_the_filter(self, db: Path) -> None:
        """Newest rows are drills, yet a limit of 3 still returns 3 real rows."""
        for i in range(5, 10):
            log_verdict(_row(f"{DRILL_ID_PREFIX}IX-1-{i:02d}"), db)
        assert [r["incident_id"] for r in query_verdicts(db, limit=3)] == [
            "drill-lowercase-is-real",
            "REAL-2",
            "REAL-1",
        ]

    def test_stats_exclude_drills(self, db: Path) -> None:
        assert stats_verdicts(db) == {"counts": {"high_risk": 1, "low_risk": 3}, "total": 4}
        assert stats_verdicts(db, include_drills=True)["total"] == 9
        assert "T1048" not in {t["technique_id"] for t in stats_mitre(db)["techniques"]}
        assert stats_mitre(db, include_drills=True)["total_rows"] == 9


@pytest.fixture()
def http(db: Path, monkeypatch: pytest.MonkeyPatch):
    import adte.server as srv

    monkeypatch.setattr(srv, "DB_PATH", db)
    srv.app.config["TESTING"] = True
    monkeypatch.setattr(srv.limiter, "enabled", False)
    with srv.app.test_client() as client:
        yield client


class TestRoutes:
    def test_verdicts_route(self, http) -> None:
        assert http.get("/api/verdicts").get_json()["count"] == 4
        assert http.get("/api/verdicts?include_drills=true").get_json()["count"] == 9
        assert http.get("/api/verdicts?include_drills=0").get_json()["count"] == 4

    @pytest.mark.parametrize(
        "route",
        [
            "/api/verdicts",
            "/api/verdicts/export",
            "/api/stats/verdicts",
            "/api/stats/mitre",
        ],
    )
    def test_junk_flag_is_a_400(self, http, route: str) -> None:
        assert http.get(f"{route}?include_drills=yes").status_code == 400

    def test_export_and_stats_routes(self, http) -> None:
        rows = json.loads(http.get("/api/verdicts/export?format=json").get_data())["verdicts"]
        assert len(rows) == 4
        rows = json.loads(
            http.get("/api/verdicts/export?format=json&include_drills=true").get_data()
        )["verdicts"]
        assert len(rows) == 9
        assert http.get("/api/stats/verdicts").get_json()["total"] == 4
        assert http.get("/api/stats/mitre?include_drills=true").get_json()["total_rows"] == 9
