"""Incident Drill routes, the DRILL- namespace guard, and the debrief/report.

/api/drill/run triages a generated run through the batch pipeline into a
per-request case store and logs DRILL- audit rows; /api/drill/report
regenerates and re-scores server-side without logging.  No caller may use
the DRILL- prefix, and drill dispositions never reach /api/feedback.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest

from adte.store.audit_log import init_db, query_feedback, query_verdicts

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture()
def srv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The server module on an isolated audit DB, limiter off."""
    import adte.server as server

    db_path = tmp_path / "drill_routes.db"
    monkeypatch.setattr(server, "DB_PATH", db_path)
    init_db(db_path)
    server.app.config["TESTING"] = True
    monkeypatch.setattr(server.limiter, "enabled", False)
    return server


@pytest.fixture()
def http(srv):
    with srv.app.test_client() as client:
        yield client


def _run(
    http, scenario: str = "identity-exfil", seed: int | None = 42, noise: str = "medium"
) -> dict[str, Any]:
    body: dict[str, Any] = {"scenario": scenario, "noise": noise}
    if seed is not None:
        body["seed"] = seed
    resp = http.post("/api/drill/run", json=body)
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()


def _verdicts(body: dict[str, Any]) -> list[tuple[Any, ...]]:
    """Replay-comparable view: case IDs are random, scores are not."""
    return [
        (
            r["evidence"]["incident_id"],
            r["verdict"],
            r["risk_score"],
            r["confidence"],
            tuple(r["mitre_techniques"]),
        )
        for r in body["results"]
    ]


class TestScenarios:
    def test_public_catalogue(self, http) -> None:
        body = http.get("/api/drill/scenarios").get_json()
        assert [s["id"] for s in body["scenarios"]] == [
            "password-spray",
            "identity-exfil",
            "malware-spread",
        ]
        assert all(
            set(s) == {"id", "name", "summary", "difficulty", "chain", "techniques"}
            for s in body["scenarios"]
        )
        assert body["max_alerts"] == 25 and set(body["noise_levels"]) == {"low", "medium", "high"}


class TestRun:
    def test_run_triages_every_alert_and_logs_hidden_rows(self, srv, http) -> None:
        body = _run(http)
        from adte.simulation.generator import generate

        assert body["count"] == len(generate("identity-exfil", 42).incidents)
        assert body["succeeded"] == body["count"] and body["failed"] == 0
        assert len(body["alerts"]) == body["count"]
        assert body["cases"] and body["cases_are_run_local"] is True
        drill_rows = query_verdicts(srv.DB_PATH, include_drills=True)
        assert len(drill_rows) == body["count"]
        assert all(r["incident_id"].startswith("DRILL-") for r in drill_rows)
        assert query_verdicts(srv.DB_PATH) == []  # hidden by default

    def test_run_never_touches_the_case_store(self, http) -> None:
        _run(http)
        assert http.get("/api/cases").get_json()["count"] == 0

    def test_same_seed_same_verdicts(self, http) -> None:
        assert _verdicts(_run(http, seed=7)) == _verdicts(_run(http, seed=7))

    def test_random_seed_is_returned_and_replays(self, http) -> None:
        first = _run(http, seed=None)
        assert 0 <= first["seed"] <= 2**31 - 1
        assert _verdicts(_run(http, seed=first["seed"])) == _verdicts(first)

    @pytest.mark.parametrize("scenario", ["password-spray", "identity-exfil", "malware-spread"])
    def test_no_ground_truth_in_the_response(self, http, scenario: str) -> None:
        """Nothing from the answer key reaches the analyst before the report."""
        from adte.simulation.generator import generate

        body = _run(http, scenario=scenario)
        text = str(body)
        for stage in generate(scenario, 42).truth:
            assert stage.title not in text and stage.why not in text
        for key in ("truth", "expected_call", "label"):
            assert all(key not in r for r in body["results"])

    @pytest.mark.parametrize(
        "payload, status",
        [
            ({"scenario": "nope"}, 422),
            ({"scenario": "identity-exfil", "extra": 1}, 422),
            ({"scenario": "identity-exfil", "seed": -1}, 422),
            ({"scenario": "identity-exfil", "seed": 2**31}, 422),
            ({"scenario": "identity-exfil", "noise": "extreme"}, 422),
            ([1, 2], 422),
        ],
    )
    def test_bad_bodies(self, http, payload: Any, status: int) -> None:
        resp = http.post("/api/drill/run", json=payload)
        assert resp.status_code == status
        assert "error" in resp.get_json()

    def test_non_json(self, http) -> None:
        assert http.post("/api/drill/run", data="x").status_code == 415


def _perfect_calls(scenario: str, seed: int, noise: str = "medium") -> list[dict[str, Any]]:
    from adte.simulation.generator import generate

    return [
        {
            "index": i,
            "call": st.expected_call,
            "escalate": st.label == "malicious",
            "rationale": "ok",
        }
        for i, st in enumerate(generate(scenario, seed, noise).truth)
    ]


class TestReport:
    def test_report_rescores_without_logging(self, srv, http) -> None:
        run = _run(http)
        rows_before = len(query_verdicts(srv.DB_PATH, include_drills=True))
        resp = http.post(
            "/api/drill/report",
            json={
                "scenario": "identity-exfil",
                "seed": 42,
                "noise": "medium",
                "dispositions": _perfect_calls("identity-exfil", 42),
            },
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert len(query_verdicts(srv.DB_PATH, include_drills=True)) == rows_before
        adte_calls = [
            (r["incident_id"], r["adte_verdict"], r["adte_risk"])
            for r in body["report"]["verdicts_vs_calls"]
        ]
        assert adte_calls == [
            (r["evidence"]["incident_id"], r["verdict"], r["risk_score"]) for r in run["results"]
        ]

    def test_perfect_analyst_grades_perfectly(self, http) -> None:
        body = http.post(
            "/api/drill/report",
            json={
                "scenario": "malware-spread",
                "seed": 7,
                "noise": "high",
                "dispositions": _perfect_calls("malware-spread", 7, "high"),
            },
        ).get_json()
        s = body["debrief"]["summary"]
        assert s["accuracy"] == 1.0 and s["exact"] == s["dispositioned"] == s["alerts"]
        assert s["missed_malicious"] == s["benign_escalated"] == s["undispositioned"] == []
        assert body["debrief"]["kill_chain"]["detected"] is True
        assert body["report"]["banner"] == "Synthetic drill: not a real incident."

    def test_empty_calls_reveal_misses(self, http) -> None:
        body = http.post(
            "/api/drill/report",
            json={
                "scenario": "password-spray",
                "seed": 1,
                "noise": "low",
                "dispositions": [],
            },
        ).get_json()
        s = body["debrief"]["summary"]
        assert s["accuracy"] is None and s["dispositioned"] == 0
        assert len(s["missed_malicious"]) == s["malicious"]
        assert body["report"]["summary"] == "The analyst confirmed no alerts as malicious."

    def test_spray_debrief_flags_low_scored_attack_alerts(self, http) -> None:
        """Per-target spray alerts score low alone; the debrief says so."""
        body = http.post(
            "/api/drill/report",
            json={
                "scenario": "password-spray",
                "seed": 7,
                "noise": "medium",
                "dispositions": [],
            },
        ).get_json()
        assert body["debrief"]["summary"]["adte_low_on_malicious"]
        assert any("low_risk on their own" in f for f in body["debrief"]["findings"])

    @pytest.mark.parametrize(
        "dispositions, notes",
        [
            ([{"index": i, "call": "true_positive"} for i in range(26)], ""),
            ([{"index": 0, "call": "true_positive"}, {"index": 0, "call": "benign_positive"}], ""),
            ([{"index": 24, "call": "true_positive"}], ""),
            ([{"index": 0, "call": "maybe"}], ""),
            ([{"index": 0, "call": "true_positive", "rationale": "x" * 281}], ""),
            ([], "n" * 2001),
        ],
    )
    def test_rejects_bad_reports(self, http, dispositions: list[Any], notes: str) -> None:
        resp = http.post(
            "/api/drill/report",
            json={
                "scenario": "identity-exfil",
                "seed": 42,
                "noise": "medium",
                "dispositions": dispositions,
                "notes": notes,
            },
        )
        assert resp.status_code == 422

    def test_report_never_writes_feedback_or_the_fp_registry(self, srv, http) -> None:
        """FP calls with IPs must not promote drill IPs into the registry."""

        def digest(p: Path) -> str | None:
            return hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None

        default_registry = ROOT / "examples" / "fp_registry.yaml"
        before = (digest(default_registry), digest(Path(srv.REGISTRY_PATH)))
        calls = [{"index": i, "call": "false_positive"} for i in range(9)]
        assert (
            http.post(
                "/api/drill/report",
                json={
                    "scenario": "identity-exfil",
                    "seed": 42,
                    "noise": "medium",
                    "dispositions": calls,
                },
            ).status_code
            == 200
        )
        assert query_feedback(srv.DB_PATH) == []
        assert (digest(default_registry), digest(Path(srv.REGISTRY_PATH))) == before

    def test_markdown_confines_analyst_text(self, http) -> None:
        body = http.post(
            "/api/drill/report",
            json={
                "scenario": "identity-exfil",
                "seed": 42,
                "noise": "medium",
                "dispositions": [{"index": 0, "call": "true_positive", "rationale": "a|b\nc"}],
                "notes": "# not a heading\nsecond line",
            },
        ).get_json()
        md = body["report_markdown"]
        assert "a\\|b c" in md
        assert "\n# not a heading" not in md and "\n    # not a heading" in md


def _one(incident_id: str) -> dict[str, Any]:
    user = "guard@corp.example"
    return {
        "incident_id": incident_id,
        "user": user,
        "events": [
            {
                "user_principal_name": user,
                "ip_address": "1.2.3.4",
                "type": "authentication",
                "timestamp": "2026-04-01T10:00:00Z",
            }
        ],
    }


class TestDrillNamespaceIsReserved:
    @pytest.mark.parametrize("incident_id", ["DRILL-X-1", "drill-x", "Drill-1"])
    def test_triage_rejects_and_logs_nothing(self, srv, http, incident_id: str) -> None:
        resp = http.post("/api/triage", json=_one(incident_id))
        assert resp.status_code == 422
        assert query_verdicts(srv.DB_PATH, include_drills=True) == []

    def test_batch_isolates_the_reserved_element(self, srv, http) -> None:
        body = http.post("/api/triage/batch", json=[_one("DRILL-1"), _one("REAL-1")]).get_json()
        assert [r["ok"] for r in body["results"]] == [False, True]
        assert "reserved" in body["results"][0]["error"]
        assert [r["incident_id"] for r in query_verdicts(srv.DB_PATH, include_drills=True)] == [
            "REAL-1"
        ]

    def test_feedback_rejects_before_writing(self, srv, http) -> None:
        resp = http.post(
            "/api/feedback",
            json={
                "incident_id": "DRILL-IX-42-01",
                "label": "fp",
                "ip": "198.51.100.9",
            },
        )
        assert resp.status_code == 422
        assert query_feedback(srv.DB_PATH) == []

    def test_ordinary_ids_still_work(self, http) -> None:
        assert http.post("/api/triage", json=_one("DRILLING-RIG-7")).status_code == 200


class TestRateLimits:
    def test_run_allows_three_per_minute(self, srv, http, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(srv.limiter, "enabled", True)
        srv.limiter.reset()
        try:
            codes = [
                http.post(
                    "/api/drill/run", json={"scenario": "identity-exfil", "seed": 1, "noise": "low"}
                ).status_code
                for _ in range(4)
            ]
        finally:
            srv.limiter.reset()
        assert codes == [200, 200, 200, 429]
