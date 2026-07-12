"""Server-level integration tests for the cluster_context signal (Phase 31).

Covers: solo golden parity for the four shipped examples (exact pins captured
pre-change on the ``pre-cluster-signal`` baseline), the boosted-vs-control
contract, end-to-end re-triage self-exclusion, and intra-batch correlation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from adte.store.audit_log import init_db

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"

# Golden pins captured on pre-change main (tag pre-cluster-signal, fresh DB,
# mock TI, no LLM key).  Solo alerts MUST keep these exact values — the
# cluster_context signal is not applicable without correlated siblings, so
# Phase 31 may not move them by a single point.
GOLDEN_SOLO = {
    "incident_account_takeover_tor_exfil.json": ("high_risk", 99, 83),
    "incident_impossible_travel_mfa_fatigue.json": ("high_risk", 99, 85),
    "incident_benign_vpn_travel.json": ("low_risk", 5, 55),
    "incident_needs_human_ambiguous.json": ("medium_risk", 43, 57),
}


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
def cluster_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Flask test client with DB_PATH redirected to an isolated tmp database."""
    db_path = tmp_path / "test_cluster_integration.db"

    import adte.server as srv

    monkeypatch.setattr(srv, "DB_PATH", db_path)
    init_db(db_path)

    srv.app.config["TESTING"] = True
    with srv.app.test_client() as client:
        yield client


def _cluster_entry(body: dict[str, Any]) -> dict[str, Any] | None:
    """Return the cluster_context rationale entry, or None."""
    return next(
        (r for r in body["rationale"] if r["signal"] == "cluster_context"), None
    )


class TestSoloGoldenParity:
    @pytest.mark.parametrize("filename", sorted(GOLDEN_SOLO))
    def test_example_solo_pins_unchanged(
        self, filename: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Each example, triaged into a FRESH DB, keeps its pre-Phase-31 pins."""
        import adte.server as srv

        db_path = tmp_path / f"golden_{filename}.db"
        monkeypatch.setattr(srv, "DB_PATH", db_path)
        init_db(db_path)
        srv.app.config["TESTING"] = True

        raw = json.loads((EXAMPLES_DIR / filename).read_text(encoding="utf-8"))
        with srv.app.test_client() as client:
            body = client.post("/api/triage", json=raw).get_json()

        verdict, risk, confidence = GOLDEN_SOLO[filename]
        assert body["verdict"] == verdict
        assert body["risk_score"] == risk
        assert body["confidence"] == confidence
        assert len(body["rationale"]) == 5
        assert _cluster_entry(body) is None


class TestBoostedVsControl:
    def test_second_correlated_alert_scores_higher_than_solo_control(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The same payload scores strictly higher with a correlated sibling."""
        import adte.server as srv

        srv.app.config["TESTING"] = True
        second = make_payload("INC-B")

        # Control: INC-B alone in a fresh DB.
        control_db = tmp_path / "control.db"
        monkeypatch.setattr(srv, "DB_PATH", control_db)
        init_db(control_db)
        with srv.app.test_client() as client:
            control = client.post("/api/triage", json=second).get_json()

        # Boosted: identical INC-B after a correlated INC-A landed.
        boosted_db = tmp_path / "boosted.db"
        monkeypatch.setattr(srv, "DB_PATH", boosted_db)
        init_db(boosted_db)
        with srv.app.test_client() as client:
            client.post("/api/triage", json=make_payload("INC-A"))
            boosted = client.post("/api/triage", json=second).get_json()

        assert boosted["risk_score"] == min(100, control["risk_score"] + 5)
        entry = _cluster_entry(boosted)
        assert entry is not None
        assert entry["score"] == 5.0
        assert "1 related alert(s)" in entry["detail"]
        assert _cluster_entry(control) is None
        assert len(boosted["rationale"]) == 6
        # The boosted member's score is what the case layer persists.
        assert boosted["case"]["alert_count"] == 2

    def test_replayed_same_incident_scores_identically(
        self, cluster_client
    ) -> None:
        """End-to-end self-exclusion: a replayed alert never boosts itself."""
        payload = make_payload("INC-REPLAY")
        first = cluster_client.post("/api/triage", json=payload).get_json()
        second = cluster_client.post("/api/triage", json=payload).get_json()
        assert first["risk_score"] == second["risk_score"]
        assert _cluster_entry(second) is None
        assert second["case"]["alert_count"] == 1  # refreshed, not duplicated

    def test_third_alert_sees_two_siblings(self, cluster_client) -> None:
        """Volume ramp is visible end-to-end: 2 siblings → 8 points."""
        cluster_client.post("/api/triage", json=make_payload("INC-1"))
        cluster_client.post("/api/triage", json=make_payload("INC-2"))
        third = cluster_client.post("/api/triage", json=make_payload("INC-3")).get_json()
        entry = _cluster_entry(third)
        assert entry is not None
        assert entry["score"] == 8.0
        assert "2 related alert(s)" in entry["detail"]


class TestBatchIntraCorrelation:
    def test_batch_second_element_boosted_by_first(self, cluster_client) -> None:
        """Element N's peek sees elements 1..N-1 (batch order matters)."""
        batch = {
            "alerts": [
                make_payload("INC-BATCH-1"),
                make_payload("INC-BATCH-2"),
                make_payload("INC-BATCH-3"),
            ]
        }
        body = cluster_client.post("/api/triage/batch", json=batch).get_json()
        assert body["succeeded"] == 3
        results = {r["index"]: r for r in body["results"]}

        assert _cluster_entry(results[0]) is None          # nothing before it
        first_entry = _cluster_entry(results[1])
        assert first_entry is not None and first_entry["score"] == 5.0
        second_entry = _cluster_entry(results[2])
        assert second_entry is not None and second_entry["score"] == 8.0
        # Ascending scores for identical payloads.
        assert (
            results[0]["risk_score"]
            < results[1]["risk_score"]
            < results[2]["risk_score"]
        )
        # All three landed in one case.
        assert len(body["cases"]) == 1
        assert body["cases"][0]["member_indices"] == [0, 1, 2]

    def test_uncorrelated_batch_elements_unboosted(self, cluster_client) -> None:
        """Distinct users + distinct IPs → no cross-boost inside the batch."""
        batch = {
            "alerts": [
                make_payload("INC-U1", user="u1@contoso.com", ip="198.51.100.1"),
                make_payload("INC-U2", user="u2@contoso.com", ip="198.51.100.2"),
            ]
        }
        body = cluster_client.post("/api/triage/batch", json=batch).get_json()
        assert body["succeeded"] == 2
        for r in body["results"]:
            assert _cluster_entry(r) is None
        assert r["risk_score"] == body["results"][0]["risk_score"]


class TestFailOpen:
    def test_unavailable_context_degrades_to_solo(
        self, cluster_client, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No context (peek fail-open returns None) → solo scoring, 200.

        peek_correlation_context never raises (its own fail-open contract is
        covered in test_peek_correlation); the route-level guarantee is that
        a None context yields a normal five-signal triage.
        """
        import adte.server as srv

        monkeypatch.setattr(srv, "peek_correlation_context", lambda *a, **k: None)
        resp = cluster_client.post(
            "/api/triage", json=make_payload("INC-FAILOPEN")
        )
        assert resp.status_code == 200
        assert _cluster_entry(resp.get_json()) is None
