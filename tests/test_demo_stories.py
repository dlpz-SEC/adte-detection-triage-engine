"""Tests for A4 (mitre_details output) and A5 (demo ATT&CK stories).

Each demo example, triaged through the real route, must yield the technique
set its scenario narrates — and mitre_details must carry name/tactic/source
for every ID in mitre_techniques.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from adte.store.audit_log import init_db


@pytest.fixture()
def demo_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Flask test client with DB_PATH redirected to an isolated tmp database."""
    db_path = tmp_path / "test_demo_stories.db"

    import adte.server as srv

    monkeypatch.setattr(srv, "DB_PATH", db_path)
    init_db(db_path)

    srv.app.config["TESTING"] = True
    with srv.app.test_client() as client:
        yield client


def _triage_example(client, key: str) -> dict[str, Any]:
    """Load one example via /api/examples and run it through /api/triage."""
    examples = client.get("/api/examples").get_json()
    resp = client.post("/api/triage", json=examples[key])
    assert resp.status_code == 200
    return resp.get_json()


class TestDemoStories:
    """Each demo example tells its documented ATT&CK story."""

    def test_critical_story_includes_tor_and_exfil(self, demo_client) -> None:
        """Account takeover → Tor proxy → exfil: signals + native tags unite."""
        body = _triage_example(demo_client, "critical")
        techniques = body["mitre_techniques"]
        # Signal-derived chapters (valid cloud account, MFA fatigue, C2).
        for tid in ("T1078.004", "T1621", "T1071"):
            assert tid in techniques
        # Native-tagged chapters (Tor multi-hop proxy, automated exfiltration).
        assert "T1090.003" in techniques
        assert "T1020" in techniques

    def test_high_risk_story(self, demo_client) -> None:
        """Impossible travel + MFA fatigue: valid-accounts + T1621 chapters."""
        techniques = _triage_example(demo_client, "high_risk")["mitre_techniques"]
        assert "T1078.004" in techniques
        assert "T1621" in techniques

    def test_low_risk_story_stays_minimal(self, demo_client) -> None:
        """The benign VPN example must NOT accumulate attack-chain techniques."""
        techniques = _triage_example(demo_client, "low_risk")["mitre_techniques"]
        assert "T1090.003" not in techniques
        assert "T1020" not in techniques
        assert "T1621" not in techniques


class TestMitreDetails:
    """mitre_details mirrors mitre_techniques with name/tactic/source."""

    def test_details_cover_every_technique(self, demo_client) -> None:
        """One detail object per ID, same order, well-formed fields."""
        body = _triage_example(demo_client, "critical")
        details = body["mitre_details"]
        assert [d["id"] for d in details] == body["mitre_techniques"]
        for d in details:
            assert set(d) == {"id", "name", "tactic", "source"}
            assert d["source"] in ("signal", "native", "rule_text")

    def test_native_tags_labeled_native(self, demo_client) -> None:
        """The Tor/exfil chapters are attributed to the log source."""
        details = _triage_example(demo_client, "critical")["mitre_details"]
        by_id = {d["id"]: d for d in details}
        assert by_id["T1090.003"]["source"] == "native"
        assert by_id["T1020"]["source"] == "native"
        # Mapped IDs resolve to their ATT&CK names.
        assert by_id["T1090.003"]["name"] == "Proxy: Multi-hop Proxy"
        assert by_id["T1020"]["tactic"] == "Exfiltration"

    def test_signal_ids_labeled_signal(self, demo_client) -> None:
        """Signal-derived IDs carry source='signal'."""
        details = _triage_example(demo_client, "high_risk")["mitre_details"]
        by_id = {d["id"]: d for d in details}
        assert by_id["T1621"]["source"] == "signal"
        assert by_id["T1621"]["name"].startswith("Multi-Factor Authentication")
