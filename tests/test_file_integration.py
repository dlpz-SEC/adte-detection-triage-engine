"""Server-level integration tests for the Wazuh malware pipeline (Phase 32).

Exercises the full /api/triage path on realistic raw Wazuh alerts (rules
554/87105/553), the file_reputation signal end-to-end, hash-based case
correlation across hosts (campaign detection), and batch triage — plus a
solo golden-parity guard proving the four bundled examples gain no file
signal or file evidence.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from adte.store.audit_log import init_db

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"

_EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
_EICAR_SHA1 = "3395856ce81f2b7382dee72602f798b642f14140"
_EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"


@pytest.fixture()
def file_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Flask test client with DB_PATH redirected to an isolated tmp database."""
    import adte.server as srv

    db_path = tmp_path / "test_file_integration.db"
    monkeypatch.setattr(srv, "DB_PATH", db_path)
    init_db(db_path)
    srv.app.config["TESTING"] = True
    with srv.app.test_client() as client:
        yield client


def _vt_conviction_alert(
    *,
    alert_id: str = "1720000002.87105",
    agent_ip: str = "192.168.1.77",
    agent_name: str = "ubuntu-agent",
    agent_id: str = "003",
) -> dict[str, Any]:
    """Raw Wazuh rule-87105 VirusTotal conviction alert (embedded verdict)."""
    return {
        "id": alert_id,
        "@timestamp": "2026-07-12T14:03:12.000Z",
        "rule": {
            "id": "87105",
            "level": 12,
            "description": "VirusTotal: Alert - /tmp/malware/eicar.com - 58 engines",
            "groups": ["virustotal"],
        },
        "agent": {"id": agent_id, "name": agent_name, "ip": agent_ip},
        "data": {
            "virustotal": {
                "malicious": "1",
                "positives": "58",
                "total": "72",
                "source": {
                    "file": "/tmp/malware/eicar.com",
                    "md5": _EICAR_MD5,
                    "sha1": _EICAR_SHA1,
                },
                "permalink": "https://www.virustotal.com/gui/file/" + _EICAR_SHA256,
            }
        },
    }


def _fim_added_alert() -> dict[str, Any]:
    """Raw Wazuh rule-554 FIM alert (file added), carries sha256_after."""
    return {
        "id": "1720000000.554001",
        "@timestamp": "2026-07-12T14:03:11.000Z",
        "rule": {
            "id": "554",
            "level": 7,
            "description": "File added to the system.",
            "groups": ["ossec", "syscheck", "syscheck_entry_added"],
        },
        "agent": {"id": "003", "name": "ubuntu-agent", "ip": "192.168.1.77"},
        "syscheck": {
            "path": "/tmp/malware/eicar.com",
            "event": "added",
            "sha256_after": _EICAR_SHA256,
            "md5_after": _EICAR_MD5,
        },
    }


def _fim_deleted_alert() -> dict[str, Any]:
    """Raw Wazuh rule-553 FIM alert (active response deleted the file)."""
    return {
        "id": "1720000003.553001",
        "@timestamp": "2026-07-12T14:03:13.000Z",
        "rule": {
            "id": "553",
            "level": 7,
            "description": "File deleted.",
            "groups": ["ossec", "syscheck", "syscheck_entry_deleted"],
        },
        "agent": {"id": "003", "name": "ubuntu-agent", "ip": "192.168.1.77"},
        "syscheck": {
            "path": "/tmp/malware/eicar.com",
            "event": "deleted",
            "sha256_before": _EICAR_SHA256,
        },
    }


def _file_entry(body: dict[str, Any]) -> dict[str, Any] | None:
    """Return the file_reputation rationale entry, or None."""
    return next(
        (r for r in body["rationale"] if r["signal"] == "file_reputation"), None
    )


def _cluster_entry(body: dict[str, Any]) -> dict[str, Any] | None:
    """Return the cluster_context rationale entry, or None."""
    return next(
        (r for r in body["rationale"] if r["signal"] == "cluster_context"), None
    )


class TestSoloGoldenParity:
    @pytest.mark.parametrize(
        "filename",
        [
            "incident_account_takeover_tor_exfil.json",
            "incident_impossible_travel_mfa_fatigue.json",
            "incident_benign_vpn_travel.json",
            "incident_needs_human_ambiguous.json",
        ],
    )
    def test_examples_gain_no_file_signal(
        self, filename: str, file_client
    ) -> None:
        """The auth-only examples never register file_reputation or file evidence."""
        raw = json.loads((EXAMPLES_DIR / filename).read_text(encoding="utf-8"))
        body = file_client.post("/api/triage", json=raw).get_json()
        assert _file_entry(body) is None
        assert "files" not in body["evidence"]
        assert "file_reputation" not in body["evidence"]
        assert "quarantine_file" not in body["actions"]


class TestRawConviction:
    def test_87105_lands_high_risk(self, file_client) -> None:
        """A raw VirusTotal conviction alert triages to high_risk ≥ 73."""
        body = file_client.post(
            "/api/triage", json=_vt_conviction_alert()
        ).get_json()
        assert body["verdict"] == "high_risk"
        assert body["risk_score"] >= 73
        entry = _file_entry(body)
        assert entry is not None and entry["score"] == 40.0

    def test_87105_recommends_containment(self, file_client) -> None:
        """Malware recommendations appear (recommend-only)."""
        body = file_client.post(
            "/api/triage", json=_vt_conviction_alert()
        ).get_json()
        for action in ("quarantine_file", "hash_sweep_fleet", "isolate_host"):
            assert action in body["actions"]

    def test_87105_embedded_verdict_no_lookup(self, file_client) -> None:
        """Embedded verdict → evidence.files present, no lookup section."""
        body = file_client.post(
            "/api/triage", json=_vt_conviction_alert()
        ).get_json()
        assert body["evidence"]["files"][0]["vt_positives"] == 58
        assert "file_reputation" not in body["evidence"]

    def test_87105_opens_case_with_hash_key(self, file_client) -> None:
        """The alert opens a case carrying the file hash as a correlation key."""
        body = file_client.post(
            "/api/triage", json=_vt_conviction_alert()
        ).get_json()
        assert body["case"] is not None
        assert _EICAR_SHA1 in body["case"]["correlation_keys"]["hashes"]


class TestPipelineSequence:
    def test_554_87105_553_form_one_case(self, file_client) -> None:
        """The added→convicted→deleted trio on one host is a single case."""
        file_client.post("/api/triage", json=_fim_added_alert())
        file_client.post("/api/triage", json=_vt_conviction_alert())
        last = file_client.post("/api/triage", json=_fim_deleted_alert()).get_json()
        assert last["case"]["alert_count"] == 3


class TestCrossHostCampaign:
    def test_same_hash_two_hosts_correlate(self, file_client) -> None:
        """Same malware on two hosts (different IPs) joins one case via hash."""
        first = file_client.post(
            "/api/triage", json=_vt_conviction_alert(alert_id="A-1")
        ).get_json()
        second = file_client.post(
            "/api/triage",
            json=_vt_conviction_alert(
                alert_id="B-1",
                agent_ip="10.0.0.55",
                agent_name="win-agent",
                agent_id="007",
            ),
        ).get_json()
        assert second["case"]["case_id"] == first["case"]["case_id"]
        assert second["case"]["alert_count"] == 2

    def test_second_host_gets_cluster_boost(self, file_client) -> None:
        """The second sighting is aggravated by correlated-case context."""
        file_client.post("/api/triage", json=_vt_conviction_alert(alert_id="A-1"))
        second = file_client.post(
            "/api/triage",
            json=_vt_conviction_alert(alert_id="B-1", agent_ip="10.0.0.55"),
        ).get_json()
        assert _cluster_entry(second) is not None
        assert _file_entry(second) is not None


class TestBatchPipeline:
    def test_batch_trio_one_case(self, file_client) -> None:
        """A batch of the 554/87105/553 trio yields one case summary."""
        batch = {
            "alerts": [
                _fim_added_alert(),
                _vt_conviction_alert(),
                _fim_deleted_alert(),
            ]
        }
        body = file_client.post("/api/triage/batch", json=batch).get_json()
        assert body["succeeded"] == 3
        assert len(body["cases"]) == 1
        assert body["cases"][0]["member_indices"] == [0, 1, 2]
