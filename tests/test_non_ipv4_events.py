"""An event ip_address that is not IPv4 is a 422, not a 500.

Regression guard for the 2026-09-27 audit finding: a schema-valid incident whose
``ip_address`` was IPv6 (``2001:db8::1``) or not an IP at all reached
``check_threat_intel`` inside ``engine.enrich()``, which raises ValueError for
anything but IPv4, and /api/triage answered with its generic 500.  The triage
routes now reject such an incident at the boundary with a 422 that names the
event, before any scoring, audit write or case ingest.  The engine is untouched.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import adte.intel.threat_intel as ti
from adte.models import NormalizedIncident
from adte.store.audit_log import init_db, query_verdicts

_NON_IPV4 = ["2001:db8::1", "::ffff:198.51.100.7", "not-an-ip", "host.example.com"]


@pytest.fixture()
def triage_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Flask test client with DB_PATH redirected to an isolated tmp database."""
    import adte.server as srv

    db_path = tmp_path / "non_ipv4.db"
    monkeypatch.setattr(srv, "DB_PATH", db_path)
    init_db(db_path)
    monkeypatch.setitem(srv.app.config, "TESTING", True)
    with srv.app.test_client() as client:
        yield client


def _with_last_ip(incident: NormalizedIncident, ip: str) -> dict[str, Any]:
    """Dump the incident with its LAST event's ip_address replaced."""
    payload = incident.model_dump(mode="json")
    payload["events"][-1]["ip_address"] = ip
    return payload


class TestSingleTriage:
    """POST /api/triage."""

    @pytest.mark.parametrize("ip", _NON_IPV4)
    def test_non_ipv4_is_422_naming_the_event(
        self, triage_client, incident_false_positive: NormalizedIncident, ip: str
    ) -> None:
        """Any non-IPv4 value gets a 422 that points at the offending event."""
        import adte.server as srv

        payload = _with_last_ip(incident_false_positive, ip)
        last = len(payload["events"]) - 1
        resp = triage_client.post("/api/triage", json=payload)
        assert resp.status_code == 422, resp.get_data(as_text=True)
        error = resp.get_json()["error"]
        assert f"events[{last}]" in error
        assert "IPv4" in error
        # Rejected before the pipeline: nothing reached the audit log.
        assert query_verdicts(srv.DB_PATH) == []

    @pytest.mark.parametrize("ip", ["198.51.100.7", ""])
    def test_ipv4_and_empty_still_triage(
        self, triage_client, incident_false_positive: NormalizedIncident, ip: str
    ) -> None:
        """IPv4 and an empty ip_address (the engine skips it) still return 200."""
        resp = triage_client.post(
            "/api/triage", json=_with_last_ip(incident_false_positive, ip)
        )
        assert resp.status_code == 200, resp.get_data(as_text=True)


class TestBatchTriage:
    """POST /api/triage/batch keeps per-alert isolation."""

    def test_bad_element_fails_alone(
        self, triage_client, incident_false_positive: NormalizedIncident
    ) -> None:
        """An IPv6 element gets its own error entry; the IPv4 element still triages."""
        bad = _with_last_ip(incident_false_positive, "2001:db8::1")
        good = _with_last_ip(incident_false_positive, "198.51.100.7")
        good["incident_id"] = f"{good['incident_id']}-v4"
        resp = triage_client.post("/api/triage/batch", json=[bad, good])
        assert resp.status_code == 200
        body = resp.get_json()
        assert (body["succeeded"], body["failed"]) == (1, 1)
        first, second = body["results"]
        assert first["ok"] is False
        assert "IPv4" in first["error"]
        assert second["ok"] is True


class TestLookupIpContract:
    """One definition of a lookup-able address, shared by the route and the lookup."""

    @pytest.mark.parametrize("ip", ["198.51.100.7", "10.1.2.3", "0.0.0.0"])
    def test_ipv4_accepted(self, ip: str) -> None:
        """IPv4 addresses are lookup-able."""
        assert ti.is_lookup_ip(ip) is True

    @pytest.mark.parametrize("ip", _NON_IPV4 + ["", " 198.51.100.7"])
    def test_everything_else_rejected(self, ip: str) -> None:
        """IPv6, hostnames, empty and padded strings are not."""
        assert ti.is_lookup_ip(ip) is False

    def test_check_threat_intel_still_raises_for_ipv6(self) -> None:
        """The lookup's own contract is unchanged (/api/intel maps it to 400)."""
        with pytest.raises(ValueError, match="Invalid IPv4 address"):
            ti.check_threat_intel("2001:db8::1")
