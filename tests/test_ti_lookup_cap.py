"""Per-alert cap on live threat-intel lookups.

With live keys, every distinct public IP in an alert costs one call per
provider against a shared daily quota, and the lookups run one after another
on the request's thread.  Without a cap, one request listing hundreds of
public IPs spends the day's quota and holds a server thread for minutes.
``threat_intel.lookup_budget`` caps live calls per alert; the routes that
run the engine enter it around ``enrich()``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from adte.intel.aggregator import ThreatIntelAggregator, _DailyQuota, _TTLCache
from adte.models import ThreatIntelResult
from adte.store.audit_log import init_db

PUBLIC_IPS = [f"1.2.3.{n}" for n in range(1, 31)]  # 30 distinct, non-reserved


class _CountingClient:
    """Live-provider stand-in that records every IP it is asked about."""

    def __init__(self, flagged: frozenset[str] = frozenset()) -> None:
        self.calls: list[str] = []
        self.flagged = flagged

    def check(self, ip: str) -> ThreatIntelResult:
        self.calls.append(ip)
        bad = ip in self.flagged
        return ThreatIntelResult(
            ip=ip, is_malicious=bad, confidence=0.9 if bad else 0.0, source="stub-live",
            tags=["flagged"] if bad else [], queried_at=datetime.now(timezone.utc),
        )


@pytest.fixture()
def live(monkeypatch: pytest.MonkeyPatch) -> _CountingClient:
    """Install a live-mode aggregator with one counting client.

    The client flags 1.2.3.26, the newest IP of a 26-IP alert built by
    ``_many_ip_incident(…, PUBLIC_IPS[:26])``.
    """
    import adte.intel.threat_intel as ti

    client = _CountingClient(flagged=frozenset({"1.2.3.26"}))
    agg = ThreatIntelAggregator.__new__(ThreatIntelAggregator)
    agg._use_mock = False
    agg._clients = [client]
    agg._quotas = [_DailyQuota(limit=10_000)]
    agg._cache = _TTLCache()
    monkeypatch.setattr(ti, "_aggregator", agg)
    return client


class TestLookupBudget:
    def test_caps_live_calls(self, live: _CountingClient) -> None:
        """Past the budget, IPs get a neutral lookup-cap result, no call."""
        from adte.intel.threat_intel import check_threat_intel, lookup_budget

        with lookup_budget(3):
            results = [check_threat_intel(ip) for ip in PUBLIC_IPS[:5]]
        assert live.calls == PUBLIC_IPS[:3]
        assert [r.source for r in results[3:]] == ["lookup-cap", "lookup-cap"]
        assert not any(r.is_malicious for r in results[3:])

    def test_free_lookups_are_not_charged(self, live: _CountingClient) -> None:
        """Documentation, private and shared-address IPs cost no budget."""
        from adte.intel.threat_intel import check_threat_intel, lookup_budget

        with lookup_budget(1):
            for ip in ("198.51.100.7", "10.0.0.1", "100.100.1.1"):
                check_threat_intel(ip)
            check_threat_intel("1.2.3.4")
            capped = check_threat_intel("5.6.7.8")
        assert live.calls == ["1.2.3.4"]
        assert capped.source == "lookup-cap"

    def test_cached_ip_is_not_charged(self, live: _CountingClient) -> None:
        """An IP already in the cache costs no budget."""
        from adte.intel.threat_intel import check_threat_intel, lookup_budget

        check_threat_intel("1.2.3.4")  # outside any budget: cached
        with lookup_budget(1):
            check_threat_intel("1.2.3.4")
            check_threat_intel("5.6.7.8")
        assert live.calls == ["1.2.3.4", "5.6.7.8"]

    def test_no_budget_means_uncapped(self, live: _CountingClient) -> None:
        """Outside a budget block (CLI, /api/intel) nothing is capped."""
        from adte.intel.threat_intel import check_threat_intel

        for ip in PUBLIC_IPS:
            check_threat_intel(ip)
        assert live.calls == PUBLIC_IPS

    def test_budget_restored_after_block(self, live: _CountingClient) -> None:
        """Leaving a block restores the outer budget, including 'none'."""
        from adte.intel.threat_intel import _lookup_budget, lookup_budget

        assert _lookup_budget.get() is None
        with lookup_budget(5):
            with lookup_budget(1):
                assert _lookup_budget.get()[0] == 1
            assert _lookup_budget.get()[0] == 5
        assert _lookup_budget.get() is None

    def test_cap_is_logged_once_per_alert(
        self, live: _CountingClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Operators see the cap fire, but a huge alert cannot flood the log."""
        from adte.intel.threat_intel import check_threat_intel, lookup_budget

        with caplog.at_level("INFO", logger="adte.intel.threat_intel"):
            with lookup_budget(1):
                for ip in PUBLIC_IPS[:10]:
                    check_threat_intel(ip)
        assert sum("lookup cap reached" in r.message for r in caplog.records) == 1

    def test_mock_mode_never_capped(self) -> None:
        """Keyless mode makes no live calls, so nothing is ever capped."""
        from adte.intel.threat_intel import check_threat_intel, lookup_budget

        with lookup_budget(0):
            sources = {check_threat_intel(ip).source for ip in PUBLIC_IPS}
        assert "lookup-cap" not in sources

    def test_needs_live_lookup(self, live: _CountingClient) -> None:
        """Only an uncached public IP in live mode needs a provider call."""
        import adte.intel.threat_intel as ti

        agg = ti._aggregator
        assert agg.needs_live_lookup("1.2.3.4") is True
        for free in ("10.1.2.3", "192.0.2.10", "100.64.5.5"):
            assert agg.needs_live_lookup(free) is False
        agg.check("1.2.3.4")
        assert agg.needs_live_lookup("1.2.3.4") is False


def _many_ip_incident(incident_id: str, ips: list[str]) -> dict[str, Any]:
    """One alert with one authentication event per IP."""
    user = "cap.test@corp.example"
    return {
        "incident_id": incident_id,
        "user": user,
        "source": "generic",
        "events": [
            {
                "user_principal_name": user,
                "ip_address": ip,
                "type": "authentication",
                "timestamp": f"2026-04-01T10:{i % 60:02d}:00Z",
                "app_display_name": "Microsoft Teams",
            }
            for i, ip in enumerate(ips)
        ],
    }


@pytest.fixture()
def http(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Flask test client on an isolated audit DB."""
    import adte.server as srv

    db_path = tmp_path / "cap.db"
    monkeypatch.setattr(srv, "DB_PATH", db_path)
    init_db(db_path)
    srv.app.config["TESTING"] = True
    with srv.app.test_client() as client:
        yield client


class TestRoutesApplyTheCap:
    def test_triage_looks_up_at_most_25(self, live: _CountingClient, http) -> None:
        """/api/triage: a 30-IP alert makes 25 live calls; 5 are marked capped."""
        body = http.post("/api/triage", json=_many_ip_incident("CAP-1", PUBLIC_IPS)).get_json()
        assert len(live.calls) == 25
        sources = [v["source"] for v in body["evidence"]["threat_intel"].values()]
        assert sources.count("lookup-cap") == 5

    def test_batch_caps_each_alert_separately(self, live: _CountingClient, http) -> None:
        """/api/triage/batch: the budget is per alert, not per request."""
        other = [f"5.6.7.{n}" for n in range(1, 31)]
        resp = http.post("/api/triage/batch", json=[
            _many_ip_incident("CAP-2", PUBLIC_IPS),
            _many_ip_incident("CAP-3", other),
        ])
        assert resp.get_json()["succeeded"] == 2
        assert len(live.calls) == 50

    def test_newest_ips_are_looked_up_first(self, live: _CountingClient, http) -> None:
        """The cap drops the oldest IPs, never the newest (usually decisive) ones.

        Events are stored oldest first, so without the newest-first prewarm the
        26th IP, the only bad one, would be the one left unchecked.
        """
        body = http.post(
            "/api/triage", json=_many_ip_incident("CAP-4", PUBLIC_IPS[:26])
        ).get_json()
        intel = body["evidence"]["threat_intel"]
        assert intel["1.2.3.26"]["is_malicious"] is True
        assert intel["1.2.3.1"]["source"] == "lookup-cap"
        ip_rep = next(r for r in body["rationale"] if r["signal"] == "ip_reputation")
        assert ip_rep["score"] > 0
        assert len(live.calls) == 25

    def test_coverage_note_only_when_capped(self, live: _CountingClient, http) -> None:
        """A capped alert says which IPs were skipped; others carry no note."""
        capped = http.post("/api/triage", json=_many_ip_incident("CAP-5", PUBLIC_IPS)).get_json()
        assert capped["threat_intel_coverage"]["complete"] is False
        assert capped["threat_intel_coverage"]["not_looked_up"] == sorted(PUBLIC_IPS[:5])
        small = http.post(
            "/api/triage", json=_many_ip_incident("CAP-6", [f"9.9.9.{n}" for n in range(1, 6)])
        ).get_json()
        assert "threat_intel_coverage" not in small
