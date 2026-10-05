"""Reserved addresses never reach a live threat-intel provider.

RFC 5737 documentation addresses (the three TEST-NETs) answer from the
deterministic mock in every mode, so the bundled examples that use them score
the same with or without API keys.  RFC 6598 shared address space
(100.64.0.0/10) is never sent to a provider either; with live keys it gets a
neutral answer rather than a synthetic label, because real CGNAT and overlay
hosts use it.  Also covers the blank-key rule: a key variable that exists but
is empty or whitespace must not switch the aggregator into live mode, and
``/api/config`` must report it as unset.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import adte.intel.aggregator as agg_mod
from adte.intel._mock import _mock_lookup
from adte.intel.aggregator import ThreatIntelAggregator, _DailyQuota, _TTLCache
from adte.models import ThreatIntelResult
from adte.store.audit_log import init_db

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"

# First, last and an inner address of each documentation block.
DOCUMENTATION_SAMPLES = [
    "192.0.2.0", "192.0.2.7", "192.0.2.255",
    "198.51.100.0", "198.51.100.23", "198.51.100.255",  # .23: the HIGH_RISK example
    "203.0.113.0", "203.0.113.9", "203.0.113.255",
]
SHARED_SAMPLES = [
    "100.64.0.0", "100.64.0.1",          # inside the mock's proxy /16
    "100.100.20.30",                     # outside the mock's /16
    "100.127.255.254", "100.127.255.255",
]
# Just outside every block: these must still go live.
BOUNDARY_PUBLIC = [
    "192.0.1.255", "192.0.3.0",
    "198.51.99.255", "198.51.101.0",
    "203.0.112.255", "203.0.114.0",
    "100.63.255.255", "100.128.0.0",
]


class _BenignClient:
    """Live-provider stand-in that counts calls and calls every IP clean."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def check(self, ip: str) -> ThreatIntelResult:
        self.calls.append(ip)
        return ThreatIntelResult(
            ip=ip,
            is_malicious=False,
            confidence=0.0,
            source="stub-live",
            tags=[],
            queried_at=datetime.now(timezone.utc),
        )


def _live(client: _BenignClient, limit: int = 1000) -> tuple[ThreatIntelAggregator, _DailyQuota]:
    """Hand-build a live-mode aggregator around one stub client."""
    quota = _DailyQuota(limit=limit)
    agg = ThreatIntelAggregator.__new__(ThreatIntelAggregator)
    agg._use_mock = False
    agg._clients = [client]
    agg._quotas = [quota]
    agg._cache = _TTLCache()
    return agg, quota


class TestDocumentationAddresses:
    @pytest.mark.parametrize("ip", DOCUMENTATION_SAMPLES)
    def test_live_mode_makes_no_client_call(self, ip: str) -> None:
        """A TEST-NET address is answered without calling any provider."""
        client = _BenignClient()
        agg, _ = _live(client)
        agg.check(ip)
        assert client.calls == []

    @pytest.mark.parametrize("ip", DOCUMENTATION_SAMPLES)
    def test_live_mode_answers_from_the_mock(self, ip: str) -> None:
        """The live-mode answer equals the deterministic mock's."""
        agg, _ = _live(_BenignClient())
        got, want = agg.check(ip), _mock_lookup(ip)
        assert (got.is_malicious, got.confidence, got.source, got.tags) == (
            want.is_malicious, want.confidence, want.source, want.tags,
        )

    def test_mock_mode_unchanged(self) -> None:
        """Keyless mode still answers TEST-NET addresses from the mock."""
        agg = ThreatIntelAggregator()
        assert agg.check("198.51.100.23").source == "synthetic-c2-feed"


class TestSharedAddressSpace:
    @pytest.mark.parametrize("ip", SHARED_SAMPLES)
    def test_live_mode_makes_no_client_call(self, ip: str) -> None:
        """RFC 6598 addresses are never sent to a provider."""
        client = _BenignClient()
        agg, _ = _live(client)
        agg.check(ip)
        assert client.calls == []

    @pytest.mark.parametrize("ip", SHARED_SAMPLES)
    def test_live_mode_answers_neutrally_not_with_a_synthetic_label(self, ip: str) -> None:
        """Real CGNAT/overlay hosts live here: no made-up reputation in live mode."""
        agg, _ = _live(_BenignClient())
        got = agg.check(ip)
        assert (got.is_malicious, got.confidence, got.source) == (
            False, 0.0, "shared-address-space",
        )

    def test_mock_mode_unchanged(self) -> None:
        """Keyless mode answers them from the mock, exactly as before."""
        agg = ThreatIntelAggregator()
        assert agg.check("100.64.0.1").source == "synthetic-proxy-feed"
        assert agg.check("100.100.20.30").source == "synthetic-no-match"


class TestReservedBookkeeping:
    def test_spends_no_quota(self) -> None:
        """Reserved lookups never consume a provider's daily budget."""
        agg, quota = _live(_BenignClient(), limit=1)
        for ip in DOCUMENTATION_SAMPLES + SHARED_SAMPLES:
            agg.check(ip)
        assert quota.try_acquire() is True  # the single slot is still unused

    def test_not_cached(self) -> None:
        """Reserved results stay out of the shared cache (no eviction pressure)."""
        agg, _ = _live(_BenignClient())
        for ip in DOCUMENTATION_SAMPLES + SHARED_SAMPLES:
            agg.check(ip)
        assert all(agg._cache.get(ip) is None for ip in DOCUMENTATION_SAMPLES + SHARED_SAMPLES)

    @pytest.mark.parametrize("ip", BOUNDARY_PUBLIC)
    def test_neighbouring_public_ips_still_go_live(self, ip: str) -> None:
        """The short-circuit covers the reserved blocks exactly, no wider."""
        client = _BenignClient()
        agg, _ = _live(client)
        agg.check(ip)
        assert client.calls == [ip]


class TestBlankKeys:
    @pytest.mark.parametrize("blank", ["", "   "])
    def test_blank_variables_mean_mock_mode(
        self, blank: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Variables that exist but are blank do not switch on live mode."""
        for name in ("ADTE_ABUSEIPDB_KEY", "ADTE_VT_API_KEY", "ADTE_OTX_KEY"):
            monkeypatch.setenv(name, blank)
        agg = ThreatIntelAggregator.from_env()
        assert agg._use_mock is True
        assert agg._clients == []

    def test_one_real_key_means_live_mode(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A non-blank key still enables live mode (constructing makes no call)."""
        monkeypatch.setenv("ADTE_ABUSEIPDB_KEY", "test-key-not-real")
        monkeypatch.setenv("ADTE_VT_API_KEY", "")
        monkeypatch.delenv("ADTE_OTX_KEY", raising=False)
        agg = ThreatIntelAggregator.from_env()
        assert agg._use_mock is False
        assert agg._vt_client is None  # the blank VT key is not configured

    def test_env_key_strips(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Surrounding whitespace is stripped from a real key."""
        monkeypatch.setenv("ADTE_OTX_KEY", "  abc  ")
        assert agg_mod.env_key("ADTE_OTX_KEY") == "abc"

    def test_config_reports_a_blank_key_as_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """/api/config agrees with the aggregator: whitespace is not a key."""
        import adte.server as srv

        monkeypatch.setenv("ADTE_VT_API_KEY", "   ")
        monkeypatch.setenv("ADTE_OTX_KEY", "  0123456789abcdef  ")
        srv.app.config["TESTING"] = True
        with srv.app.test_client() as http:
            keys = http.get("/api/config").get_json()["intel_keys"]
        assert keys["virustotal"] == ""
        assert keys["otx"] == "0123****cdef"


class TestExampleScoresWithLiveKeys:
    def test_high_risk_example_keeps_99_85_when_the_feed_calls_its_public_ip_clean(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With live keys, the HIGH_RISK example's attacker IP stays on the mock.

        198.51.100.23 is a TEST-NET address that a live provider calls clean,
        which used to drop the example to 79.  Here the stub feed also calls
        the example's one real public IP clean, so the full 99/85 pin holds;
        a real feed that flagged that IP above 0.95 could move the confidence,
        never the 99.
        """
        import adte.intel.threat_intel as ti
        import adte.server as srv

        client = _BenignClient()
        agg, _ = _live(client)
        monkeypatch.setattr(ti, "_aggregator", agg)
        db_path = tmp_path / "live_mode_example.db"
        monkeypatch.setattr(srv, "DB_PATH", db_path)
        init_db(db_path)
        srv.app.config["TESTING"] = True

        raw = json.loads(
            (EXAMPLES_DIR / "incident_impossible_travel_mfa_fatigue.json").read_text(
                encoding="utf-8"
            )
        )
        with srv.app.test_client() as http:
            body = http.post("/api/triage", json=raw).get_json()

        assert (body["verdict"], body["risk_score"], body["confidence"]) == (
            "high_risk", 99, 85,
        )
        assert "198.51.100.23" not in client.calls
        assert client.calls  # the real public IP did go live
