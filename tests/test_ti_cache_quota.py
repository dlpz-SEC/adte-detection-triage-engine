"""Tests for the B1 threat-intel hardening: bounded TTL cache + daily quotas.

Covers _TTLCache expiry/eviction, _DailyQuota consumption and UTC-day reset,
quota-aware provider skipping in the aggregator, and the all-exhausted →
mock fallback with its warning log.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Any

import pytest

import adte.intel.aggregator as agg_mod
from adte.intel.aggregator import _DailyQuota, _TTLCache, ThreatIntelAggregator
from adte.models import ThreatIntelResult


def _result(ip: str, source: str = "stub") -> ThreatIntelResult:
    """Build a minimal ThreatIntelResult for cache/aggregation tests."""
    return ThreatIntelResult(
        ip=ip,
        is_malicious=False,
        confidence=0.2,
        source=source,
        tags=[],
        queried_at=datetime.now(timezone.utc),
    )


class _StubClient:
    """Fake provider client that counts calls and returns a fixed result."""

    def __init__(self, source: str = "stub") -> None:
        self.source = source
        self.calls = 0

    def check(self, ip: str) -> ThreatIntelResult:
        self.calls += 1
        return _result(ip, self.source)


def _live_aggregator(clients: list[Any], quotas: list[_DailyQuota]) -> ThreatIntelAggregator:
    """Hand-construct a live-mode aggregator with stub clients and quotas."""
    agg = ThreatIntelAggregator.__new__(ThreatIntelAggregator)
    agg._use_mock = False
    agg._clients = clients
    agg._quotas = quotas
    agg._cache = _TTLCache()
    return agg


class TestTTLCache:
    """Expiry and eviction semantics of the bounded TTL cache."""

    def test_entry_served_within_ttl(self) -> None:
        """A stored entry is returned before its TTL elapses."""
        cache = _TTLCache(ttl_seconds=60.0)
        cache["1.2.3.4"] = _result("1.2.3.4")
        assert cache.get("1.2.3.4") is not None
        assert "1.2.3.4" in cache

    def test_entry_expires_after_ttl(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """After the TTL passes, the entry is gone and its slot is freed."""
        now = {"t": 1000.0}
        monkeypatch.setattr(agg_mod.time, "monotonic", lambda: now["t"])
        cache = _TTLCache(ttl_seconds=10.0)
        cache["1.2.3.4"] = _result("1.2.3.4")
        now["t"] += 11.0
        assert cache.get("1.2.3.4") is None
        assert "1.2.3.4" not in cache
        assert len(cache) == 0

    def test_oldest_entry_evicted_at_max_size(self) -> None:
        """Insertion beyond max_size evicts the oldest entry first."""
        cache = _TTLCache(ttl_seconds=60.0, max_size=2)
        cache["ip-1"] = _result("ip-1")
        cache["ip-2"] = _result("ip-2")
        cache["ip-3"] = _result("ip-3")
        assert len(cache) == 2
        assert "ip-1" not in cache
        assert "ip-2" in cache and "ip-3" in cache

    def test_overwrite_does_not_evict(self) -> None:
        """Re-storing an existing key at capacity keeps the other entries."""
        cache = _TTLCache(ttl_seconds=60.0, max_size=2)
        cache["ip-1"] = _result("ip-1")
        cache["ip-2"] = _result("ip-2")
        cache["ip-1"] = _result("ip-1")
        assert "ip-2" in cache and len(cache) == 2


class TestDailyQuota:
    """Consumption and UTC-day reset of the per-provider budget."""

    def test_acquire_until_exhausted(self) -> None:
        """Exactly `limit` acquisitions succeed per day."""
        quota = _DailyQuota(limit=2)
        assert quota.try_acquire() is True
        assert quota.try_acquire() is True
        assert quota.try_acquire() is False

    def test_resets_on_new_utc_day(self) -> None:
        """A stale day marker resets the counter (UTC-midnight rollover)."""
        quota = _DailyQuota(limit=1)
        assert quota.try_acquire() is True
        assert quota.try_acquire() is False
        quota._day = date(2020, 1, 1)  # simulate yesterday
        assert quota.try_acquire() is True

    def test_zero_limit_disables_provider(self) -> None:
        """limit=0 never grants a slot."""
        assert _DailyQuota(limit=0).try_acquire() is False


class TestQuotaAwareAggregation:
    """The aggregator skips exhausted providers and falls back to mock."""

    def test_exhausted_provider_is_skipped(self) -> None:
        """Provider with spent quota gets no call; others still answer."""
        fresh, spent = _StubClient("fresh"), _StubClient("spent")
        q_fresh, q_spent = _DailyQuota(limit=100), _DailyQuota(limit=0)
        agg = _live_aggregator([spent, fresh], [q_spent, q_fresh])
        result = agg.check("203.0.113.10")
        assert spent.calls == 0
        assert fresh.calls == 1
        assert result.source == "fresh"

    def test_all_exhausted_falls_back_to_synthetic_with_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """No quota anywhere → synthetic fallback result + one clear warning log."""
        client = _StubClient()
        agg = _live_aggregator([client], [_DailyQuota(limit=0)])
        with caplog.at_level("WARNING", logger="adte.intel.aggregator"):
            result = agg.check("203.0.113.11")
        assert client.calls == 0
        assert result.source.startswith("synthetic")
        assert any("daily quotas exhausted" in r.message for r in caplog.records)

    def test_cache_hit_burns_no_quota(self) -> None:
        """A repeated IP is served from cache without consuming quota."""
        client = _StubClient()
        quota = _DailyQuota(limit=1)
        agg = _live_aggregator([client], [quota])
        first = agg.check("203.0.113.12")
        second = agg.check("203.0.113.12")
        assert client.calls == 1
        assert second == first

    def test_env_override_controls_limit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """ADTE_TI_QUOTA_<PROVIDER> overrides the default budget."""
        monkeypatch.setenv("ADTE_TI_QUOTA_VIRUSTOTAL", "7")
        assert agg_mod._quota_limit("VIRUSTOTAL", 500) == 7
        monkeypatch.setenv("ADTE_TI_QUOTA_VIRUSTOTAL", "not-a-number")
        assert agg_mod._quota_limit("VIRUSTOTAL", 500) == 500
