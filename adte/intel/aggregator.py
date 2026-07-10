"""Threat intelligence aggregator — combines results from multiple providers.

``ThreatIntelAggregator`` queries all configured threat intel sources and
returns a single normalised ``ThreatIntelResult``.  It is instantiated via
``from_env()`` which reads ``ADTE_ABUSEIPDB_KEY``, ``ADTE_VT_API_KEY``, and
``ADTE_OTX_KEY`` from the environment.

Fallback behaviour:
  - If no keys at all are set, the deterministic mock lookup is used.
  - If at least one key is set, only live API clients are queried.
  - If all live clients return errors, the mock lookup is used as a last
    resort and a warning is logged.
  - Private and loopback IPs are short-circuited without any API call.

NIST 800-61 Phase: Detection & Analysis — aggregates threat context from
multiple feeds to produce a single weighted enrichment signal.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import logging
import os
import threading
import time
from datetime import date, datetime, timezone

from adte.intel._mock import _mock_lookup
from adte.intel.abuseipdb import AbuseIPDBClient
from adte.intel.otx import OTXClient
from adte.intel.virustotal import VirusTotalClient
from adte.models import ThreatIntelResult

_log = logging.getLogger(__name__)

# RFC 1918 + loopback ranges — never query external APIs for these.
_PRIVATE_NETWORKS: list[ipaddress.IPv4Network] = [
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
]


def _is_private(ip: str) -> bool:
    """Return True if *ip* belongs to a private or loopback range.

    Args:
        ip: Pre-validated IPv4 address string.

    Returns:
        ``True`` if the address is in a private or loopback range.
    """
    addr = ipaddress.IPv4Address(ip)
    return any(addr in net for net in _PRIVATE_NETWORKS)


class _TTLCache:
    """Bounded per-IP result cache with time-based expiry.

    Dict-compatible for the operations the aggregator uses (``get``,
    ``__setitem__``, ``__contains__``, ``__len__``), so a plain ``dict``
    can still be substituted in tests.  Thread-safe: Flask worker threads
    hit the shared aggregator concurrently.

    Attributes:
        _ttl: Seconds an entry stays valid.
        _max: Maximum number of entries; the oldest inserted entry is
            evicted when full (insertion order via dict ordering).
    """

    def __init__(self, ttl_seconds: float = 3600.0, max_size: int = 1024) -> None:
        """Create the cache.

        Args:
            ttl_seconds: Entry lifetime in seconds (default 1 hour).
            max_size: Entry cap before oldest-first eviction (default 1024).
        """
        self._ttl = ttl_seconds
        self._max = max_size
        self._data: dict[str, tuple[ThreatIntelResult, float]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> ThreatIntelResult | None:
        """Return the live entry for *key*, or None if absent/expired."""
        with self._lock:
            item = self._data.get(key)
            if item is None:
                return None
            result, expires_at = item
            if time.monotonic() >= expires_at:
                del self._data[key]
                return None
            return result

    def __setitem__(self, key: str, value: ThreatIntelResult) -> None:
        """Store *value* under *key*, evicting the oldest entry when full."""
        with self._lock:
            if key not in self._data and len(self._data) >= self._max:
                self._data.pop(next(iter(self._data)))
            self._data[key] = (value, time.monotonic() + self._ttl)

    def __contains__(self, key: str) -> bool:
        """Return True when a live (non-expired) entry exists for *key*."""
        return self.get(key) is not None

    def __len__(self) -> int:
        """Return the number of stored (possibly stale) entries."""
        with self._lock:
            return len(self._data)


class _DailyQuota:
    """Per-provider daily API budget with UTC-midnight reset.

    In-memory only — the counter restarts with the process, which is
    acceptable: it exists to stop a single process from silently burning a
    provider's free-tier daily quota.

    Attributes:
        limit: Calls permitted per UTC day.
    """

    def __init__(self, limit: int) -> None:
        """Create the counter.

        Args:
            limit: Calls permitted per UTC day (0 disables the provider).
        """
        self.limit = limit
        self._count = 0
        self._day: date | None = None
        self._lock = threading.Lock()

    def try_acquire(self) -> bool:
        """Consume one call slot if the daily budget allows it.

        Returns:
            True when the call may proceed; False when today's budget is
            exhausted.
        """
        today = datetime.now(timezone.utc).date()
        with self._lock:
            if self._day != today:
                self._day = today
                self._count = 0
            if self._count >= self.limit:
                return False
            self._count += 1
            return True


def _quota_limit(provider: str, default: int) -> int:
    """Read a provider's daily quota from ``ADTE_TI_QUOTA_<PROVIDER>``.

    Args:
        provider: Uppercase provider name (e.g. ``"VIRUSTOTAL"``).
        default: Fallback limit when the env var is absent or malformed.

    Returns:
        The configured daily call limit.
    """
    raw = os.environ.get(f"ADTE_TI_QUOTA_{provider}", "")
    try:
        return int(raw) if raw else default
    except ValueError:
        return default


class ThreatIntelAggregator:
    """Combines results from multiple threat intelligence providers.

    Instantiates only the clients whose API keys are present.  When no keys
    are configured the deterministic mock is used exclusively (suitable for
    offline testing and CI).

    Aggregation rules:
      - Confidence: average across all sources that respond without error.
      - ``is_malicious``: ``True`` if any source flags the IP, or if the
        average confidence ≥ 0.5.
      - Tags: union-merged and deduplicated (insertion order preserved).
      - ``source``: comma-joined provider names.

    Results are cached per IP for the lifetime of the aggregator instance to
    avoid redundant API calls within a single triage run.

    Attributes:
        _use_mock: Whether to use the deterministic mock exclusively.
        _clients: Live API client instances to query.
        _cache: Per-instance result cache keyed by IP string.
    """

    def __init__(
        self,
        abuseipdb_key: str | None = None,
        vt_key: str | None = None,
        otx_key: str | None = None,
    ) -> None:
        """Initialise the aggregator with optional API keys.

        When all three keys are ``None`` the aggregator operates in pure mock
        mode and makes no network calls.  OTX is always included when at
        least one key is provided because it functions without authentication.

        Args:
            abuseipdb_key: AbuseIPDB API key, or ``None``.
            vt_key: VirusTotal API key, or ``None``.
            otx_key: OTX API key, or ``None`` (OTX works without a key).
        """
        self._use_mock = abuseipdb_key is None and vt_key is None and otx_key is None
        self._clients: list[AbuseIPDBClient | VirusTotalClient | OTXClient] = []
        self._cache: _TTLCache = _TTLCache()
        self._quotas: list[_DailyQuota] = []

        if not self._use_mock:
            if abuseipdb_key:
                self._clients.append(AbuseIPDBClient(abuseipdb_key))
                self._quotas.append(_DailyQuota(_quota_limit("ABUSEIPDB", 1000)))
            if vt_key:
                self._clients.append(VirusTotalClient(vt_key))
                self._quotas.append(_DailyQuota(_quota_limit("VIRUSTOTAL", 500)))
            # OTX works unauthenticated; always include when in live mode.
            self._clients.append(OTXClient(otx_key))
            self._quotas.append(_DailyQuota(_quota_limit("OTX", 10000)))

    @classmethod
    def from_env(cls) -> "ThreatIntelAggregator":
        """Create an aggregator populated from ADTE environment variables.

        Reads ``ADTE_ABUSEIPDB_KEY``, ``ADTE_VT_API_KEY``, and
        ``ADTE_OTX_KEY``.

        Returns:
            A configured ``ThreatIntelAggregator``.
        """
        return cls(
            abuseipdb_key=os.environ.get("ADTE_ABUSEIPDB_KEY"),
            vt_key=os.environ.get("ADTE_VT_API_KEY"),
            otx_key=os.environ.get("ADTE_OTX_KEY"),
        )

    def check(self, ip: str) -> ThreatIntelResult:
        """Query all configured providers and return an aggregated result.

        Resolution order:
          1. Return cached result if this IP was already queried.
          2. Return a neutral result for private/loopback IPs without
             making any API calls.
          3. Return the deterministic mock result if no keys are configured.
          4. Query live API clients, aggregate, and cache the result.
             Falls back to the mock if all clients return errors.

        Args:
            ip: Pre-validated IPv4 address string.

        Returns:
            An aggregated ``ThreatIntelResult``.
        """
        # 1. Cache hit (get-once: entries can expire between checks).
        cached = self._cache.get(ip)
        if cached is not None:
            return cached

        # 2. Private / loopback short-circuit.
        if _is_private(ip):
            result = ThreatIntelResult(
                ip=ip,
                is_malicious=False,
                confidence=0.0,
                source="private-ip",
                tags=["private"],
                queried_at=datetime.now(timezone.utc),
            )
            self._cache[ip] = result
            return result

        # 3. Mock-only mode.
        if self._use_mock:
            result = _mock_lookup(ip)
            self._cache[ip] = result
            return result

        # 4. Live API clients — queried in parallel to minimise latency.
        # Providers whose daily quota is exhausted are skipped for the day
        # (tolerate hand-constructed aggregators without _quotas — tests
        # build instances via __new__).
        quotas = getattr(self, "_quotas", [])
        if len(quotas) == len(self._clients):
            live_clients = []
            for client, quota in zip(self._clients, quotas):
                if quota.try_acquire():
                    live_clients.append(client)
                else:
                    _log.info(
                        "ThreatIntelAggregator: daily quota exhausted for %s; "
                        "skipping provider until UTC midnight",
                        type(client).__name__,
                    )
        else:
            live_clients = list(self._clients)

        if not live_clients:
            _log.warning(
                "ThreatIntelAggregator: all provider daily quotas exhausted; "
                "serving mock result for %s until UTC midnight",
                ip,
            )
            result = _mock_lookup(ip)
            self._cache[ip] = result
            return result

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(live_clients)) as pool:
            futures = [pool.submit(client.check, ip) for client in live_clients]
        # ThreadPoolExecutor context manager waits for all futures before
        # exiting, so f.result() here never blocks.
        raw_results = [f.result() for f in futures]
        # Each client signals failure by returning source="<name>-error";
        # filter those out before aggregating confidence and tags.
        good = [r for r in raw_results if not r.source.endswith("-error")]

        if not good:
            _log.warning(
                "ThreatIntelAggregator: all sources failed for %s; falling back to mock", ip
            )
            result = _mock_lookup(ip)
            self._cache[ip] = result
            return result

        avg_confidence = sum(r.confidence for r in good) / len(good)
        any_malicious = any(r.is_malicious for r in good)
        # Flag malicious if any source says so OR if average confidence
        # crosses the 0.5 threshold — two conservative criteria, not one.
        is_malicious = any_malicious or avg_confidence >= 0.5

        seen: set[str] = set()
        merged_tags: list[str] = []
        for r in good:
            for tag in r.tags:
                if tag not in seen:
                    seen.add(tag)
                    merged_tags.append(tag)

        result = ThreatIntelResult(
            ip=ip,
            is_malicious=is_malicious,
            confidence=avg_confidence,
            source=",".join(r.source for r in good),
            tags=merged_tags,
            queried_at=datetime.now(timezone.utc),
        )
        self._cache[ip] = result
        return result
