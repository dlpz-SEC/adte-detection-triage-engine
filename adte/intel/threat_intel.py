"""Threat intelligence lookups for IP reputation and file-hash reputation.

Public entry point for IP and file-hash reputation checks.  Delegates to
``ThreatIntelAggregator``, which queries live threat intel APIs when keys
are configured (``ADTE_ABUSEIPDB_KEY``, ``ADTE_VT_API_KEY``,
``ADTE_OTX_KEY``) and falls back to a deterministic mock when no keys are
set — suitable for development, testing, and dry-run triage without
requiring external API access.  File-hash reputation is VirusTotal-only
(``ADTE_VT_API_KEY``); AbuseIPDB and OTX are IP-only feeds.

NIST 800-61 Phase: Detection & Analysis — enriches observables with
threat context to support triage decisions.
"""

from __future__ import annotations

import contextvars
import ipaddress
import logging
import re
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Literal

from adte.intel.aggregator import ThreatIntelAggregator
from adte.models import FileReputationResult, ThreatIntelResult

_log = logging.getLogger(__name__)

# Module-level singleton — reused across requests so the per-IP result cache
# persists and clients are not re-instantiated on every triage call.
_aggregator: ThreatIntelAggregator | None = None
_aggregator_lock = threading.Lock()

# Most distinct IPs one alert may send to live providers.  Without a cap, a
# single request listing hundreds of public IPs spends every provider's daily
# quota and holds a server thread while the lookups run one after another.
MAX_LIVE_LOOKUPS_PER_ALERT: int = 25

# [live lookups left, IPs skipped] for the alert triaged in the current
# context.  None (the default) means uncapped: the CLI, and /api/intel's
# single lookup.
_lookup_budget: contextvars.ContextVar[list[int] | None] = contextvars.ContextVar(
    "adte_ti_lookup_budget", default=None
)


@contextmanager
def lookup_budget(limit: int = MAX_LIVE_LOOKUPS_PER_ALERT) -> Iterator[None]:
    """Cap live threat-intel lookups for the alert triaged inside this block.

    Only calls that would reach a live provider are charged (see
    ``ThreatIntelAggregator.needs_live_lookup``); cached, private and
    reserved IPs are free.  An IP over the cap gets a neutral ``lookup-cap``
    result, visible in the triage evidence, and counts as not malicious.
    Context-local: enter it in the thread that runs the engine, because a
    context variable does not follow work into another thread.

    Args:
        limit: Live lookups allowed inside the block.

    Yields:
        Nothing; the previous budget is restored when the block exits.
    """
    token = _lookup_budget.set([limit, 0])
    try:
        yield
    finally:
        _lookup_budget.reset(token)


# Hex-digest length -> digest algorithm name.
_HASH_TYPE_BY_LENGTH: dict[int, Literal["md5", "sha1", "sha256"]] = {
    32: "md5",
    40: "sha1",
    64: "sha256",
}


def _get_aggregator() -> ThreatIntelAggregator:
    """Return the module-level aggregator, creating it on first call.

    Thread-safe: the lock ensures only one instance is created even under
    concurrent Flask requests.

    Returns:
        The shared ``ThreatIntelAggregator`` instance.
    """
    global _aggregator
    if _aggregator is None:
        with _aggregator_lock:
            if _aggregator is None:
                _aggregator = ThreatIntelAggregator.from_env()
    return _aggregator


def check_threat_intel(ip: str) -> ThreatIntelResult:
    """Look up an IP address against threat intelligence feeds.

    Validates the IP, then delegates to the module-level
    ``ThreatIntelAggregator`` singleton which selects live API sources based
    on configured environment variables or falls back to a deterministic mock
    when none are set.  Results are cached per IP for the lifetime of the
    server process.

    Args:
        ip: IPv4 address string to check (e.g. ``"198.51.100.14"``).

    Returns:
        A ``ThreatIntelResult`` with reputation data.

    Raises:
        ValueError: If *ip* is not a valid IPv4 address.
    """
    try:
        ipaddress.IPv4Address(ip)
    except ipaddress.AddressValueError as exc:
        raise ValueError(f"Invalid IPv4 address: {ip!r}") from exc

    aggregator = _get_aggregator()
    budget = _lookup_budget.get()
    if budget is not None and aggregator.needs_live_lookup(ip):
        if budget[0] <= 0:
            budget[1] += 1
            if budget[1] == 1:  # once per alert, so the log cannot be flooded
                _log.info("Threat-intel lookup cap reached; further IPs in this alert are not looked up")
            return ThreatIntelResult(
                ip=ip,
                is_malicious=False,
                confidence=0.0,
                source="lookup-cap",
                tags=["not-looked-up"],
                queried_at=datetime.now(timezone.utc),
            )
        budget[0] -= 1
    return aggregator.check(ip)


def check_file_hash(file_hash: str) -> FileReputationResult:
    """Look up a file hash against threat intelligence feeds.

    Validates the hash as a hex-encoded MD5, SHA-1, or SHA-256 digest,
    determines the digest algorithm from its length, then delegates to the
    module-level ``ThreatIntelAggregator`` singleton which queries
    VirusTotal (the only hash-capable configured source) or falls back to a
    deterministic mock when no VirusTotal key is set.  Results are cached
    per hash for the lifetime of the server process.

    Args:
        file_hash: Hex-encoded MD5 (32 chars), SHA-1 (40 chars), or SHA-256
            (64 chars) digest string.  Case-insensitive; normalised to
            lowercase before lookup.

    Returns:
        A ``FileReputationResult`` with reputation data.

    Raises:
        ValueError: If *file_hash* is not a valid MD5/SHA-1/SHA-256 hex
            digest.
    """
    if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", file_hash) is None:
        raise ValueError(f"Invalid file hash: {file_hash!r}")

    normalized = file_hash.lower()
    hash_type = _HASH_TYPE_BY_LENGTH[len(normalized)]

    return _get_aggregator().check_hash(normalized, hash_type)
