"""Threat intelligence lookups for IP reputation.

Public entry point for IP reputation checks.  Delegates to
``ThreatIntelAggregator``, which queries live threat intel APIs when keys
are configured (``ADTE_ABUSEIPDB_KEY``, ``ADTE_VT_API_KEY``,
``ADTE_OTX_KEY``) and falls back to a deterministic mock when no keys are
set — suitable for development, testing, and dry-run triage without
requiring external API access.

NIST 800-61 Phase: Detection & Analysis — enriches observables with
threat context to support triage decisions.
"""

from __future__ import annotations

import ipaddress
import threading

from adte.intel.aggregator import ThreatIntelAggregator
from adte.models import ThreatIntelResult

# Module-level singleton — reused across requests so the per-IP result cache
# persists and clients are not re-instantiated on every triage call.
_aggregator: ThreatIntelAggregator | None = None
_aggregator_lock = threading.Lock()


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

    return _get_aggregator().check(ip)
