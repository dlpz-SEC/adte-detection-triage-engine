"""Threat intelligence lookups for IP reputation.

Provides a mock-mode threat intel service with deterministic responses
for known IP ranges, suitable for development, testing, and dry-run
triage without requiring external API access.

NIST 800-61 Phase: Detection & Analysis — enriches observables with
threat context to support triage decisions.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

from adte.models import ThreatIntelResult

# ---------------------------------------------------------------------------
# Deterministic mock IP ranges
# ---------------------------------------------------------------------------

_MALICIOUS_RANGES: list[tuple[ipaddress.IPv4Network, float, str, list[str]]] = [
    # Known C2 infrastructure
    (ipaddress.IPv4Network("198.51.100.0/24"), 0.95, "mock-c2-feed", ["c2", "cobalt-strike"]),
    # Tor exit nodes
    (ipaddress.IPv4Network("185.220.101.0/24"), 0.85, "mock-tor-list", ["tor-exit"]),
    # Brute-force scanners
    (ipaddress.IPv4Network("45.33.32.0/24"), 0.75, "mock-scanner-feed", ["scanner", "brute-force"]),
    # Crypto-mining pool proxies
    (ipaddress.IPv4Network("203.0.113.0/24"), 0.70, "mock-mining-feed", ["cryptominer", "proxy"]),
]

_SUSPICIOUS_RANGES: list[tuple[ipaddress.IPv4Network, float, str, list[str]]] = [
    # Residential proxy network
    (ipaddress.IPv4Network("100.64.0.0/16"), 0.45, "mock-proxy-feed", ["residential-proxy"]),
    # Hosting provider frequently abused
    (ipaddress.IPv4Network("192.0.2.0/24"), 0.40, "mock-abuse-db", ["hosting", "bulletproof"]),
]


def check_threat_intel(ip: str) -> ThreatIntelResult:
    """Look up an IP address against mock threat intelligence feeds.

    The mock implementation uses deterministic IP-range matching so that
    tests and dry-run triage produce repeatable results.

    Args:
        ip: IPv4 address string to check (e.g. ``"198.51.100.14"``).

    Returns:
        A ``ThreatIntelResult`` with reputation data.  For IPs that do
        not match any known-bad range, ``is_malicious`` is ``False``
        and ``confidence`` is ``0.0``.

    Raises:
        ValueError: If *ip* is not a valid IPv4 address.
    """
    try:
        addr = ipaddress.IPv4Address(ip)
    except ipaddress.AddressValueError as exc:
        raise ValueError(f"Invalid IPv4 address: {ip!r}") from exc

    now = datetime.now(timezone.utc)

    # Check malicious ranges first (higher priority).
    for network, confidence, source, tags in _MALICIOUS_RANGES:
        if addr in network:
            return ThreatIntelResult(
                ip=ip,
                is_malicious=True,
                confidence=confidence,
                source=source,
                tags=tags,
                queried_at=now,
            )

    # Check suspicious-but-not-confirmed ranges.
    for network, confidence, source, tags in _SUSPICIOUS_RANGES:
        if addr in network:
            return ThreatIntelResult(
                ip=ip,
                is_malicious=False,
                confidence=confidence,
                source=source,
                tags=tags,
                queried_at=now,
            )

    # IP not found in any feed — benign by default.
    return ThreatIntelResult(
        ip=ip,
        is_malicious=False,
        confidence=0.0,
        source="mock-no-match",
        tags=[],
        queried_at=now,
    )
