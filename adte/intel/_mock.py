"""Internal mock threat intelligence lookups.

Provides deterministic IP-range matching for development, testing, and
fallback when no external API keys are configured.  Not part of the public
API — imported only by ``threat_intel`` and ``aggregator``.

NIST 800-61 Phase: Detection & Analysis — enriches observables with threat
context to support triage decisions without requiring external API access.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

from adte.models import ThreatIntelResult

# ---------------------------------------------------------------------------
# Deterministic mock IP ranges
# ---------------------------------------------------------------------------
#
# Range selection rationale:
#
# RFC 5737 TEST-NET blocks (reserved for documentation — will never appear
# in real traffic, so matching them in production is always safe):
#   192.0.2.0/24   (TEST-NET-1)
#   198.51.100.0/24 (TEST-NET-2)
#   203.0.113.0/24  (TEST-NET-3)
#
# RFC 6598 Shared Address Space (CGNAT — not publicly routable):
#   100.64.0.0/16  — used here to represent residential proxy space.
#
# Realistic-looking ranges included for demo fidelity only:
#   185.220.101.0/24 — frequently cited as a Tor exit range in threat feeds;
#                       NOT guaranteed to be non-routable in production.
#   45.33.32.0/24    — a Linode/Akamai hosting block; NOT reserved.
#
# IMPORTANT: if this mock is used alongside real incident data (e.g. in a
# staging environment), 185.220.101.0/24 and 45.33.32.0/24 could match
# legitimate traffic.  Replace those two ranges with RFC 5737 addresses for
# staging deployments that process real IPs.

_MALICIOUS_RANGES: list[tuple[ipaddress.IPv4Network, float, str, list[str]]] = [
    # RFC 5737 TEST-NET-2 — C2 infrastructure (safe in production: never real traffic)
    (ipaddress.IPv4Network("198.51.100.0/24"), 0.95, "mock-c2-feed", ["c2", "cobalt-strike"]),
    # Demo-only: realistic Tor exit range — may match real traffic in staging
    (ipaddress.IPv4Network("185.220.101.0/24"), 0.85, "mock-tor-list", ["tor-exit"]),
    # Demo-only: realistic hosting/scanner range — may match real traffic in staging
    (ipaddress.IPv4Network("45.33.32.0/24"), 0.75, "mock-scanner-feed", ["scanner", "brute-force"]),
    # RFC 5737 TEST-NET-3 — crypto-mining proxies (safe in production: never real traffic)
    (ipaddress.IPv4Network("203.0.113.0/24"), 0.70, "mock-mining-feed", ["cryptominer", "proxy"]),
]

_SUSPICIOUS_RANGES: list[tuple[ipaddress.IPv4Network, float, str, list[str]]] = [
    # RFC 6598 Shared Address Space (CGNAT) — residential proxy (not publicly routable)
    (ipaddress.IPv4Network("100.64.0.0/16"), 0.45, "mock-proxy-feed", ["residential-proxy"]),
    # RFC 5737 TEST-NET-1 — abused hosting provider (safe in production: never real traffic)
    (ipaddress.IPv4Network("192.0.2.0/24"), 0.40, "mock-abuse-db", ["hosting", "bulletproof"]),
]


def _mock_lookup(ip: str) -> ThreatIntelResult:
    """Return a deterministic mock ThreatIntelResult for a pre-validated IP.

    Checks the IP against hardcoded malicious and suspicious ranges in order.
    Returns a benign result for IPs that do not match any range.

    Args:
        ip: A pre-validated IPv4 address string.  No validation is performed
            here — the caller must validate first.

    Returns:
        A ``ThreatIntelResult`` based on hardcoded range matching.
    """
    addr = ipaddress.IPv4Address(ip)
    now = datetime.now(timezone.utc)

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

    return ThreatIntelResult(
        ip=ip,
        is_malicious=False,
        confidence=0.0,
        source="mock-no-match",
        tags=[],
        queried_at=now,
    )
