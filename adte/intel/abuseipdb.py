"""AbuseIPDB v2 HTTP client for IP reputation lookups.

Queries the AbuseIPDB ``/api/v2/check`` endpoint and maps the
``abuseConfidenceScore`` (0–100) to a normalised confidence value (0.0–1.0).

Configure via environment variable ``ADTE_ABUSEIPDB_KEY``.

NIST 800-61 Phase: Detection & Analysis — enriches IP observables with
community-sourced abuse-report data to support triage decisions.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import requests

from adte.models import ThreatIntelResult

_log = logging.getLogger(__name__)

_BASE_URL = "https://api.abuseipdb.com/api/v2/check"
_TIMEOUT = 10  # seconds


# _neutral() mirrors the same helper in otx.py and virustotal.py; each
# returns a client-specific source name so the aggregator can tell which
# provider failed.  Kept per-module rather than shared to avoid coupling
# clients to a common util.
def _neutral(ip: str) -> ThreatIntelResult:
    """Return a neutral result indicating a failed or skipped lookup.

    Args:
        ip: The IPv4 address that could not be queried.

    Returns:
        A ``ThreatIntelResult`` with zero confidence and source
        ``"abuseipdb-error"``.
    """
    return ThreatIntelResult(
        ip=ip,
        is_malicious=False,
        confidence=0.0,
        source="abuseipdb-error",
        tags=[],
        queried_at=datetime.now(timezone.utc),
    )


class AbuseIPDBClient:
    """HTTP client for the AbuseIPDB v2 IP reputation API.

    Attributes:
        _api_key: AbuseIPDB API key, or ``None`` if unconfigured.
    """

    def __init__(self, api_key: str | None) -> None:
        """Initialise the client.

        Args:
            api_key: AbuseIPDB API key from ``ADTE_ABUSEIPDB_KEY``.
                Pass ``None`` to disable this source.
        """
        self._api_key = api_key

    def check(self, ip: str) -> ThreatIntelResult:
        """Query AbuseIPDB for an IP address's reputation.

        Maps ``abuseConfidenceScore`` (0–100) to a normalised confidence
        value (0.0–1.0).  IPs with confidence ≥ 0.5 are marked malicious.

        Args:
            ip: IPv4 address string to look up.

        Returns:
            A ``ThreatIntelResult``.  On HTTP error or network failure,
            returns a neutral result with ``source="abuseipdb-error"`` and
            logs a warning.
        """
        if not self._api_key:
            _log.warning("AbuseIPDBClient: no API key configured, skipping lookup for %s", ip)
            return _neutral(ip)

        params = {"ipAddress": ip, "maxAgeInDays": 90}
        headers = {"Key": self._api_key, "Accept": "application/json"}

        try:
            response = requests.get(_BASE_URL, params=params, headers=headers, timeout=_TIMEOUT)
            response.raise_for_status()
        except requests.RequestException as exc:
            _log.warning("AbuseIPDBClient: request failed for %s (%s)", ip, type(exc).__name__)
            return _neutral(ip)

        data = response.json().get("data", {})
        raw_score: int = data.get("abuseConfidenceScore", 0)
        confidence = raw_score / 100.0

        tags: list[str] = []
        usage_type: str = data.get("usageType") or ""
        if usage_type:
            tags.append(usage_type)
        domain: str = data.get("domain") or ""
        if domain:
            tags.append(f"domain:{domain}")
        if data.get("isTor") is True:
            tags.append("tor-exit")

        return ThreatIntelResult(
            ip=ip,
            is_malicious=confidence >= 0.5,
            confidence=confidence,
            source="abuseipdb",
            tags=tags,
            queried_at=datetime.now(timezone.utc),
        )
