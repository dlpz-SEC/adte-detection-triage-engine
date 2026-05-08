"""VirusTotal v3 HTTP client for IP address reputation lookups.

Queries the VirusTotal ``/api/v3/ip_addresses/{ip}`` endpoint and maps
``last_analysis_stats.malicious`` counts to a normalised confidence score.

Configure via environment variable ``ADTE_VT_API_KEY``.

Rate limit: 4 requests/minute for public API keys.  A configurable
inter-request sleep (default 15 s) is applied after each successful call.

NIST 800-61 Phase: Detection & Analysis — enriches IP observables with
multi-engine antivirus verdict data to support triage decisions.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

import requests

from adte.models import ThreatIntelResult

_log = logging.getLogger(__name__)

_BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses"
_TIMEOUT = 10  # seconds


# _neutral() mirrors the same helper in abuseipdb.py and otx.py.
# Each copy uses a different source string so the aggregator can identify
# which provider failed.  See abuseipdb._neutral for the rationale.
def _neutral(ip: str) -> ThreatIntelResult:
    """Return a neutral result indicating a failed or skipped lookup.

    Args:
        ip: The IPv4 address that could not be queried.

    Returns:
        A ``ThreatIntelResult`` with zero confidence and source
        ``"virustotal-error"``.
    """
    return ThreatIntelResult(
        ip=ip,
        is_malicious=False,
        confidence=0.0,
        source="virustotal-error",
        tags=[],
        queried_at=datetime.now(timezone.utc),
    )


class VirusTotalClient:
    """HTTP client for the VirusTotal v3 IP address reputation API.

    Rate limit: 4 requests/minute (public key).  A class-level timestamp
    tracks the last call time so the inter-request delay is only applied
    when a previous call was made within the rate-limit window — single
    lookups incur no delay.

    Attributes:
        _api_key: VirusTotal API key, or ``None`` if unconfigured.
        _rate_limit_sleep: Minimum seconds between consecutive API calls.
        _last_call_time: Class-level timestamp of the most recent call.
    """

    # Class attribute intentionally shared across instances: if two
    # VirusTotalClient objects are ever created they compete on the same
    # rate-limit window, which is the correct conservative behaviour.
    _last_call_time: float = 0.0

    def __init__(self, api_key: str | None, *, rate_limit_sleep: float = 15.0) -> None:
        """Initialise the client.

        Args:
            api_key: VirusTotal API key from ``ADTE_VT_API_KEY``.
                Pass ``None`` to disable this source.
            rate_limit_sleep: Seconds to sleep after each API call to respect
                the 4 req/min rate limit.  Set to ``0`` in tests to avoid
                delays.
        """
        self._api_key = api_key
        self._rate_limit_sleep = rate_limit_sleep

    def check(self, ip: str) -> ThreatIntelResult:
        """Query VirusTotal for an IP address's analysis statistics.

        Computes a confidence score as ``malicious / total_engines`` where
        total includes malicious, suspicious, undetected, and harmless counts
        (timeout is excluded from the denominator).  IPs with score ≥ 0.5
        are marked malicious.

        Sleeps for ``rate_limit_sleep`` seconds after each successful call to
        respect the public API rate limit of 4 requests/minute.

        Args:
            ip: IPv4 address string to look up.

        Returns:
            A ``ThreatIntelResult``.  On HTTP error or network failure,
            returns a neutral result with ``source="virustotal-error"`` and
            logs a warning.
        """
        if not self._api_key:
            _log.warning("VirusTotalClient: no API key configured, skipping lookup for %s", ip)
            return _neutral(ip)

        url = f"{_BASE_URL}/{ip}"
        headers = {"x-apikey": self._api_key}

        # Only sleep the remaining window if a previous call was made recently.
        elapsed = time.time() - VirusTotalClient._last_call_time
        wait = self._rate_limit_sleep - elapsed
        if wait > 0:
            time.sleep(wait)

        try:
            response = requests.get(url, headers=headers, timeout=_TIMEOUT)
            VirusTotalClient._last_call_time = time.time()  # record on class, not self

            response.raise_for_status()
        except requests.RequestException as exc:
            _log.warning("VirusTotalClient: request failed for %s (%s)", ip, type(exc).__name__)
            return _neutral(ip)

        stats: dict[str, int] = (
            response.json()
            .get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)
        harmless = stats.get("harmless", 0)
        total = malicious + suspicious + undetected + harmless

        confidence = malicious / total if total > 0 else 0.0

        return ThreatIntelResult(
            ip=ip,
            is_malicious=confidence >= 0.5,
            confidence=confidence,
            source="virustotal",
            tags=[],
            queried_at=datetime.now(timezone.utc),
        )
