"""AlienVault OTX HTTP client for IPv4 indicator lookups.

Queries the OTX ``/api/v1/indicators/IPv4/{ip}/general`` endpoint and maps
the pulse count to a normalised confidence score (pulse_count / 10, capped
at 1.0).

An API key is optional — unauthenticated requests are allowed but may be
rate-limited.  Configure via environment variable ``ADTE_OTX_KEY``.

NIST 800-61 Phase: Detection & Analysis — enriches IP observables with
community threat pulse data to support triage decisions.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import requests

from adte.models import ThreatIntelResult

_log = logging.getLogger(__name__)

_BASE_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4"
_TIMEOUT = 10  # seconds


# _neutral() mirrors the same helper in abuseipdb.py and virustotal.py.
# Each copy uses a different source string so the aggregator can identify
# which provider failed.  See abuseipdb._neutral for the rationale.
def _neutral(ip: str) -> ThreatIntelResult:
    """Return a neutral result indicating a failed or skipped lookup.

    Args:
        ip: The IPv4 address that could not be queried.

    Returns:
        A ``ThreatIntelResult`` with zero confidence and source
        ``"otx-error"``.
    """
    return ThreatIntelResult(
        ip=ip,
        is_malicious=False,
        confidence=0.0,
        source="otx-error",
        tags=[],
        queried_at=datetime.now(timezone.utc),
    )


class OTXClient:
    """HTTP client for the AlienVault OTX IPv4 general indicator endpoint.

    The API key is optional; unauthenticated requests are rate-limited but
    functional for basic lookups.

    Attributes:
        _api_key: OTX API key, or ``None`` for unauthenticated access.
    """

    def __init__(self, api_key: str | None) -> None:
        """Initialise the client.

        Args:
            api_key: OTX API key from ``ADTE_OTX_KEY``, or ``None`` for
                unauthenticated access.
        """
        self._api_key = api_key

    def check(self, ip: str) -> ThreatIntelResult:
        """Query OTX for threat pulses associated with an IPv4 address.

        Confidence is computed as ``min(pulse_count / 10, 1.0)``.  IPs with
        confidence ≥ 0.5 (≥ 5 pulses) are marked malicious.  Tags are
        collected from all pulse tag lists and deduplicated.

        Args:
            ip: IPv4 address string to look up.

        Returns:
            A ``ThreatIntelResult``.  On HTTP error or network failure,
            returns a neutral result with ``source="otx-error"`` and logs a
            warning.
        """
        url = f"{_BASE_URL}/{ip}/general"
        headers: dict[str, str] = {}
        if self._api_key:
            headers["X-OTX-API-KEY"] = self._api_key

        try:
            response = requests.get(url, headers=headers, timeout=_TIMEOUT)
            response.raise_for_status()
        except requests.RequestException as exc:
            _log.warning("OTXClient: request failed for %s (%s)", ip, type(exc).__name__)
            return _neutral(ip)

        pulse_info: dict = response.json().get("pulse_info", {})
        pulse_count: int = pulse_info.get("count", 0)
        confidence = min(pulse_count / 10.0, 1.0)

        # Flatten and deduplicate tags from all pulses.
        seen: set[str] = set()
        tags: list[str] = []
        for pulse in pulse_info.get("pulses", []):
            for tag in pulse.get("tags", []):
                if tag not in seen:
                    seen.add(tag)
                    tags.append(tag)

        return ThreatIntelResult(
            ip=ip,
            is_malicious=confidence >= 0.5,
            confidence=confidence,
            source="otx",
            tags=tags,
            queried_at=datetime.now(timezone.utc),
        )
