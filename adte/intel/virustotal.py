"""VirusTotal v3 HTTP client for IP address and file-hash reputation lookups.

Queries the VirusTotal ``/api/v3/ip_addresses/{ip}`` and
``/api/v3/files/{hash}`` endpoints and maps ``last_analysis_stats.malicious``
counts to a normalised confidence score.

Configure via environment variable ``ADTE_VT_API_KEY``.

Rate limit: 4 requests/minute for public API keys.  A configurable
inter-request sleep (default 15 s) is applied after each successful call,
shared between IP and hash lookups.

NIST 800-61 Phase: Detection & Analysis — enriches IP and file-hash
observables with multi-engine antivirus verdict data to support triage
decisions.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Literal

import requests

from adte.models import FileReputationResult, ThreatIntelResult

_log = logging.getLogger(__name__)

_BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses"
_FILES_BASE_URL = "https://www.virustotal.com/api/v3/files"
_TIMEOUT = 10  # seconds

# Maximum seconds this client may EVER block waiting on the shared rate-limit
# window.  Zero: never block.  These lookups run on the request thread inside
# TriageEngine.enrich(), which iterates observables sequentially — sleeping the
# 15 s window per observable turned a 10-IP queue refresh into ~150 s and let
# gunicorn's --timeout 60 kill the worker (a self-inflicted DoS, and the same
# path an attacker could drive with a many-hash alert).  When the window is
# still closed we abstain instead: a "-error" source, which the aggregator
# already excludes from the confidence average.
_MAX_THROTTLE_WAIT: float = 0.0


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


def _neutral_hash(
    file_hash: str, hash_type: Literal["md5", "sha1", "sha256"]
) -> FileReputationResult:
    """Return a neutral result indicating a failed or skipped hash lookup.

    Args:
        file_hash: The hash that could not be queried.
        hash_type: The digest algorithm implied by *file_hash*'s length.

    Returns:
        A ``FileReputationResult`` with zero confidence and source
        ``"virustotal-error"``.
    """
    return FileReputationResult(
        file_hash=file_hash,
        hash_type=hash_type,
        is_malicious=False,
        confidence=0.0,
        positives=None,
        total=None,
        source="virustotal-error",
        tags=[],
        permalink="",
        queried_at=datetime.now(timezone.utc),
    )


class VirusTotalClient:
    """HTTP client for the VirusTotal v3 IP address reputation API.

    Rate limit: 4 requests/minute (public key).  A class-level timestamp
    tracks the last call time.  When a call would land inside that window
    the client **abstains** (returns a neutral ``-error`` result the
    aggregator excludes from its average) rather than sleeping — it runs on
    the request thread and must never block it.  See ``_MAX_THROTTLE_WAIT``.

    Attributes:
        _api_key: VirusTotal API key, or ``None`` if unconfigured.
        _rate_limit_sleep: Minimum seconds between consecutive API calls.
        _last_call_time: Class-level timestamp of the most recent call.
    """

    # Class attribute intentionally shared across instances: if two
    # VirusTotalClient objects are ever created they compete on the same
    # rate-limit window, which is the correct conservative behaviour.
    _last_call_time: float = 0.0

    @classmethod
    def _throttled(cls, rate_limit_sleep: float) -> bool:
        """Report whether the shared rate-limit window is still closed.

        The caller is on a request thread, so a closed window must SKIP the
        lookup rather than sleep through it (see ``_MAX_THROTTLE_WAIT``).

        Args:
            rate_limit_sleep: The configured inter-request spacing.

        Returns:
            ``True`` when the next call would have to wait longer than
            ``_MAX_THROTTLE_WAIT``.
        """
        wait = rate_limit_sleep - (time.time() - cls._last_call_time)
        return wait > _MAX_THROTTLE_WAIT

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

        Abstains (never blocks) when the shared 4-req/min rate-limit window
        is still closed — see the class docstring and ``_MAX_THROTTLE_WAIT``.

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

        # Rate-limit window still closed → SKIP, never sleep.  enrich() runs
        # this on the request thread and loops observables sequentially, so
        # sleeping the window blocks the worker (N observables x 15s) and
        # gunicorn's --timeout kills the request outright.  A skipped lookup
        # is a "-error" source, which the aggregator excludes from the
        # average, so VirusTotal simply abstains for this observable.
        if self._throttled(self._rate_limit_sleep):
            _log.info("VirusTotalClient: rate-limit window open, skipping %s", ip)
            return _neutral(ip)

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

    def check_hash(
        self, file_hash: str, hash_type: Literal["md5", "sha1", "sha256"]
    ) -> FileReputationResult:
        """Query VirusTotal for a file hash's analysis statistics.

        Computes a confidence score as ``malicious / total_engines`` where
        total includes malicious, suspicious, undetected, and harmless
        counts (timeout is excluded from the denominator) — identical
        arithmetic to ``check()`` for IP addresses.  Shares the same
        class-level rate-limit throttle as IP lookups: hash and IP checks
        compete for the same 4 req/min window.

        Args:
            file_hash: Pre-validated, lowercase hex digest string.
            hash_type: The digest algorithm implied by *file_hash*'s length.

        Returns:
            A ``FileReputationResult``.  On HTTP error, network failure, or
            a response that cannot be parsed, returns a neutral result with
            ``source="virustotal-error"`` and logs a warning.
        """
        if not self._api_key:
            _log.warning(
                "VirusTotalClient: no API key configured, skipping hash lookup for %s",
                file_hash,
            )
            return _neutral_hash(file_hash, hash_type)

        url = f"{_FILES_BASE_URL}/{file_hash}"
        headers = {"x-apikey": self._api_key}

        # Rate-limit window still closed → SKIP, never sleep (see check()).
        # The embedded Wazuh/VirusTotal verdict is preferred anyway, so a
        # skipped hash lookup only affects alerts that carry no verdict.
        if self._throttled(self._rate_limit_sleep):
            _log.info(
                "VirusTotalClient: rate-limit window open, skipping hash %s", file_hash
            )
            return _neutral_hash(file_hash, hash_type)

        try:
            response = requests.get(url, headers=headers, timeout=_TIMEOUT)
            VirusTotalClient._last_call_time = time.time()  # record on class, not self

            response.raise_for_status()
        except requests.RequestException as exc:
            _log.warning(
                "VirusTotalClient: hash request failed for %s (%s)",
                file_hash,
                type(exc).__name__,
            )
            return _neutral_hash(file_hash, hash_type)

        try:
            attributes = response.json().get("data", {}).get("attributes", {})
            stats: dict[str, int] = attributes.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            undetected = stats.get("undetected", 0)
            harmless = stats.get("harmless", 0)
            total = malicious + suspicious + undetected + harmless

            confidence = malicious / total if total > 0 else 0.0

            threat_label = attributes.get("popular_threat_classification", {}).get(
                "suggested_threat_label"
            )
            tags = [threat_label] if threat_label else []
        except (ValueError, AttributeError, TypeError) as exc:
            # response.json() raises ValueError on malformed JSON; a
            # non-dict payload raises AttributeError/TypeError on .get().
            _log.warning(
                "VirusTotalClient: failed to parse hash response for %s (%s)",
                file_hash,
                type(exc).__name__,
            )
            return _neutral_hash(file_hash, hash_type)

        return FileReputationResult(
            file_hash=file_hash,
            hash_type=hash_type,
            is_malicious=confidence >= 0.5,
            confidence=confidence,
            positives=malicious,
            total=total,
            source="virustotal",
            tags=tags,
            permalink=f"https://www.virustotal.com/gui/file/{file_hash}",
            queried_at=datetime.now(timezone.utc),
        )
