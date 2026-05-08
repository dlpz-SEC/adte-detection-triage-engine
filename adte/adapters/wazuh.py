"""Wazuh Indexer (OpenSearch) source adapter for ADTE.

Connects to a Wazuh Indexer instance, authenticates via HTTP Basic Auth,
pulls recent alerts from the OpenSearch ``_search`` API, and normalises
them into the ADTE ``NormalizedIncident`` schema for triage.

The Wazuh Indexer is an OpenSearch distribution that stores Wazuh alerts
in indices named ``wazuh-alerts-4.x-*``.  Alerts are queried via the
standard OpenSearch ``POST /{index}/_search`` endpoint using a range
filter on ``@timestamp``.

Environment variables:
    ADTE_WAZUH_HOST:         Base URL of the Wazuh Indexer
                             (default: ``https://localhost:9200``).
    ADTE_WAZUH_USER: Wazuh API username (required).
    ADTE_WAZUH_PASS: Wazuh API password (required).

NIST 800-61 Phase: Detection & Analysis — alert ingestion is the first
step in structured incident analysis.
"""

from __future__ import annotations

import ipaddress
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Literal
from urllib.parse import urlparse

import warnings

import requests
import urllib3

from adte.models import AlertEntity, GeoLocation, NormalizedIncident, SignInMetadata

_DEFAULT_INDEXER_URL = "https://localhost:9200"
_DEFAULT_INDEXER_PORT = 9200
_INDEXER_PAGE_SIZE = 500  # Maximum results per OpenSearch request.
_ALERTS_INDEX = "wazuh-alerts-4.x-*"
_log = logging.getLogger(__name__)

# Values treated as "no real user extracted" in the data fields.
_SKIP_USER_VALUES: frozenset[str] = frozenset({"", "-", "root", "SYSTEM", "N/A"})

# SSRF protection: schemes that are valid for an OpenSearch endpoint.
_ALLOWED_SCHEMES: frozenset[str] = frozenset({"https", "http"})

# SSRF protection: hostnames that must never be targeted.
# 169.254.169.254 is the IMDS endpoint on AWS, Azure, and GCP;
# metadata.google.internal is GCP's DNS alias for the same service.
_SSRF_BLOCKED_HOSTS: frozenset[str] = frozenset({
    "169.254.169.254",
    "metadata.google.internal",
})


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _normalise_indexer_url(raw: str) -> str:
    """Normalise a Wazuh Indexer URL so it always has a scheme and port.

    Accepts any of the following forms for ``ADTE_WAZUH_HOST``:

    - Full URL:          ``https://192.168.1.10:9200``  (unchanged)
    - Hostname + port:   ``192.168.1.10:9200``          → ``https://192.168.1.10:9200``
    - Bare hostname/IP:  ``192.168.1.10``               → ``https://192.168.1.10:9200``

    Args:
        raw: Raw value read from the environment variable.

    Returns:
        A normalised URL with scheme ``https://`` and an explicit port.
    """
    # Add scheme so urlparse can extract host and port reliably.
    if "://" not in raw:
        raw = f"https://{raw}"
    parsed = urlparse(raw)
    scheme = parsed.scheme or "https"
    host = parsed.hostname or "localhost"
    port = parsed.port or _DEFAULT_INDEXER_PORT
    path = parsed.path.rstrip("/")
    return f"{scheme}://{host}:{port}{path}"


def _validate_indexer_url(url: str) -> None:
    """Raise ``EnvironmentError`` if the URL could enable an SSRF attack.

    Checks performed (in order):

    1. Scheme must be ``https`` or ``http`` — rejects ``file://``, ``ftp://``,
       and other non-HTTP schemes that could read local resources.
    2. Host must not be in ``_SSRF_BLOCKED_HOSTS`` — prevents requests to
       cloud instance-metadata services (AWS/Azure/GCP IMDS).
    3. Host must not be a link-local address (``169.254.0.0/16``) — catches
       numeric variants of the IMDS endpoint that evade name-based checks.

    Args:
        url: Fully normalised URL (output of ``_normalise_indexer_url``).

    Raises:
        EnvironmentError: If the URL fails any SSRF check.
    """
    parsed = urlparse(url)
    scheme = parsed.scheme or ""
    host = parsed.hostname or ""

    if scheme not in _ALLOWED_SCHEMES:
        raise EnvironmentError(
            f"ADTE_WAZUH_HOST scheme {scheme!r} is not permitted — "
            "only 'https' and 'http' are accepted."
        )

    if host in _SSRF_BLOCKED_HOSTS:
        raise EnvironmentError(
            f"ADTE_WAZUH_HOST targets {host!r}, which is a cloud instance-metadata "
            "endpoint. SSRF protection: this host is blocked."
        )

    try:
        addr = ipaddress.ip_address(host)
        if addr.is_link_local:
            raise EnvironmentError(
                f"ADTE_WAZUH_HOST targets link-local address {host!r}. "
                "SSRF protection: link-local addresses are blocked."
            )
    except ValueError:
        pass  # Not a bare IP address — DNS resolution is the operator's responsibility.


def _severity_from_level(level: int) -> Literal["Low", "Medium", "High", "Critical"]:
    """Map a Wazuh rule level (1–15) to an ADTE severity string.

    Args:
        level: Wazuh ``rule.level`` integer.

    Returns:
        One of ``"Low"``, ``"Medium"``, ``"High"``, ``"Critical"``.
        Values outside the 1–15 range are clamped to the nearest bound.
    """
    if level <= 3:
        return "Low"
    if level <= 7:
        return "Medium"
    if level <= 11:
        return "High"
    return "Critical"


def _extract_user(alert: dict[str, Any]) -> str:
    """Best-effort extraction of a user identifier from a Wazuh alert.

    Tries common field paths in priority order:

    1. ``data.dstuser``, ``data.user``, ``data.srcuser``
    2. ``data.win.eventdata.targetUserName``,
       ``data.win.eventdata.subjectUserName``
    3. Fallback: ``"{agent.name}\\system"`` — never returns an empty string.

    Args:
        alert: Raw Wazuh alert dict.

    Returns:
        A non-empty string identifying the relevant user.
    """
    data = alert.get("data", {})

    # Linux / generic auth events.
    for key in ("dstuser", "user", "srcuser"):
        val = data.get(key, "")
        if val and val not in _SKIP_USER_VALUES:
            return val

    # Windows event data.
    win_eventdata = data.get("win", {}).get("eventdata", {})
    for key in ("targetUserName", "subjectUserName"):
        val = win_eventdata.get(key, "")
        if val and val not in _SKIP_USER_VALUES:
            return val

    agent_name = alert.get("agent", {}).get("name", "unknown")
    return f"{agent_name}\\system"


def _extract_srcip(alert: dict[str, Any]) -> str:
    """Extract the source IP address from a Wazuh alert.

    Tries the following fields in priority order:

    1. ``data.srcip``    — generic Wazuh / Syslog events
    2. ``data.src_ip``   — Suricata / EVE-JSON events (``rule.groups`` contains
                           ``"suricata"``)
    3. ``agent.ip``      — fallback to the reporting agent's IP

    Args:
        alert: Raw Wazuh alert dict.

    Returns:
        An IP address string, or ``""`` if none is available.
    """
    data = alert.get("data", {})
    for field in ("srcip", "src_ip"):
        val = data.get(field, "")
        if val:
            return val
    return alert.get("agent", {}).get("ip", "")


def _parse_wazuh_timestamp(ts: str) -> datetime:
    """Parse a Wazuh ISO 8601 timestamp into a timezone-aware datetime.

    Handles both Wazuh Indexer format (``Z`` suffix) and legacy Manager
    format (``+0000`` offset without colon), which Python's
    ``fromisoformat`` rejects before 3.11.  We normalise both.

    Args:
        ts: Timestamp string such as ``"2024-01-15T10:30:00.000Z"``
            or ``"2024-01-15T10:30:00.000+0000"``.

    Returns:
        A UTC-aware ``datetime``.
    """
    # Normalise "+0000" → "+00:00", and "Z" → "+00:00".
    normalised = ts.replace("+0000", "+00:00").replace("Z", "+00:00")
    return datetime.fromisoformat(normalised)


# ---------------------------------------------------------------------------
# Adapter class
# ---------------------------------------------------------------------------


class WazuhAdapter:
    """Source adapter that fetches and normalises Wazuh alerts for ADTE.

    Authenticates against the Wazuh Indexer (OpenSearch) using HTTP Basic
    Auth, retrieves recent alerts (with pagination) via the ``_search``
    endpoint, and converts each alert to a ``NormalizedIncident`` for the
    triage engine.

    Typical usage::

        adapter = WazuhAdapter.from_env()
        incidents = adapter.fetch_incidents(hours=24)

    Or with explicit parameters::

        adapter = WazuhAdapter(
            url="https://wazuh-indexer.internal:9200",
            user="api-user",
            password="secret",
        )
        incidents = adapter.fetch_incidents(hours=6, limit=200)
    """

    def __init__(
        self,
        url: str,
        user: str,
        password: str,
        verify_ssl: bool = True,
    ) -> None:
        """Initialise the adapter.

        Args:
            url: Wazuh Indexer base URL (e.g. ``https://localhost:9200``).
            user: Wazuh API username.
            password: Wazuh API password.
            verify_ssl: Whether to verify the server's TLS certificate.
                Defaults to ``True``.  Set to ``False`` only for local
                self-signed development instances (or via
                ``ADTE_WAZUH_VERIFY_SSL=false``).
        """
        self._url = _normalise_indexer_url(url)
        _validate_indexer_url(self._url)
        self._user = user
        self._password = password
        self._verify_ssl = verify_ssl
        self._session = requests.Session()
        self._session.auth = (user, password)

    def __repr__(self) -> str:
        """Safe repr that never exposes credentials."""
        return f"WazuhAdapter(url={self._url!r}, user={self._user!r})"

    @classmethod
    def from_env(cls) -> "WazuhAdapter":
        """Create a ``WazuhAdapter`` from environment variables.

        Reads:
        - ``ADTE_WAZUH_HOST`` (default: ``https://localhost:9200``)
        - ``ADTE_WAZUH_USER`` (required)
        - ``ADTE_WAZUH_PASS`` (required)

        Returns:
            A configured ``WazuhAdapter`` instance.

        Raises:
            EnvironmentError: If ``ADTE_WAZUH_USER`` or ``ADTE_WAZUH_PASS``
                are not set.
        """
        url = os.environ.get("ADTE_WAZUH_HOST", _DEFAULT_INDEXER_URL)
        user = os.environ.get("ADTE_WAZUH_USER", "")
        password = os.environ.get("ADTE_WAZUH_PASS", "")
        verify_ssl = os.environ.get("ADTE_WAZUH_VERIFY_SSL", "true").lower() != "false"
        if not user:
            raise EnvironmentError(
                "ADTE_WAZUH_USER is not set. "
                "Export the Wazuh API username before running --source wazuh."
            )
        if not password:
            raise EnvironmentError(
                "ADTE_WAZUH_PASS is not set. "
                "Export the Wazuh API password before running --source wazuh."
            )
        if not verify_ssl:
            parsed_host = urlparse(_normalise_indexer_url(url)).hostname or "localhost"
            if parsed_host not in ("localhost", "127.0.0.1", "::1"):
                raise EnvironmentError(
                    f"ADTE_WAZUH_VERIFY_SSL=false is not permitted for non-local host {parsed_host!r}. "
                    "Certificate verification may only be disabled for localhost connections. "
                    "Use a valid TLS certificate or set ADTE_WAZUH_HOST to a localhost URL."
                )
        return cls(url=url, user=user, password=password, verify_ssl=verify_ssl)

    def fetch_alerts(
        self,
        hours: int = 24,
        limit: int = 500,
        min_level: int = 1,
    ) -> list[dict[str, Any]]:
        """Fetch recent alerts from the Wazuh Indexer.

        Pages through ``POST /{index}/_search`` until all alerts within
        the time window are retrieved or ``limit`` is reached.  Level-0
        informational alerts are always excluded; ``min_level`` raises the
        floor further.

        Each returned dict is the OpenSearch ``_source`` document with the
        document ``_id`` injected as the ``"id"`` field.

        Args:
            hours: Look-back window in hours (default: 24).
            limit: Maximum total alerts to return (default: 500).  If the
                Indexer reports more alerts than this, a warning is logged
                and the results are truncated.
            min_level: Minimum Wazuh rule level to include (default: 1).
                Alerts below this level are excluded at the query layer.

        Returns:
            A list of raw alert dicts with ``rule.level >= min_level``.

        Raises:
            requests.HTTPError: If any API request fails.
        """
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=hours)
        ).strftime("%Y-%m-%dT%H:%M:%S")

        all_items: list[dict[str, Any]] = []
        total: int | None = None

        while True:
            page_size = min(_INDEXER_PAGE_SIZE, limit - len(all_items))
            if page_size <= 0:
                break

            body: dict[str, Any] = {
                "size": page_size,
                "from": len(all_items),
                "sort": [{"@timestamp": {"order": "desc"}}],
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"@timestamp": {"gte": cutoff}}},
                            {"range": {"rule.level": {"gte": min_level}}},
                        ]
                    }
                },
            }
            with warnings.catch_warnings():
                if not self._verify_ssl:
                    warnings.filterwarnings(
                        "ignore", category=urllib3.exceptions.InsecureRequestWarning
                    )
                resp = self._session.post(
                    f"{self._url}/{_ALERTS_INDEX}/_search",
                    json=body,
                    verify=self._verify_ssl,
                    timeout=30,
                )
            resp.raise_for_status()
            hits = resp.json().get("hits", {})

            if total is None:
                raw_total = hits.get("total", 0)
                # OpenSearch returns total as {"value": N, "relation": "eq"}
                # or as a plain integer in older versions.
                total = (
                    raw_total["value"]
                    if isinstance(raw_total, dict)
                    else int(raw_total)
                )

            page = hits.get("hits", [])
            for hit in page:
                source = hit.get("_source", {})
                # Inject the OpenSearch document _id as "id" for normalization.
                source.setdefault("id", hit.get("_id", ""))
                all_items.append(source)

            if not page or len(all_items) >= total:
                break

        if total is not None and total > limit:
            _log.warning(
                "Wazuh Indexer reports %d alerts matching the filter but --limit is %d; "
                "results are truncated. Increase --limit to retrieve all alerts.",
                total,
                limit,
            )

        # Belt-and-suspenders: strip any documents that slipped under min_level.
        return [a for a in all_items if a.get("rule", {}).get("level", 0) >= min_level]

    @staticmethod
    def normalize_alert(alert: dict[str, Any]) -> NormalizedIncident:
        """Convert a single Wazuh alert into a ``NormalizedIncident``.

        Field mapping:

        - ``alert["id"]``                    → ``incident_id``
        - ``rule.level`` via severity table  → ``severity``
        - ``alert["@timestamp"]``            → ``created_time``
        - ``_extract_user(alert)``           → ``user``
        - One ``SignInMetadata`` per alert:
          - ``_extract_user``     → ``user_principal_name``
          - ``_extract_srcip``    → ``ip_address``
          - ``None``              → ``location`` (Wazuh provides no geo;
            the engine will skip the travel signal and redistribute weight)
          - ``agent.id``          → ``device_id``
          - ``agent.name``        → ``device_name``
          - ``"NotAttempted"``    → ``mfa_result`` (Wazuh doesn't track MFA)
          - ``rule.description``  → ``app_display_name``
          - ``str(rule.level)``   → ``risk_state``
        - Entities: Host always; IP and Account when extractable.

        Args:
            alert: Raw Wazuh alert dict (``_source`` from OpenSearch with
                ``id`` injected from ``_id``, as returned by
                ``fetch_alerts``).

        Returns:
            A ``NormalizedIncident`` ready for the triage pipeline.
        """
        rule = alert.get("rule", {})
        agent = alert.get("agent", {})

        severity = _severity_from_level(rule.get("level", 1))
        user = _extract_user(alert)
        srcip = _extract_srcip(alert)
        # Wazuh Indexer uses @timestamp; fall back to timestamp for compatibility.
        raw_ts = alert.get("@timestamp") or alert.get(
            "timestamp", "1970-01-01T00:00:00+00:00"
        )
        ts = _parse_wazuh_timestamp(raw_ts)

        sign_in = SignInMetadata(
            user_principal_name=user,
            ip_address=srcip,
            location=None,  # Wazuh does not provide geolocation data.
            device_id=agent.get("id", ""),
            device_name=agent.get("name", ""),
            mfa_result="NotAttempted",
            app_display_name=rule.get("description", ""),
            risk_state=str(rule.get("level", 0)),
            timestamp=ts,
        )

        entities: list[AlertEntity] = [
            AlertEntity(
                entity_type="Host",
                identifier=agent.get("name", "unknown"),
                metadata={
                    "agent_id": agent.get("id", ""),
                    "agent_ip": agent.get("ip", ""),
                },
            )
        ]
        if srcip:
            mitre = rule.get("mitre", {})
            entities.append(AlertEntity(
                entity_type="IP",
                identifier=srcip,
                metadata={
                    "rule_id": rule.get("id", ""),
                    "mitre_techniques": mitre.get("technique", []),
                },
            ))
        # Only add Account entity when the user is a real extracted value
        # (not the fallback system account pattern).
        if user and not user.endswith("\\system"):
            entities.append(AlertEntity(
                entity_type="Account",
                identifier=user,
                metadata={},
            ))

        return NormalizedIncident(
            incident_id=alert.get("id", "wazuh-unknown"),
            user=user,
            sign_in_events=[sign_in],
            entities=entities,
            severity=severity,
            created_time=ts,
        )

    def fetch_incidents(
        self,
        hours: int = 24,
        limit: int = 500,
        min_level: int = 1,
    ) -> list[NormalizedIncident]:
        """Fetch alerts from the Indexer and normalise each one.

        Args:
            hours: Look-back window passed to ``fetch_alerts``.
            limit: Maximum alert count passed to ``fetch_alerts``.
            min_level: Minimum rule level passed to ``fetch_alerts``.

        Returns:
            A list of ``NormalizedIncident`` objects ready for triage.
        """
        alerts = self.fetch_alerts(hours=hours, limit=limit, min_level=min_level)
        return [self.normalize_alert(alert) for alert in alerts]
