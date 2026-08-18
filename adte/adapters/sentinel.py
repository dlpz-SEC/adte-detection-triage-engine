"""Microsoft Sentinel (Log Analytics) source adapter for ADTE.

Connects to a Microsoft Sentinel workspace via the Azure Monitor
Log Analytics Query API, authenticates with OAuth2 client-credentials
(a least-privilege service principal holding the Log Analytics Reader
role), pulls recent ``SecurityIncident``/``SecurityAlert`` rows with a
single KQL query, and normalises them into the ADTE
``NormalizedIncident`` schema for triage.

Unlike the Wazuh adapter (HTTP Basic Auth against a self-hosted
Indexer), both endpoints here are fixed Microsoft-operated hosts —
``login.microsoftonline.com`` for tokens and
``api.loganalytics.azure.com`` for queries — so the SSRF surface shifts
from URL validation to *path injection*: the tenant and workspace IDs
are interpolated into those URLs and are therefore validated as strict
GUIDs before any request is built.

Design notes:
    - ``normalize_incident`` constructs ``SignInMetadata`` directly
      (mirroring ``WazuhAdapter.normalize_alert``) rather than routing
      through ``NormalizedIncident.from_sentinel``: the ``from_sentinel``
      path defaults a missing ``location`` to ``GeoLocation(0, 0)``
      ("Null Island"), which could mis-fire the impossible-travel signal
      against events that carry real geo.  Direct construction passes
      ``location=None`` so the engine skips the travel signal and
      redistributes its weight — exactly the Wazuh behaviour.
    - ``auth_status`` is left ``None`` (v1): the ``SecurityAlert`` table
      carries no reliable MFA outcome, so the engine skips the
      MFA-fatigue signal and redistributes.  A later revision may expand
      events from correlated ``SigninLogs`` rows, which do carry both
      geo and auth outcomes.
    - TLS verification is always on — these are public Microsoft
      endpoints with valid certificates; there is deliberately no
      ``verify_ssl`` knob to disable it.

Environment variables:
    ADTE_SENTINEL_TENANT_ID:     Entra tenant GUID (required).
    ADTE_SENTINEL_CLIENT_ID:     App-registration (service principal)
                                 client GUID (required).
    ADTE_SENTINEL_CLIENT_SECRET: Client secret value (required; env var
                                 only — never committed, never logged).
    ADTE_SENTINEL_WORKSPACE_ID:  Log Analytics workspace GUID (required).

NIST 800-61 Phase: Detection & Analysis — alert ingestion is the first
step in structured incident analysis.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Literal

import requests

from adte.models import AlertEntity, NormalizedIncident, SignInMetadata

_TOKEN_URL_TEMPLATE = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
_QUERY_URL_TEMPLATE = "https://api.loganalytics.azure.com/v1/workspaces/{workspace_id}/query"
# Token audience deliberately differs from the query host: not every tenant
# holds the ``api.loganalytics.azure.com`` resource principal (AADSTS500011
# observed live 2026-08-18), while the classic ``api.loganalytics.io``
# audience is universally provisioned and accepted by both query hosts.
_SCOPE = "https://api.loganalytics.io/.default"
_REQUEST_TIMEOUT = 30  # Seconds, on both the token and query calls.
_TOKEN_REFRESH_MARGIN = 300  # Refresh this many seconds before expiry.
_DEFAULT_TOKEN_TTL = 3600  # Assumed lifetime when the response omits expires_in.
_log = logging.getLogger(__name__)

# Path-injection guard: tenant/client/workspace IDs are interpolated into
# fixed-host URLs, so they must be strict GUIDs — nothing else.
# \Z (not $) — $ would accept a trailing newline.
_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z"
)

# Trim ADX 7-digit (100 ns) fractional seconds to the 6 digits
# ``datetime.fromisoformat`` accepts.
_FRACTION_TRIM_RE = re.compile(r"(\.\d{6})\d+")

# The one KQL this adapter runs: latest revision of each open incident in
# the window, joined to the latest revision of each of its alerts.
# Column aliases are chosen so the projected names survive the join.
_INCIDENT_QUERY_TEMPLATE = """
SecurityIncident
| where TimeGenerated > ago({hours}h)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Status != 'Closed'
| mv-expand AlertId = AlertIds
| extend AlertId = tostring(AlertId)
| join kind=inner (
    SecurityAlert
    | where TimeGenerated > ago({hours}h)
    | summarize arg_max(TimeGenerated, *) by SystemAlertId
) on $left.AlertId == $right.SystemAlertId
| project
    IncidentNumber,
    IncidentTitle = Title,
    IncidentStatus = Status,
    IncidentCreated = CreatedTime,
    AlertName,
    AlertSeverity,
    AlertTime = StartTime,
    Entities,
    Techniques,
    Tactics,
    ProviderName
| take {limit}
""".strip()

# Sentinel entity "Type" values → ADTE AlertEntity entity_type.
# Anything not listed (url, dns, cloud-application, ...) is skipped —
# AlertEntity's Literal only admits these five.
_ENTITY_TYPE_MAP: dict[str, str] = {
    "account": "Account",
    "ip": "IP",
    "host": "Host",
    "file": "File",
    "process": "Process",
}


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _validate_guid(value: str, var_name: str) -> None:
    """Raise ``EnvironmentError`` unless ``value`` is a strict GUID.

    The tenant, client, and workspace IDs are interpolated into
    fixed-host URLs; validating them as GUIDs closes the path-injection
    surface (e.g. ``../`` or query-string smuggling) the same way
    ``_validate_indexer_url`` closes SSRF for the Wazuh adapter.

    Args:
        value: The candidate identifier.
        var_name: Environment-variable name, used in the error message.

    Raises:
        EnvironmentError: If ``value`` is not a canonical GUID.
    """
    if not _GUID_RE.match(value):
        raise EnvironmentError(
            f"{var_name} value {value!r} is not a valid GUID. "
            "Copy the ID exactly as shown in the Azure portal "
            "(format: 00000000-0000-0000-0000-000000000000)."
        )


def _parse_api_timestamp(ts: Any) -> datetime | None:
    """Parse a Log Analytics ISO 8601 timestamp defensively.

    The Query API emits datetimes as ISO strings, sometimes with a ``Z``
    suffix and sometimes with 7-digit (100 ns) fractional seconds that
    ``datetime.fromisoformat`` rejects.  Both are normalised.  Malformed
    or missing values return ``None`` so the caller can fall back —
    normalisation must degrade, never raise (the ``from_sentinel`` path's
    unguarded ``fromisoformat`` is exactly the failure mode this avoids).

    Args:
        ts: Raw timestamp value from a query-result row.

    Returns:
        A timezone-aware ``datetime``, or ``None`` when unparseable.
    """
    if not ts or not isinstance(ts, str):
        return None
    normalised = _FRACTION_TRIM_RE.sub(r"\1", ts.replace("Z", "+00:00"))
    try:
        parsed = datetime.fromisoformat(normalised)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _event_risk_from_severity(severity: Any) -> Literal["none", "suspicious", "high", "confirmed"]:
    """Map a Sentinel ``AlertSeverity`` to the normalised ``event_risk`` band.

    Sentinel severities are analyst-facing labels, not AAD risk states,
    so they are mapped onto the source-agnostic enum the same way the
    Wazuh adapter maps rule levels.

    Args:
        severity: ``AlertSeverity`` value (``Informational``/``Low``/
            ``Medium``/``High``; anything else maps to ``"none"``).

    Returns:
        One of ``"none"``, ``"suspicious"``, ``"high"``, ``"confirmed"``.
    """
    mapping: dict[str, Literal["none", "suspicious", "high", "confirmed"]] = {
        "informational": "none",
        "low": "suspicious",
        "medium": "high",
        "high": "confirmed",
    }
    return mapping.get(str(severity or "").lower(), "none")


def _parse_techniques(raw: Any) -> list[str]:
    """Parse the ``SecurityAlert.Techniques`` column into technique IDs.

    The column is a JSON-encoded array string such as ``'["T1110"]'``.
    Malformed values degrade to ``[]`` — never raise.

    Args:
        raw: Raw ``Techniques`` column value.

    Returns:
        A list of non-empty technique ID strings.
    """
    if not raw or not isinstance(raw, str):
        return []
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return []
    if not isinstance(parsed, list):
        return []
    return [str(t) for t in parsed if t]


def _entity_identifier(kind: str, entity: dict[str, Any]) -> str:
    """Derive a display identifier for one parsed Sentinel entity.

    Field priority per kind (Sentinel's entity schema):

    - account: ``Name@UPNSuffix`` when both present, else ``Name``.
    - ip:      ``Address``.
    - host:    ``HostName`` → ``NetBiosName``.
    - file:    ``Name``.
    - process: ``ProcessId`` → ``CommandLine``.

    Args:
        kind: Lower-cased Sentinel entity ``Type``.
        entity: The raw entity dict.

    Returns:
        The identifier string, or ``""`` when nothing usable exists.
    """
    if kind == "account":
        name = str(entity.get("Name") or "")
        suffix = str(entity.get("UPNSuffix") or "")
        return f"{name}@{suffix}" if name and suffix else name
    if kind == "ip":
        return str(entity.get("Address") or "")
    if kind == "host":
        return str(entity.get("HostName") or entity.get("NetBiosName") or "")
    if kind == "file":
        return str(entity.get("Name") or "")
    if kind == "process":
        return str(entity.get("ProcessId") or entity.get("CommandLine") or "")
    return ""


def _parse_entities(raw: Any) -> list[AlertEntity]:
    """Parse the ``SecurityAlert.Entities`` JSON string into ``AlertEntity`` rows.

    ``Entities`` is a JSON-encoded list of dicts, each carrying a
    ``Type`` discriminator plus type-specific fields.  Kinds outside
    ADTE's ``AlertEntity`` Literal (url, dns, cloud-application, ...)
    are skipped; malformed JSON degrades to ``[]``.

    Args:
        raw: Raw ``Entities`` column value.

    Returns:
        The mappable entities, in source order.
    """
    if not raw or not isinstance(raw, str):
        return []
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return []
    if not isinstance(parsed, list):
        return []

    entities: list[AlertEntity] = []
    for item in parsed:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("Type") or "").lower()
        mapped = _ENTITY_TYPE_MAP.get(kind)
        if mapped is None:
            continue
        identifier = _entity_identifier(kind, item)
        if not identifier:
            continue
        entities.append(
            AlertEntity(
                entity_type=mapped,  # type: ignore[arg-type]
                identifier=identifier,
                metadata={},
            )
        )
    return entities


def _rows_as_dicts(table: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert one Query API table (columns + row arrays) into row dicts.

    The Query API returns ``{"columns": [{"name": ...}, ...],
    "rows": [[...], ...]}``; zipping the column names over each row
    array yields the ``{column: value}`` dicts the rest of the adapter
    consumes.  Shape irregularities degrade to skipped rows.

    Args:
        table: One entry of the response's ``tables`` array.

    Returns:
        A list of row dicts.
    """
    raw_columns = table.get("columns")
    columns = raw_columns if isinstance(raw_columns, list) else []
    names = [str(c.get("name", "")) for c in columns if isinstance(c, dict)]
    raw_rows = table.get("rows")
    rows = raw_rows if isinstance(raw_rows, list) else []
    out: list[dict[str, Any]] = []
    for row in rows:
        if isinstance(row, list) and len(row) == len(names):
            out.append(dict(zip(names, row)))
    return out


# ---------------------------------------------------------------------------
# Adapter class
# ---------------------------------------------------------------------------


class SentinelAdapter:
    """Source adapter that fetches and normalises Sentinel incidents for ADTE.

    Authenticates against Microsoft Entra with OAuth2 client-credentials,
    queries the Log Analytics workspace for recent open incidents joined
    to their alerts, and converts each incident to a
    ``NormalizedIncident`` for the triage engine.

    Typical usage::

        adapter = SentinelAdapter.from_env()
        incidents = adapter.fetch_incidents(hours=24)

    Or with explicit parameters::

        adapter = SentinelAdapter(
            tenant_id="00000000-0000-0000-0000-000000000000",
            client_id="00000000-0000-0000-0000-000000000001",
            client_secret="secret-value",
            workspace_id="00000000-0000-0000-0000-000000000002",
        )
        incidents = adapter.fetch_incidents(hours=6, limit=200)
    """

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        workspace_id: str,
    ) -> None:
        """Initialise the adapter.

        Args:
            tenant_id: Entra tenant GUID.
            client_id: App-registration client GUID.
            client_secret: Client secret value (never logged).
            workspace_id: Log Analytics workspace GUID.

        Raises:
            EnvironmentError: If any GUID parameter is malformed
                (path-injection guard).
        """
        _validate_guid(tenant_id, "ADTE_SENTINEL_TENANT_ID")
        _validate_guid(client_id, "ADTE_SENTINEL_CLIENT_ID")
        _validate_guid(workspace_id, "ADTE_SENTINEL_WORKSPACE_ID")
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._workspace_id = workspace_id
        self._session = requests.Session()
        self._token: str = ""
        self._token_expires_at: float = 0.0

    def __repr__(self) -> str:
        """Safe repr that never exposes the client secret."""
        return (
            f"SentinelAdapter(tenant_id={self._tenant_id!r}, "
            f"client_id={self._client_id!r}, "
            f"workspace_id={self._workspace_id!r})"
        )

    @classmethod
    def from_env(cls) -> "SentinelAdapter":
        """Create a ``SentinelAdapter`` from environment variables.

        Reads (all required):
        - ``ADTE_SENTINEL_TENANT_ID``
        - ``ADTE_SENTINEL_CLIENT_ID``
        - ``ADTE_SENTINEL_CLIENT_SECRET``
        - ``ADTE_SENTINEL_WORKSPACE_ID``

        Returns:
            A configured ``SentinelAdapter`` instance.

        Raises:
            EnvironmentError: If any variable is unset, naming the
                missing variable and the CLI flag it unblocks.
        """
        values: dict[str, str] = {}
        for var in (
            "ADTE_SENTINEL_TENANT_ID",
            "ADTE_SENTINEL_CLIENT_ID",
            "ADTE_SENTINEL_CLIENT_SECRET",
            "ADTE_SENTINEL_WORKSPACE_ID",
        ):
            value = os.environ.get(var, "")
            if not value:
                raise EnvironmentError(
                    f"{var} is not set. Export the Sentinel service-principal "
                    "credentials before running --source sentinel."
                )
            values[var] = value
        return cls(
            tenant_id=values["ADTE_SENTINEL_TENANT_ID"],
            client_id=values["ADTE_SENTINEL_CLIENT_ID"],
            client_secret=values["ADTE_SENTINEL_CLIENT_SECRET"],
            workspace_id=values["ADTE_SENTINEL_WORKSPACE_ID"],
        )

    def _get_token(self) -> str:
        """Return a valid bearer token, refreshing when near expiry.

        Uses the OAuth2 client-credentials grant against the tenant's
        ``login.microsoftonline.com`` endpoint.  The token is cached and
        refreshed ``_TOKEN_REFRESH_MARGIN`` seconds before expiry.

        Returns:
            The bearer token string.

        Raises:
            requests.HTTPError: If the token request fails.
        """
        if self._token and time.monotonic() < self._token_expires_at:
            return self._token

        resp = self._session.post(
            _TOKEN_URL_TEMPLATE.format(tenant_id=self._tenant_id),
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "scope": _SCOPE,
            },
            timeout=_REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        payload = resp.json()
        self._token = str(payload.get("access_token", ""))
        try:
            ttl = int(payload.get("expires_in", _DEFAULT_TOKEN_TTL))
        except (TypeError, ValueError):
            ttl = _DEFAULT_TOKEN_TTL
        self._token_expires_at = time.monotonic() + max(0, ttl - _TOKEN_REFRESH_MARGIN)
        return self._token

    def fetch_incidents_raw(
        self,
        hours: int = 24,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        """Run the incident/alert KQL and return the result rows.

        One incident may span several rows — one per joined alert.
        Rows are grouped into incidents by ``normalize_incident``.

        Args:
            hours: Look-back window in hours (default: 24).
            limit: Maximum joined rows to return (default: 500).

        Returns:
            A list of ``{column: value}`` row dicts.

        Raises:
            requests.HTTPError: If the query request fails.
        """
        query = _INCIDENT_QUERY_TEMPLATE.format(hours=int(hours), limit=int(limit))
        resp = self._session.post(
            _QUERY_URL_TEMPLATE.format(workspace_id=self._workspace_id),
            headers={"Authorization": f"Bearer {self._get_token()}"},
            json={"query": query},
            timeout=_REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        raw_tables = resp.json().get("tables")
        tables = raw_tables if isinstance(raw_tables, list) else []
        rows: list[dict[str, Any]] = []
        for table in tables:
            if isinstance(table, dict):
                rows.extend(_rows_as_dicts(table))
        return rows

    @staticmethod
    def normalize_incident(rows: list[dict[str, Any]]) -> NormalizedIncident:
        """Convert one incident's query rows into a ``NormalizedIncident``.

        Field mapping (one ``SignInMetadata`` event per alert row):

        - ``IncidentNumber``                  → ``incident_id`` (prefixed
          ``sentinel-``)
        - ``"azure_ad"``                      → ``source`` (Sentinel is the
          pipe; the telemetry domain is Entra ID)
        - ``IncidentCreated``                 → ``created_time``
        - First ``Account`` entity            → ``user`` /
          ``user_principal_name``
        - First ``IP`` entity in the row      → ``ip_address``
        - ``AlertName``                       → ``app_display_name``
        - ``_event_risk_from_severity(AlertSeverity)`` → ``event_risk``
        - ``Techniques`` (JSON string)        → ``technique_ids``
        - ``AlertTime`` → ``IncidentCreated`` → epoch → ``timestamp``
          (each parsed defensively; malformed values fall back rather
          than raise)
        - ``None``                            → ``location`` (no geo at
          the alert level; the engine skips the travel signal and
          redistributes weight — never ``GeoLocation(0, 0)``)
        - ``None``                            → ``auth_status`` (no MFA
          outcome at the alert level; the engine skips MFA-fatigue)
        - ``"authentication"``                → ``type`` (identity-lab
          default; matches ``from_sentinel``'s default)

        Entities from every row are merged and de-duplicated by
        ``(entity_type, identifier)``, preserving first-seen order.

        Args:
            rows: All query rows sharing one ``IncidentNumber`` (as
                returned by ``fetch_incidents_raw``).

        Returns:
            A ``NormalizedIncident`` ready for the triage pipeline.

        Raises:
            ValueError: If ``rows`` is empty.
        """
        if not rows:
            raise ValueError("normalize_incident requires at least one row")

        first = rows[0]
        incident_number = first.get("IncidentNumber", "unknown")
        created = _parse_api_timestamp(first.get("IncidentCreated"))

        # Merge entities across rows, de-duplicated, first-seen order.
        entities: list[AlertEntity] = []
        seen: set[tuple[str, str]] = set()
        for row in rows:
            for entity in _parse_entities(row.get("Entities")):
                key = (entity.entity_type, entity.identifier)
                if key not in seen:
                    seen.add(key)
                    entities.append(entity)

        user = ""
        for entity in entities:
            if entity.entity_type == "Account":
                user = entity.identifier
                break

        epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
        events: list[SignInMetadata] = []
        for row in rows:
            row_entities = _parse_entities(row.get("Entities"))
            ip_address = next(
                (e.identifier for e in row_entities if e.entity_type == "IP"), ""
            )
            row_user = next(
                (e.identifier for e in row_entities if e.entity_type == "Account"),
                user,
            )
            ts = (
                _parse_api_timestamp(row.get("AlertTime"))
                or created
                or epoch
            )
            events.append(
                SignInMetadata(
                    user_principal_name=row_user or user,
                    ip_address=ip_address,
                    type="authentication",
                    location=None,  # No geo at alert level — engine skips travel.
                    device_id="",
                    device_name="",
                    # No MFA outcome at alert level → auth_status None so the
                    # engine skips MFA-fatigue and redistributes its weight.
                    app_display_name=str(row.get("AlertName") or ""),
                    event_risk=_event_risk_from_severity(row.get("AlertSeverity")),
                    technique_ids=_parse_techniques(row.get("Techniques")),
                    timestamp=ts,
                )
            )
        events.sort(key=lambda e: e.timestamp)

        return NormalizedIncident(
            incident_id=f"sentinel-{incident_number}",
            user=user,
            source="azure_ad",
            events=events,
            entities=entities,
            created_time=created or (events[0].timestamp if events else epoch),
        )

    def fetch_incidents(
        self,
        hours: int = 24,
        limit: int = 500,
    ) -> list[NormalizedIncident]:
        """Fetch recent incidents and normalise each one.

        Rows are grouped by ``IncidentNumber`` (one incident may span
        several alert rows) and each group is normalised independently.

        Args:
            hours: Look-back window passed to ``fetch_incidents_raw``.
            limit: Maximum joined rows passed to ``fetch_incidents_raw``.

        Returns:
            A list of ``NormalizedIncident`` objects ready for triage,
            in first-seen incident order.
        """
        rows = self.fetch_incidents_raw(hours=hours, limit=limit)
        grouped: dict[Any, list[dict[str, Any]]] = {}
        for row in rows:
            grouped.setdefault(row.get("IncidentNumber", "unknown"), []).append(row)
        return [self.normalize_incident(group) for group in grouped.values()]
