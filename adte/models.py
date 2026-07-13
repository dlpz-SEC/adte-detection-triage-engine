"""Pydantic models shared across ADTE modules.

All data structures that cross module boundaries are defined here
to maintain a single source of truth for the domain model.
"""

from __future__ import annotations

from datetime import datetime, time
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ThreatIntelResult(BaseModel):
    """Result from a threat intelligence lookup.

    Attributes:
        ip: The queried IP address.
        is_malicious: Whether the IP is considered malicious.
        confidence: Confidence score from 0.0 (no confidence) to 1.0 (certain).
        source: The intel feed or provider that produced this result.
        tags: Descriptive labels (e.g. 'c2', 'tor-exit', 'scanner').
        queried_at: Timestamp of when the lookup was performed.
    """

    ip: str
    is_malicious: bool
    confidence: float = Field(ge=0.0, le=1.0)
    source: str
    tags: list[str] = Field(default_factory=list)
    queried_at: datetime = Field(default_factory=datetime.utcnow)


class FileReputationResult(BaseModel):
    """Result from a file-hash reputation lookup (Phase 32).

    Parallel to ``ThreatIntelResult`` but for file hashes — kept as a
    separate model so IP-keyed evidence output is never polluted with
    hash subjects.

    Attributes:
        file_hash: The queried hash, normalised to lowercase hex.
        hash_type: Which digest algorithm the hash length implies.
        is_malicious: Whether the file is considered malicious.
        confidence: Confidence score from 0.0 (no confidence) to 1.0 (certain).
        positives: Number of engines flagging the file malicious, if known.
        total: Total number of engines consulted, if known.
        source: The intel feed or provider that produced this result.
        tags: Descriptive labels (e.g. 'eicar-test', 'trojan').
        permalink: Provider URL for the full report, if any.
        queried_at: Timestamp of when the lookup was performed.
    """

    file_hash: str
    hash_type: Literal["md5", "sha1", "sha256"]
    is_malicious: bool
    confidence: float = Field(ge=0.0, le=1.0)
    positives: int | None = None
    total: int | None = None
    source: str
    tags: list[str] = Field(default_factory=list)
    permalink: str = ""
    queried_at: datetime = Field(default_factory=datetime.utcnow)


class GeoLocation(BaseModel):
    """A geographic coordinate with optional metadata.

    Attributes:
        lat: Latitude in decimal degrees.
        lon: Longitude in decimal degrees.
        city: Human-readable city name.
        country: ISO 3166-1 alpha-2 country code.
    """

    lat: float = Field(ge=-90.0, le=90.0)
    lon: float = Field(ge=-180.0, le=180.0)
    city: str = ""
    country: str = ""


class DeviceInfo(BaseModel):
    """A known device associated with a user.

    Attributes:
        device_id: Unique identifier for the device.
        display_name: Human-readable device name.
        os: Operating system of the device.
        compliant: Whether the device meets compliance policy.
    """

    device_id: str
    display_name: str
    os: str = ""
    compliant: bool = True


class LoginHourRange(BaseModel):
    """A time range representing typical login hours.

    Attributes:
        start: Start of the typical login window.
        end: End of the typical login window.
        timezone: IANA timezone string (e.g. 'America/New_York').
    """

    start: time = Field(default=time(7, 0))
    end: time = Field(default=time(19, 0))
    timezone: str = "UTC"


class UserProfile(BaseModel):
    """Behavioral baseline for a user, used for anomaly detection.

    NIST 800-61 Phase: Detection & Analysis — provides the baseline
    against which current activity is compared.

    Attributes:
        upn: User principal name (e.g. 'alice@contoso.com').
        known_locations: Locations the user has previously authenticated from.
        known_devices: Devices the user has previously authenticated with.
        baseline_login_hours: Typical login time window.
        last_seen_location: Most recent authentication location.
        last_seen_at: Timestamp of most recent authentication.
        risk_score: Cumulative risk score from prior incidents (0.0–1.0).
    """

    upn: str
    known_locations: list[GeoLocation] = Field(default_factory=list)
    known_devices: list[DeviceInfo] = Field(default_factory=list)
    baseline_login_hours: LoginHourRange = Field(default_factory=LoginHourRange)
    last_seen_location: GeoLocation | None = None
    last_seen_at: datetime | None = None
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)


# ---------------------------------------------------------------------------
# Incident models
# ---------------------------------------------------------------------------


class FileArtifact(BaseModel):
    """File observable attached to a single event (Phase 32).

    Carries file-integrity-monitoring evidence (path, checksums, FIM
    action) and any scanner verdict embedded in the source alert (e.g.
    Wazuh's VirusTotal integration fields).  Read only by the additive
    ``file_reputation`` engine signal — absent on all non-file events.

    Hash fields are permissive by design: values are lowercase-normalised
    but never format-rejected at the model layer, so a hostile or
    malformed alert degrades gracefully instead of failing validation.
    Strict hex/length validation lives at the intel boundary
    (``check_file_hash``) and in the engine's hash guard.

    Attributes:
        path: Filesystem path of the observed file.
        sha256: SHA-256 checksum (lowercase hex), empty if unknown.
        sha1: SHA-1 checksum (lowercase hex), empty if unknown.
        md5: MD5 checksum (lowercase hex), empty if unknown.
        fim_action: File-integrity event kind, when the source is a FIM
            alert (``added``/``modified``/``deleted``).
        vt_positives: Engines flagging the file malicious, when the source
            alert embeds a VirusTotal verdict.
        vt_total: Total engines consulted, when embedded.
        vt_malicious: Provider's own malicious flag, when embedded.
        vt_permalink: Provider report URL, when embedded.
    """

    path: str = ""
    sha256: str = ""
    sha1: str = ""
    md5: str = ""
    fim_action: Literal["added", "modified", "deleted"] | None = None
    vt_positives: int | None = None
    vt_total: int | None = None
    vt_malicious: bool | None = None
    vt_permalink: str = ""

    @field_validator("sha256", "sha1", "md5")
    @classmethod
    def _normalise_hash(cls, value: str) -> str:
        """Lowercase-normalise hash strings without rejecting format.

        Args:
            value: Raw hash string from the source alert.

        Returns:
            The stripped, lowercased hash string.
        """
        return value.strip().lower()


class SignInMetadata(BaseModel):
    """A single normalised security event (OCSF-inspired, source-agnostic).

    Captures the raw observables from one event (originally an Azure AD /
    Entra ID sign-in, but now vendor-neutral) that the triage engine needs
    for enrichment and anomaly detection.  The ``type`` field tells the
    engine how to interpret the event.

    Attributes:
        user_principal_name: UPN / principal of the actor.
        ip_address: Source IP of the event.
        type: OCSF-style event class — how the engine should interpret this
            event (``authentication``, ``network``, ``process``, ``file``).
        location: Resolved geographic location of the source IP.
        device_id: Device-object ID (empty if unmanaged).
        device_name: Human-readable device name.
        user_agent: HTTP User-Agent string from the request.
        auth_status: Vendor-neutral authentication outcome
            (``success``/``failure``/``challenge``), or ``None`` when no
            authentication outcome applies to this event (e.g. a network or
            file event, or a sign-in where MFA was not attempted).
        app_display_name: Application the actor interacted with.
        event_risk: Normalised per-event risk assessment
            (``none``/``suspicious``/``high``/``confirmed``).
        technique_ids: Native MITRE ATT&CK technique IDs carried by the
            source log (e.g. Wazuh ``rule.mitre.id``).  Advisory metadata
            only — never read by the scoring signals.  Empty when the
            source provides none.
        file: File observable for ``file``-type events (path, checksums,
            FIM action, embedded scanner verdict).  ``None`` on all other
            events; read only by the additive ``file_reputation`` signal.
        timestamp: UTC timestamp of the event.
    """

    user_principal_name: str
    ip_address: str
    type: Literal["authentication", "network", "process", "file"]
    location: GeoLocation | None = None
    device_id: str = ""
    device_name: str = ""
    user_agent: str = ""
    auth_status: Literal["success", "failure", "challenge"] | None = None
    app_display_name: str = ""
    event_risk: Literal["none", "suspicious", "high", "confirmed"] = "none"
    technique_ids: list[str] = Field(default_factory=list)
    file: FileArtifact | None = None
    timestamp: datetime


class AlertEntity(BaseModel):
    """An entity extracted from a security alert.

    Entities are the observable artifacts (accounts, IPs, hosts, etc.)
    that link an alert to real-world objects for investigation.

    Attributes:
        entity_type: Category of the entity.
        identifier: Primary identifier value (UPN, IP, hostname, etc.).
        metadata: Additional key-value pairs specific to the entity type.
    """

    entity_type: Literal["Account", "IP", "Host", "File", "Process"]
    identifier: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class SentinelIncident(BaseModel):
    """Raw incident payload from Microsoft Sentinel.

    Represents the incident as it arrives from the Sentinel API before
    any normalisation or enrichment.

    Attributes:
        incident_id: Unique Sentinel incident identifier.
        title: Short description / rule name that fired.
        source: Origin platform of the incident (``azure_ad``, ``wazuh``,
            ``okta``, ``generic``); carried through to the normalised incident.
        status: Current incident status (e.g. 'New', 'Active', 'Closed').
        created_time: UTC timestamp when Sentinel created the incident.
        entities: Observable entities extracted from the underlying alerts.
        alerts: Raw alert payloads associated with this incident.
        raw_payload: Complete original JSON from the Sentinel API.

    Note:
        ``severity`` is intentionally absent — severity is engine-assigned,
        not caller-supplied.  Any ``severity`` present in raw source JSON is
        ignored (pydantic ``extra='ignore'``) rather than propagated.
    """

    model_config = ConfigDict(extra="ignore")

    incident_id: str
    title: str
    source: Literal["azure_ad", "wazuh", "okta", "generic"] = "azure_ad"
    status: str = "New"
    created_time: datetime
    entities: list[AlertEntity] = Field(default_factory=list)
    alerts: list[dict[str, Any]] = Field(default_factory=list)
    raw_payload: dict[str, Any] = Field(default_factory=dict)


class NormalizedIncident(BaseModel):
    """Incident normalised for the ADTE triage pipeline.

    The canonical, source-agnostic schema the decision engine consumes:
    a single user, their ``events``, and the associated entities.  It can
    be produced from a ``SentinelIncident`` via ``from_sentinel()``, from a
    Wazuh alert via the ``WazuhAdapter``, or constructed directly.

    NIST 800-61 Phase: Detection & Analysis — normalisation is the
    first step in structured incident analysis.

    Attributes:
        incident_id: Unique incident identifier (carried from the source incident).
        user: Primary user principal name under investigation.
        source: Origin platform of the incident (``azure_ad``, ``wazuh``,
            ``okta``, ``generic``) — lets the engine apply source-aware
            normalisation if needed.
        events: Ordered events relevant to this incident.  Each event
            carries a ``type`` so the engine knows how to interpret it.
        entities: Observable entities from the underlying alerts.
        created_time: UTC timestamp of incident creation.

    Note:
        ``severity`` is intentionally NOT an input field — the triage engine
        derives severity from its computed verdict.  Supplying a top-level
        ``severity`` on input is rejected (see ``_reject_severity``).
    """

    incident_id: str
    user: str
    source: Literal["azure_ad", "wazuh", "okta", "generic"] = "generic"
    events: list[SignInMetadata] = Field(default_factory=list)
    entities: list[AlertEntity] = Field(default_factory=list)
    created_time: datetime = Field(default_factory=datetime.utcnow)

    @model_validator(mode="before")
    @classmethod
    def _reject_severity(cls, data: Any) -> Any:
        """Reject any input that supplies a top-level ``severity``.

        Severity is engine-assigned (derived from the computed verdict),
        never accepted from the caller.  Raising here surfaces as an HTTP
        422 at the ``/api/triage`` validation boundary.

        Args:
            data: Raw input passed to model validation/construction.

        Returns:
            The unmodified input when no ``severity`` key is present.

        Raises:
            ValueError: If a top-level ``severity`` key is supplied.
        """
        if isinstance(data, dict) and "severity" in data:
            raise ValueError(
                "severity is engine-assigned and must not be provided on input"
            )
        return data

    @classmethod
    def from_sentinel(cls, incident: SentinelIncident) -> "NormalizedIncident":
        """Create a ``NormalizedIncident`` from a raw Sentinel payload.

        Extraction logic:
        1. The primary user is taken from the first ``Account`` entity.
        2. Events are rebuilt from the ``alerts`` list — each alert's
           ``events`` array (legacy key: ``sign_in_events``) is converted
           to ``SignInMetadata`` instances, defaulting ``type`` to
           ``authentication`` for sign-in-style events.
        3. All entities are carried through as-is.
        4. ``source`` is carried from the Sentinel payload (default
           ``azure_ad``); ``severity`` is dropped (engine-assigned).

        Args:
            incident: The raw Sentinel incident to normalise.

        Returns:
            A ``NormalizedIncident`` ready for the triage pipeline.
        """
        # --- Identify the primary user ---
        user = ""
        for entity in incident.entities:
            if entity.entity_type == "Account":
                user = entity.identifier
                break

        # --- Extract events from alerts ---
        # Accepts the new "events" key, with a backward-compatible fallback
        # to the legacy "sign_in_events" key so pre-migration payloads still
        # normalise cleanly.
        events: list[SignInMetadata] = []
        for alert in incident.alerts:
            raw_events = alert.get("events", alert.get("sign_in_events", []))
            for si in raw_events:
                loc_data = si.get("location", {})
                location = GeoLocation(
                    lat=loc_data.get("lat", 0.0),
                    lon=loc_data.get("lon", 0.0),
                    city=loc_data.get("city", ""),
                    country=loc_data.get("country", ""),
                )
                events.append(
                    SignInMetadata(
                        user_principal_name=si.get("user_principal_name", user),
                        ip_address=si.get("ip_address", ""),
                        type=si.get("type", "authentication"),
                        location=location,
                        device_id=si.get("device_id", ""),
                        device_name=si.get("device_name", ""),
                        user_agent=si.get("user_agent", ""),
                        auth_status=si.get("auth_status"),
                        app_display_name=si.get("app_display_name", ""),
                        event_risk=si.get("event_risk", "none"),
                        technique_ids=[
                            str(t) for t in (si.get("technique_ids") or []) if t
                        ],
                        file=(
                            FileArtifact.model_validate(si["file"])
                            if si.get("file")
                            else None
                        ),
                        timestamp=datetime.fromisoformat(si["timestamp"]),
                    )
                )

        # Sort chronologically.
        events.sort(key=lambda e: e.timestamp)

        return cls(
            incident_id=incident.incident_id,
            user=user,
            source=incident.source,
            events=events,
            entities=incident.entities,
            created_time=incident.created_time,
        )
