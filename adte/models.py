"""Pydantic models shared across ADTE modules.

All data structures that cross module boundaries are defined here
to maintain a single source of truth for the domain model.
"""

from __future__ import annotations

from datetime import datetime, time
from typing import Any, Literal

from pydantic import BaseModel, Field


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


class SignInMetadata(BaseModel):
    """A single Azure AD / Entra ID sign-in event.

    Captures the raw observables from a sign-in log entry that the
    triage engine needs for enrichment and anomaly detection.

    Attributes:
        user_principal_name: UPN of the authenticating user.
        ip_address: Source IP of the sign-in attempt.
        location: Resolved geographic location of the source IP.
        device_id: Entra device-object ID (empty if unmanaged).
        device_name: Human-readable device name.
        user_agent: HTTP User-Agent string from the sign-in request.
        mfa_result: Outcome of the MFA challenge.
        app_display_name: Application the user signed in to.
        risk_state: Entra ID risk assessment at sign-in time.
        timestamp: UTC timestamp of the sign-in event.
    """

    user_principal_name: str
    ip_address: str
    location: GeoLocation | None = None
    device_id: str = ""
    device_name: str = ""
    user_agent: str = ""
    mfa_result: Literal["Success", "Denied", "NotAttempted"] = "NotAttempted"
    app_display_name: str = ""
    risk_state: str = ""
    timestamp: datetime


class AlertEntity(BaseModel):
    """An entity extracted from a Sentinel alert.

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
        severity: Sentinel-assigned severity level.
        status: Current incident status (e.g. 'New', 'Active', 'Closed').
        created_time: UTC timestamp when Sentinel created the incident.
        entities: Observable entities extracted from the underlying alerts.
        alerts: Raw alert payloads associated with this incident.
        raw_payload: Complete original JSON from the Sentinel API.
    """

    incident_id: str
    title: str
    severity: Literal["Low", "Medium", "High", "Critical"]
    status: str = "New"
    created_time: datetime
    entities: list[AlertEntity] = Field(default_factory=list)
    alerts: list[dict[str, Any]] = Field(default_factory=list)
    raw_payload: dict[str, Any] = Field(default_factory=dict)


class NormalizedIncident(BaseModel):
    """Incident normalised for the ADTE triage pipeline.

    Flattens and enriches a ``SentinelIncident`` into the shape the
    decision engine expects: a single user, their sign-in events, and
    the associated entities.

    NIST 800-61 Phase: Detection & Analysis — normalisation is the
    first step in structured incident analysis.

    Attributes:
        incident_id: Unique incident identifier (carried from Sentinel).
        user: Primary user principal name under investigation.
        sign_in_events: Ordered sign-in log entries relevant to this incident.
        entities: Observable entities from the underlying alerts.
        severity: Incident severity level.
        created_time: UTC timestamp of incident creation.
    """

    incident_id: str
    user: str
    sign_in_events: list[SignInMetadata] = Field(default_factory=list)
    entities: list[AlertEntity] = Field(default_factory=list)
    severity: Literal["Low", "Medium", "High", "Critical"] = "Medium"
    created_time: datetime = Field(default_factory=datetime.utcnow)

    @classmethod
    def from_sentinel(cls, incident: SentinelIncident) -> "NormalizedIncident":
        """Create a ``NormalizedIncident`` from a raw Sentinel payload.

        Extraction logic:
        1. The primary user is taken from the first ``Account`` entity.
        2. Sign-in events are rebuilt from the ``alerts`` list — each
           alert that contains sign-in fields is converted to a
           ``SignInMetadata``.
        3. All entities are carried through as-is.

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

        # --- Extract sign-in events from alerts ---
        sign_in_events: list[SignInMetadata] = []
        for alert in incident.alerts:
            sign_ins = alert.get("sign_in_events", [])
            for si in sign_ins:
                loc_data = si.get("location", {})
                location = GeoLocation(
                    lat=loc_data.get("lat", 0.0),
                    lon=loc_data.get("lon", 0.0),
                    city=loc_data.get("city", ""),
                    country=loc_data.get("country", ""),
                )
                sign_in_events.append(
                    SignInMetadata(
                        user_principal_name=si.get("user_principal_name", user),
                        ip_address=si.get("ip_address", ""),
                        location=location,
                        device_id=si.get("device_id", ""),
                        device_name=si.get("device_name", ""),
                        user_agent=si.get("user_agent", ""),
                        mfa_result=si.get("mfa_result", "NotAttempted"),
                        app_display_name=si.get("app_display_name", ""),
                        risk_state=si.get("risk_state", ""),
                        timestamp=datetime.fromisoformat(si["timestamp"]),
                    )
                )

        # Sort chronologically.
        sign_in_events.sort(key=lambda e: e.timestamp)

        return cls(
            incident_id=incident.incident_id,
            user=user,
            sign_in_events=sign_in_events,
            entities=incident.entities,
            severity=incident.severity,
            created_time=incident.created_time,
        )
