"""User behavioral history store.

Provides mock user profiles with realistic baseline data for
development and dry-run triage.  In production this would be
backed by a database or the Microsoft Graph API.

NIST 800-61 Phase: Detection & Analysis — supplies historical
behavioral baselines for anomaly comparison.
"""

from __future__ import annotations

from datetime import datetime, time

from adte.models import DeviceInfo, GeoLocation, LoginHourRange, UserProfile

# ---------------------------------------------------------------------------
# Mock user database
# ---------------------------------------------------------------------------

_MOCK_PROFILES: dict[str, UserProfile] = {
    "alice@contoso.com": UserProfile(
        upn="alice@contoso.com",
        known_locations=[
            GeoLocation(lat=40.7128, lon=-74.0060, city="New York", country="US"),
            GeoLocation(lat=42.3601, lon=-71.0589, city="Boston", country="US"),
        ],
        known_devices=[
            DeviceInfo(
                device_id="dev-001",
                display_name="Alice-Laptop",
                os="Windows 11",
                compliant=True,
            ),
            DeviceInfo(
                device_id="dev-002",
                display_name="Alice-iPhone",
                os="iOS 17",
                compliant=True,
            ),
        ],
        baseline_login_hours=LoginHourRange(
            start=time(8, 0), end=time(18, 0), timezone="America/New_York",
        ),
        last_seen_location=GeoLocation(
            lat=40.7128, lon=-74.0060, city="New York", country="US",
        ),
        last_seen_at=datetime(2025, 1, 15, 14, 30, 0),
        risk_score=0.1,
    ),
    "bob@contoso.com": UserProfile(
        upn="bob@contoso.com",
        known_locations=[
            GeoLocation(lat=51.5074, lon=-0.1278, city="London", country="GB"),
            GeoLocation(lat=48.8566, lon=2.3522, city="Paris", country="FR"),
        ],
        known_devices=[
            DeviceInfo(
                device_id="dev-003",
                display_name="Bob-Surface",
                os="Windows 11",
                compliant=True,
            ),
        ],
        baseline_login_hours=LoginHourRange(
            start=time(9, 0), end=time(17, 30), timezone="Europe/London",
        ),
        last_seen_location=GeoLocation(
            lat=51.5074, lon=-0.1278, city="London", country="GB",
        ),
        last_seen_at=datetime(2025, 1, 15, 9, 0, 0),
        risk_score=0.05,
    ),
    "eve@contoso.com": UserProfile(
        upn="eve@contoso.com",
        known_locations=[
            GeoLocation(lat=35.6762, lon=139.6503, city="Tokyo", country="JP"),
        ],
        known_devices=[
            DeviceInfo(
                device_id="dev-004",
                display_name="Eve-MacBook",
                os="macOS 14",
                compliant=False,
            ),
        ],
        baseline_login_hours=LoginHourRange(
            start=time(10, 0), end=time(22, 0), timezone="Asia/Tokyo",
        ),
        last_seen_location=GeoLocation(
            lat=35.6762, lon=139.6503, city="Tokyo", country="JP",
        ),
        last_seen_at=datetime(2025, 1, 14, 20, 0, 0),
        risk_score=0.35,
    ),
}


def get_user_profile(upn: str) -> UserProfile:
    """Retrieve the behavioral profile for a user.

    In mock mode this returns pre-built sample data.  Unknown UPNs
    receive a minimal empty profile rather than raising an error, since
    a missing baseline is itself a useful triage signal (new account /
    first-time activity).

    Args:
        upn: User principal name (e.g. ``"alice@contoso.com"``).

    Returns:
        A ``UserProfile`` for the requested user.  If the UPN is not
        found in the mock database a default empty profile is returned.
    """
    if upn in _MOCK_PROFILES:
        return _MOCK_PROFILES[upn].model_copy()

    # Unknown user — return a sparse profile.
    return UserProfile(upn=upn)
