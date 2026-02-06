"""Geographic utility functions for travel-speed anomaly detection.

Provides haversine distance calculation and impossible-travel checks
used by the triage engine to flag physically implausible login
sequences.

NIST 800-61 Phase: Detection & Analysis — supports geographic
anomaly indicators during incident triage.
"""

from __future__ import annotations

import math


# Earth's mean radius in kilometres (WGS-84 approximation).
_EARTH_RADIUS_KM: float = 6_371.0


def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate the great-circle distance between two points on Earth.

    Uses the haversine formula, which gives good accuracy for all
    distances and is numerically stable for small separations.

    Args:
        lat1: Latitude of the first point in decimal degrees.
        lon1: Longitude of the first point in decimal degrees.
        lat2: Latitude of the second point in decimal degrees.
        lon2: Longitude of the second point in decimal degrees.

    Returns:
        Distance in kilometres (always >= 0).
    """
    lat1_r, lon1_r = math.radians(lat1), math.radians(lon1)
    lat2_r, lon2_r = math.radians(lat2), math.radians(lon2)

    dlat = lat2_r - lat1_r
    dlon = lon2_r - lon1_r

    a = math.sin(dlat / 2) ** 2 + math.cos(lat1_r) * math.cos(lat2_r) * math.sin(dlon / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    return _EARTH_RADIUS_KM * c


def calculate_travel_speed(distance_km: float, time_delta_minutes: float) -> float:
    """Derive the average speed required to cover a distance in a given time.

    Args:
        distance_km: Distance in kilometres (must be >= 0).
        time_delta_minutes: Elapsed time in minutes (must be > 0).

    Returns:
        Speed in kilometres per hour.

    Raises:
        ValueError: If *distance_km* is negative or *time_delta_minutes*
            is not positive.
    """
    if distance_km < 0:
        raise ValueError(f"distance_km must be >= 0, got {distance_km}")
    if time_delta_minutes <= 0:
        raise ValueError(f"time_delta_minutes must be > 0, got {time_delta_minutes}")

    hours = time_delta_minutes / 60.0
    return distance_km / hours


def is_impossible_travel(speed_kmh: float, threshold: float = 800.0) -> bool:
    """Determine whether a travel speed is physically implausible.

    The default threshold of 800 km/h approximates the cruising speed
    of a commercial airliner.  Speeds above this are considered
    impossible for legitimate human travel and strongly suggest
    credential use from a second location.

    Args:
        speed_kmh: Computed travel speed in km/h.
        threshold: Maximum plausible speed in km/h.  Defaults to
            ``800.0`` (commercial aviation).

    Returns:
        ``True`` if *speed_kmh* exceeds the *threshold*.
    """
    return speed_kmh > threshold
