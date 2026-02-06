"""Tests for adte.utils.geo — geographic utilities."""

from __future__ import annotations

import pytest

from adte.utils.geo import (
    calculate_travel_speed,
    haversine_distance,
    is_impossible_travel,
)


class TestHaversineDistance:
    """Tests for haversine_distance()."""

    def test_haversine_nyc_to_london(self) -> None:
        """NYC (40.7128, -74.006) to London (51.5074, -0.1278) is ~5570 km."""
        dist = haversine_distance(40.7128, -74.006, 51.5074, -0.1278)
        assert 5550 < dist < 5600

    def test_haversine_same_point(self) -> None:
        """Distance from a point to itself is 0."""
        dist = haversine_distance(40.7128, -74.006, 40.7128, -74.006)
        assert dist == 0.0

    def test_haversine_antipodal(self) -> None:
        """Antipodal points are ~20015 km apart (half circumference)."""
        dist = haversine_distance(0.0, 0.0, 0.0, 180.0)
        assert 20000 < dist < 20100

    def test_haversine_short_distance(self) -> None:
        """Short distances should be numerically stable."""
        # ~1.1 km apart within Manhattan
        dist = haversine_distance(40.7580, -73.9855, 40.7484, -73.9856)
        assert 0.5 < dist < 2.0


class TestCalculateTravelSpeed:
    """Tests for calculate_travel_speed()."""

    def test_calculate_travel_speed_basic(self) -> None:
        """600 km in 60 min = 600 km/h."""
        speed = calculate_travel_speed(600, 60)
        assert speed == pytest.approx(600.0)

    def test_calculate_travel_speed_fast(self) -> None:
        """5000 km in 30 min = 10000 km/h."""
        speed = calculate_travel_speed(5000, 30)
        assert speed == pytest.approx(10000.0)

    def test_calculate_travel_speed_zero_distance(self) -> None:
        """Zero distance returns 0 km/h."""
        speed = calculate_travel_speed(0, 60)
        assert speed == 0.0

    def test_calculate_travel_speed_negative_distance(self) -> None:
        """Negative distance raises ValueError."""
        with pytest.raises(ValueError, match="distance_km must be >= 0"):
            calculate_travel_speed(-100, 60)

    def test_calculate_travel_speed_zero_time(self) -> None:
        """Zero time raises ValueError."""
        with pytest.raises(ValueError, match="time_delta_minutes must be > 0"):
            calculate_travel_speed(100, 0)

    def test_calculate_travel_speed_negative_time(self) -> None:
        """Negative time raises ValueError."""
        with pytest.raises(ValueError, match="time_delta_minutes must be > 0"):
            calculate_travel_speed(100, -10)


class TestIsImpossibleTravel:
    """Tests for is_impossible_travel()."""

    def test_above_threshold(self) -> None:
        """Speed above 800 km/h is impossible travel."""
        assert is_impossible_travel(801.0) is True

    def test_below_threshold(self) -> None:
        """Speed below 800 km/h is plausible."""
        assert is_impossible_travel(500.0) is False

    def test_at_threshold(self) -> None:
        """Speed exactly at 800 km/h is NOT impossible (boundary)."""
        assert is_impossible_travel(800.0) is False

    def test_custom_threshold(self) -> None:
        """Custom threshold is respected."""
        assert is_impossible_travel(600.0, threshold=500.0) is True
        assert is_impossible_travel(400.0, threshold=500.0) is False
