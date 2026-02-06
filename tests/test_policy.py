"""Tests for adte.decision_policy — scoring policy and thresholds."""

from __future__ import annotations

from adte.decision_policy import (
    SIGNAL_WEIGHTS,
    THRESHOLD_HIGH,
    THRESHOLD_LOW,
    classify_verdict,
    compute_confidence,
)


class TestClassifyVerdict:
    """Tests for classify_verdict()."""

    def test_classify_verdict_low(self) -> None:
        """Scores below THRESHOLD_LOW produce low_risk."""
        assert classify_verdict(0) == "low_risk"
        assert classify_verdict(15) == "low_risk"
        assert classify_verdict(29) == "low_risk"

    def test_classify_verdict_medium(self) -> None:
        """Scores between THRESHOLD_LOW and THRESHOLD_HIGH produce medium_risk."""
        assert classify_verdict(30) == "medium_risk"
        assert classify_verdict(50) == "medium_risk"
        assert classify_verdict(70) == "medium_risk"

    def test_classify_verdict_high(self) -> None:
        """Scores above THRESHOLD_HIGH produce high_risk."""
        assert classify_verdict(71) == "high_risk"
        assert classify_verdict(85) == "high_risk"
        assert classify_verdict(100) == "high_risk"

    def test_threshold_boundaries(self) -> None:
        """Verify exact boundary values."""
        assert classify_verdict(THRESHOLD_LOW - 1) == "low_risk"
        assert classify_verdict(THRESHOLD_LOW) == "medium_risk"
        assert classify_verdict(THRESHOLD_HIGH) == "medium_risk"
        assert classify_verdict(THRESHOLD_HIGH + 1) == "high_risk"


class TestComputeConfidence:
    """Tests for compute_confidence()."""

    def test_compute_confidence_full_coverage(self) -> None:
        """All signals evaluated with perfect agreement → 100%."""
        result = compute_confidence(
            signals_present=5, signals_total=5, signal_agreement=1.0,
        )
        assert result == 100

    def test_compute_confidence_partial_coverage(self) -> None:
        """3 of 5 signals evaluated with perfect agreement → 60%."""
        result = compute_confidence(
            signals_present=3, signals_total=5, signal_agreement=1.0,
        )
        assert result == 60

    def test_compute_confidence_half_agreement(self) -> None:
        """Full coverage with 50% agreement → 50%."""
        result = compute_confidence(
            signals_present=5, signals_total=5, signal_agreement=0.5,
        )
        assert result == 50

    def test_compute_confidence_zero_signals(self) -> None:
        """Zero signals total returns 0."""
        result = compute_confidence(
            signals_present=0, signals_total=0, signal_agreement=1.0,
        )
        assert result == 0

    def test_compute_confidence_clamped(self) -> None:
        """Result is clamped to 0-100."""
        result = compute_confidence(
            signals_present=5, signals_total=5, signal_agreement=1.5,
        )
        assert result == 100

    def test_signal_weights_sum_to_100(self) -> None:
        """All signal weights should sum to 100 for intuitive scaling."""
        assert sum(SIGNAL_WEIGHTS.values()) == 100
