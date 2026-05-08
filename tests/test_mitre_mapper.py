"""Tests for adte.intel.mitre_mapper module-level functions.

Covers get_techniques() and get_nist_phase() using the real YAML mapping
file — no mocking required since the file is a committed fixture.
"""

from __future__ import annotations

import unittest

from adte.intel.mitre_mapper import get_nist_phase, get_techniques


class TestGetTechniques(unittest.TestCase):
    """Tests for get_techniques()."""

    def test_impossible_travel_returns_correct_id(self) -> None:
        """impossible_travel maps to T1078.004 (Valid Accounts: Cloud Accounts)."""
        result = get_techniques(["impossible_travel"])
        self.assertEqual(result, ["T1078.004"])

    def test_mfa_fatigue_returns_correct_id(self) -> None:
        """mfa_fatigue maps to T1621 (MFA Request Generation)."""
        result = get_techniques(["mfa_fatigue"])
        self.assertEqual(result, ["T1621"])

    def test_device_novelty_returns_correct_id(self) -> None:
        """device_novelty maps to T1078 (Valid Accounts)."""
        result = get_techniques(["device_novelty"])
        self.assertEqual(result, ["T1078"])

    def test_ip_reputation_returns_correct_id(self) -> None:
        """ip_reputation maps to T1071 (Application Layer Protocol)."""
        result = get_techniques(["ip_reputation"])
        self.assertEqual(result, ["T1071"])

    def test_login_hour_anomaly_returns_correct_id(self) -> None:
        """login_hour_anomaly maps to T1078.004 (Valid Accounts: Cloud Accounts)."""
        result = get_techniques(["login_hour_anomaly"])
        self.assertEqual(result, ["T1078.004"])

    def test_deduplicates_when_signals_share_technique(self) -> None:
        """impossible_travel and login_hour_anomaly both map to T1078.004 — deduplicated."""
        result = get_techniques(["impossible_travel", "login_hour_anomaly"])
        self.assertEqual(result, ["T1078.004"])

    def test_multiple_distinct_signals_return_multiple_ids(self) -> None:
        """Different signals produce multiple distinct technique IDs."""
        result = get_techniques(["mfa_fatigue", "ip_reputation"])
        self.assertIn("T1621", result)
        self.assertIn("T1071", result)
        self.assertEqual(len(result), 2)

    def test_empty_list_returns_empty(self) -> None:
        """Empty input produces empty output."""
        self.assertEqual(get_techniques([]), [])

    def test_unknown_signal_returns_empty_without_raising(self) -> None:
        """Unknown signal name is silently skipped — no exception raised."""
        result = get_techniques(["not_a_real_signal"])
        self.assertEqual(result, [])

    def test_mixed_known_and_unknown_signals(self) -> None:
        """Unknown signals are skipped; known ones are still returned."""
        result = get_techniques(["mfa_fatigue", "not_a_real_signal"])
        self.assertEqual(result, ["T1621"])


class TestGetNistPhase(unittest.TestCase):
    """Tests for get_nist_phase()."""

    def test_high_risk_returns_containment(self) -> None:
        """high_risk verdict maps to Containment phase."""
        self.assertEqual(get_nist_phase("high_risk"), "Containment")

    def test_medium_risk_returns_detection_and_analysis(self) -> None:
        """medium_risk verdict maps to Detection & Analysis phase."""
        self.assertEqual(get_nist_phase("medium_risk"), "Detection & Analysis")

    def test_low_risk_returns_detection_and_analysis(self) -> None:
        """low_risk verdict maps to Detection & Analysis phase."""
        self.assertEqual(get_nist_phase("low_risk"), "Detection & Analysis")

    def test_unknown_verdict_returns_nonempty_string_without_raising(self) -> None:
        """Unrecognised verdict string returns a non-empty string and never raises."""
        result = get_nist_phase("completely_unknown_verdict")
        self.assertIsInstance(result, str)
        self.assertTrue(len(result) > 0)


if __name__ == "__main__":
    unittest.main()
