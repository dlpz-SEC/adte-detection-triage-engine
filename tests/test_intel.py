"""Tests for adte.intel — threat intelligence and FP registry."""

from __future__ import annotations

import pytest

from adte.intel.sigma_fp_registry import FPRegistry
from adte.intel.threat_intel import check_threat_intel


class TestCheckThreatIntel:
    """Tests for check_threat_intel()."""

    def test_threat_intel_malicious_ip(self) -> None:
        """198.51.100.x IPs are flagged as malicious (C2 range)."""
        result = check_threat_intel("198.51.100.14")
        assert result.is_malicious is True
        assert result.confidence == 0.95
        assert result.source == "mock-c2-feed"
        assert "c2" in result.tags
        assert "cobalt-strike" in result.tags

    def test_threat_intel_clean_ip(self) -> None:
        """8.8.8.8 is not in any mock feed and returns clean."""
        result = check_threat_intel("8.8.8.8")
        assert result.is_malicious is False
        assert result.confidence == 0.0
        assert result.source == "mock-no-match"
        assert result.tags == []

    def test_threat_intel_suspicious_ip(self) -> None:
        """100.64.x.x IPs are suspicious but not confirmed malicious."""
        result = check_threat_intel("100.64.1.1")
        assert result.is_malicious is False
        assert result.confidence == 0.45
        assert "residential-proxy" in result.tags

    def test_threat_intel_tor_exit(self) -> None:
        """185.220.101.x IPs are flagged as Tor exit nodes."""
        result = check_threat_intel("185.220.101.42")
        assert result.is_malicious is True
        assert result.confidence == 0.85
        assert "tor-exit" in result.tags

    def test_threat_intel_invalid_ip(self) -> None:
        """Invalid IP string raises ValueError."""
        with pytest.raises(ValueError, match="Invalid IPv4 address"):
            check_threat_intel("not-an-ip")

    def test_threat_intel_result_has_queried_at(self) -> None:
        """Every result includes a queried_at timestamp."""
        result = check_threat_intel("8.8.8.8")
        assert result.queried_at is not None


class TestFPRegistry:
    """Tests for FPRegistry."""

    def test_fp_registry_corporate_vpn(self, fp_registry: FPRegistry) -> None:
        """10.x.x.x matches corporate_vpn pattern type."""
        assert fp_registry.is_known_benign("10.1.2.3", "corporate_vpn") is True

    def test_fp_registry_rfc1918_all(self, fp_registry: FPRegistry) -> None:
        """All RFC1918 ranges match corporate_vpn."""
        assert fp_registry.is_known_benign("172.16.5.1", "corporate_vpn") is True
        assert fp_registry.is_known_benign("192.168.0.1", "corporate_vpn") is True

    def test_fp_registry_sso_quirk(self, fp_registry: FPRegistry) -> None:
        """Microsoft SSO relay IPs match sso_quirk."""
        assert fp_registry.is_known_benign("20.190.130.1", "sso_quirk") is True

    def test_fp_registry_no_match(self, fp_registry: FPRegistry) -> None:
        """8.8.8.8 does not match any pattern type."""
        assert fp_registry.is_known_benign("8.8.8.8", "corporate_vpn") is False
        assert fp_registry.is_known_benign("8.8.8.8", "sso_quirk") is False

    def test_fp_registry_is_known_benign_any(self, fp_registry: FPRegistry) -> None:
        """is_known_benign_any returns the first matching pattern type."""
        matched, ptype = fp_registry.is_known_benign_any("10.0.0.1")
        assert matched is True
        assert ptype == "corporate_vpn"

    def test_fp_registry_is_known_benign_any_no_match(self, fp_registry: FPRegistry) -> None:
        """is_known_benign_any returns (False, None) for unknown IPs."""
        matched, ptype = fp_registry.is_known_benign_any("8.8.8.8")
        assert matched is False
        assert ptype is None

    def test_fp_registry_pattern_types(self, fp_registry: FPRegistry) -> None:
        """Registry contains expected pattern types."""
        types = fp_registry.pattern_types()
        assert "corporate_vpn" in types
        assert "sso_quirk" in types
        assert "travel_provider" in types
        assert "cloud_nat" in types

    def test_fp_registry_invalid_ip(self, fp_registry: FPRegistry) -> None:
        """Invalid IP raises ValueError."""
        with pytest.raises(ValueError, match="Invalid IPv4 address"):
            fp_registry.is_known_benign("bad", "corporate_vpn")
