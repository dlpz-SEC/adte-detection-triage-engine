"""Tests for adte.intel — threat intelligence and FP registry."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
import responses as resp

from adte.intel.abuseipdb import AbuseIPDBClient
from adte.intel.aggregator import ThreatIntelAggregator
from adte.intel.otx import OTXClient
from adte.intel.sigma_fp_registry import FPRegistry
from adte.intel.threat_intel import check_threat_intel
from adte.intel.virustotal import VirusTotalClient
from adte.models import ThreatIntelResult


# ---------------------------------------------------------------------------
# Existing mock-fallback tests — must remain unchanged
# ---------------------------------------------------------------------------


class TestCheckThreatIntel:
    """Tests for check_threat_intel() in mock-fallback mode (no API keys set)."""

    def test_threat_intel_malicious_ip(self) -> None:
        """198.51.100.x IPs are flagged as malicious (C2 range)."""
        result = check_threat_intel("198.51.100.14")
        assert result.is_malicious is True
        assert result.confidence == 0.95
        assert result.source == "synthetic-c2-feed"
        assert "c2" in result.tags
        assert "cobalt-strike" in result.tags

    def test_threat_intel_clean_ip(self) -> None:
        """8.8.8.8 is not in any mock feed and returns clean."""
        result = check_threat_intel("8.8.8.8")
        assert result.is_malicious is False
        assert result.confidence == 0.0
        assert result.source == "synthetic-no-match"
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


# ---------------------------------------------------------------------------
# AbuseIPDB client tests
# ---------------------------------------------------------------------------


class TestAbuseIPDBClient:
    """Tests for AbuseIPDBClient using mocked HTTP responses."""

    @resp.activate
    def test_malicious_ip_returns_malicious_result(self) -> None:
        """abuseConfidenceScore 80 → confidence 0.80, is_malicious True."""
        resp.add(
            resp.GET,
            "https://api.abuseipdb.com/api/v2/check",
            json={
                "data": {
                    "abuseConfidenceScore": 80,
                    "isPublic": True,
                    "usageType": "Data Center/Web Hosting/Transit",
                    "domain": "example.com",
                    "isTor": False,
                }
            },
            status=200,
        )
        result = AbuseIPDBClient(api_key="fake-key").check("1.2.3.4")
        assert result.is_malicious is True
        assert result.confidence == pytest.approx(0.8)
        assert result.source == "abuseipdb"

    @resp.activate
    def test_clean_ip_returns_benign_result(self) -> None:
        """abuseConfidenceScore 10 → confidence 0.10, is_malicious False."""
        resp.add(
            resp.GET,
            "https://api.abuseipdb.com/api/v2/check",
            json={"data": {"abuseConfidenceScore": 10, "isTor": False, "usageType": "", "domain": ""}},
            status=200,
        )
        result = AbuseIPDBClient(api_key="fake-key").check("8.8.8.8")
        assert result.is_malicious is False
        assert result.confidence == pytest.approx(0.1)
        assert result.source == "abuseipdb"

    @resp.activate
    def test_tor_exit_tag_added(self) -> None:
        """isTor=True adds 'tor-exit' to tags."""
        resp.add(
            resp.GET,
            "https://api.abuseipdb.com/api/v2/check",
            json={"data": {"abuseConfidenceScore": 85, "isTor": True, "usageType": "", "domain": ""}},
            status=200,
        )
        result = AbuseIPDBClient(api_key="fake-key").check("185.220.101.1")
        assert "tor-exit" in result.tags

    @resp.activate
    def test_domain_tag_included(self) -> None:
        """Non-empty domain field is added as 'domain:{value}' tag."""
        resp.add(
            resp.GET,
            "https://api.abuseipdb.com/api/v2/check",
            json={"data": {"abuseConfidenceScore": 50, "isTor": False, "usageType": "", "domain": "badactor.ru"}},
            status=200,
        )
        result = AbuseIPDBClient(api_key="fake-key").check("5.6.7.8")
        assert "domain:badactor.ru" in result.tags

    @resp.activate
    def test_http_error_returns_neutral_result(self) -> None:
        """HTTP 403 returns neutral result with source 'abuseipdb-error'."""
        resp.add(resp.GET, "https://api.abuseipdb.com/api/v2/check", status=403)
        result = AbuseIPDBClient(api_key="bad-key").check("1.2.3.4")
        assert result.is_malicious is False
        assert result.confidence == 0.0
        assert result.source == "abuseipdb-error"

    @resp.activate
    def test_network_error_returns_neutral_result(self) -> None:
        """requests.ConnectionError returns a neutral result without raising."""
        import requests as _req
        resp.add(
            resp.GET,
            "https://api.abuseipdb.com/api/v2/check",
            body=_req.exceptions.ConnectionError("timeout"),
        )
        result = AbuseIPDBClient(api_key="fake-key").check("1.2.3.4")
        assert result.source == "abuseipdb-error"
        assert result.confidence == 0.0

    def test_no_api_key_returns_neutral_result(self) -> None:
        """Missing API key returns neutral result without making HTTP calls."""
        result = AbuseIPDBClient(api_key=None).check("1.2.3.4")
        assert result.source == "abuseipdb-error"


# ---------------------------------------------------------------------------
# VirusTotal client tests
# ---------------------------------------------------------------------------


class TestVirusTotalClient:
    """Tests for VirusTotalClient — always use rate_limit_sleep=0."""

    @resp.activate
    def test_malicious_score_computed_correctly(self) -> None:
        """Score = 10 / (10+2+40+48) = 0.10, is_malicious False."""
        resp.add(
            resp.GET,
            "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4",
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 10,
                            "suspicious": 2,
                            "undetected": 40,
                            "harmless": 48,
                            "timeout": 0,
                        }
                    }
                }
            },
            status=200,
        )
        result = VirusTotalClient(api_key="fake-key", rate_limit_sleep=0).check("1.2.3.4")
        assert result.confidence == pytest.approx(0.1)
        assert result.is_malicious is False
        assert result.source == "virustotal"

    @resp.activate
    def test_majority_malicious_flagged(self) -> None:
        """Score = 55 / (55+5+30+10) = 0.55 → is_malicious True."""
        resp.add(
            resp.GET,
            "https://www.virustotal.com/api/v3/ip_addresses/5.6.7.8",
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 55,
                            "suspicious": 5,
                            "undetected": 30,
                            "harmless": 10,
                            "timeout": 2,
                        }
                    }
                }
            },
            status=200,
        )
        result = VirusTotalClient(api_key="fake-key", rate_limit_sleep=0).check("5.6.7.8")
        assert result.confidence == pytest.approx(0.55)
        assert result.is_malicious is True

    @resp.activate
    def test_zero_engines_returns_zero_confidence(self) -> None:
        """All-zero stats produce confidence=0.0 without division error."""
        resp.add(
            resp.GET,
            "https://www.virustotal.com/api/v3/ip_addresses/9.9.9.9",
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 0,
                            "suspicious": 0,
                            "undetected": 0,
                            "harmless": 0,
                            "timeout": 0,
                        }
                    }
                }
            },
            status=200,
        )
        result = VirusTotalClient(api_key="fake-key", rate_limit_sleep=0).check("9.9.9.9")
        assert result.confidence == 0.0
        assert result.is_malicious is False

    @resp.activate
    def test_http_error_returns_neutral(self) -> None:
        """HTTP 429 returns neutral result with source 'virustotal-error'."""
        resp.add(
            resp.GET,
            "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4",
            status=429,
        )
        result = VirusTotalClient(api_key="fake-key", rate_limit_sleep=0).check("1.2.3.4")
        assert result.source == "virustotal-error"
        assert result.confidence == 0.0

    def test_no_api_key_returns_neutral_result(self) -> None:
        """Missing API key returns neutral result without making HTTP calls."""
        result = VirusTotalClient(api_key=None, rate_limit_sleep=0).check("1.2.3.4")
        assert result.source == "virustotal-error"


# ---------------------------------------------------------------------------
# OTX client tests
# ---------------------------------------------------------------------------


class TestOTXClient:
    """Tests for OTXClient using mocked HTTP responses."""

    @resp.activate
    def test_pulse_count_determines_confidence(self) -> None:
        """7 pulses → confidence=0.7, tags from pulses."""
        resp.add(
            resp.GET,
            "https://otx.alienvault.com/api/v1/indicators/IPv4/1.2.3.4/general",
            json={
                "pulse_info": {
                    "count": 7,
                    "pulses": [
                        {"tags": ["c2", "botnet"]},
                        {"tags": ["c2"]},
                    ],
                }
            },
            status=200,
        )
        result = OTXClient(api_key=None).check("1.2.3.4")
        assert result.confidence == pytest.approx(0.7)
        assert result.is_malicious is True
        assert "c2" in result.tags
        assert "botnet" in result.tags
        assert result.tags.count("c2") == 1  # deduplicated

    @resp.activate
    def test_confidence_capped_at_one(self) -> None:
        """15 pulses → confidence capped at 1.0."""
        resp.add(
            resp.GET,
            "https://otx.alienvault.com/api/v1/indicators/IPv4/9.9.9.9/general",
            json={"pulse_info": {"count": 15, "pulses": []}},
            status=200,
        )
        result = OTXClient(api_key=None).check("9.9.9.9")
        assert result.confidence == pytest.approx(1.0)

    @resp.activate
    def test_zero_pulses_returns_benign(self) -> None:
        """0 pulses → confidence=0.0, is_malicious False."""
        resp.add(
            resp.GET,
            "https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general",
            json={"pulse_info": {"count": 0, "pulses": []}},
            status=200,
        )
        result = OTXClient(api_key=None).check("8.8.8.8")
        assert result.confidence == 0.0
        assert result.is_malicious is False
        assert result.source == "otx"

    @resp.activate
    def test_api_key_sent_in_header_when_configured(self) -> None:
        """API key is included in the X-OTX-API-KEY header when set."""
        resp.add(
            resp.GET,
            "https://otx.alienvault.com/api/v1/indicators/IPv4/1.1.1.1/general",
            json={"pulse_info": {"count": 0, "pulses": []}},
            status=200,
        )
        OTXClient(api_key="secret-key").check("1.1.1.1")
        assert resp.calls[0].request.headers.get("X-OTX-API-KEY") == "secret-key"

    @resp.activate
    def test_no_api_key_omits_header(self) -> None:
        """X-OTX-API-KEY header is absent when no key is configured."""
        resp.add(
            resp.GET,
            "https://otx.alienvault.com/api/v1/indicators/IPv4/1.1.1.1/general",
            json={"pulse_info": {"count": 0, "pulses": []}},
            status=200,
        )
        OTXClient(api_key=None).check("1.1.1.1")
        assert "X-OTX-API-KEY" not in resp.calls[0].request.headers

    @resp.activate
    def test_http_error_returns_neutral(self) -> None:
        """HTTP 500 returns neutral result with source 'otx-error'."""
        resp.add(
            resp.GET,
            "https://otx.alienvault.com/api/v1/indicators/IPv4/1.2.3.4/general",
            status=500,
        )
        result = OTXClient(api_key=None).check("1.2.3.4")
        assert result.source == "otx-error"
        assert result.confidence == 0.0

    @resp.activate
    def test_pulses_missing_tags_key_handled(self) -> None:
        """Pulses without a 'tags' key do not raise KeyError."""
        resp.add(
            resp.GET,
            "https://otx.alienvault.com/api/v1/indicators/IPv4/2.2.2.2/general",
            json={"pulse_info": {"count": 2, "pulses": [{"name": "pulse-without-tags"}]}},
            status=200,
        )
        result = OTXClient(api_key=None).check("2.2.2.2")
        assert result.tags == []


# ---------------------------------------------------------------------------
# ThreatIntelAggregator tests
# ---------------------------------------------------------------------------


def _make_result(ip: str, source: str, confidence: float = 0.0, is_malicious: bool = False, tags: list[str] | None = None) -> ThreatIntelResult:
    """Helper to build a ThreatIntelResult for test assertions."""
    return ThreatIntelResult(
        ip=ip,
        is_malicious=is_malicious,
        confidence=confidence,
        source=source,
        tags=tags or [],
        queried_at=datetime.now(timezone.utc),
    )


class TestThreatIntelAggregator:
    """Tests for ThreatIntelAggregator."""

    # -- Mock fallback --

    def test_fallback_to_mock_when_no_keys(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """With no keys set, mock fallback returns known synthetic-c2-feed result."""
        monkeypatch.delenv("ADTE_ABUSEIPDB_KEY", raising=False)
        monkeypatch.delenv("ADTE_VT_API_KEY", raising=False)
        monkeypatch.delenv("ADTE_OTX_KEY", raising=False)
        agg = ThreatIntelAggregator.from_env()
        assert agg._use_mock is True
        result = agg.check("198.51.100.14")
        assert result.is_malicious is True
        assert result.source == "synthetic-c2-feed"

    # -- from_env key reading --

    def test_from_env_reads_keys(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """from_env() populates clients when env vars are set."""
        monkeypatch.setenv("ADTE_ABUSEIPDB_KEY", "abuse-key")
        monkeypatch.setenv("ADTE_VT_API_KEY", "vt-key")
        monkeypatch.setenv("ADTE_OTX_KEY", "otx-key")
        agg = ThreatIntelAggregator.from_env()
        assert agg._use_mock is False
        # AbuseIPDB + VirusTotal + OTX
        assert len(agg._clients) == 3

    def test_from_env_only_otx_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Setting only ADTE_OTX_KEY activates live mode with OTX client only."""
        monkeypatch.delenv("ADTE_ABUSEIPDB_KEY", raising=False)
        monkeypatch.delenv("ADTE_VT_API_KEY", raising=False)
        monkeypatch.setenv("ADTE_OTX_KEY", "otx-key")
        agg = ThreatIntelAggregator.from_env()
        assert agg._use_mock is False
        assert len(agg._clients) == 1
        assert isinstance(agg._clients[0], OTXClient)

    # -- Aggregation logic --

    def test_aggregates_two_sources(self) -> None:
        """Confidence is averaged and tags merged across two good sources."""
        mock_abuse = MagicMock()
        mock_abuse.check.return_value = _make_result(
            "1.2.3.4", "abuseipdb", confidence=0.8, is_malicious=True, tags=["scanner"]
        )
        mock_vt = MagicMock()
        mock_vt.check.return_value = _make_result(
            "1.2.3.4", "virustotal", confidence=0.3, is_malicious=False, tags=["hosting"]
        )
        agg = ThreatIntelAggregator.__new__(ThreatIntelAggregator)
        agg._use_mock = False
        agg._clients = [mock_abuse, mock_vt]
        agg._cache = {}

        result = agg.check("1.2.3.4")
        assert result.confidence == pytest.approx(0.55)
        assert result.is_malicious is True  # any source malicious → True
        assert "scanner" in result.tags
        assert "hosting" in result.tags
        assert result.source == "abuseipdb,virustotal"

    def test_any_malicious_overrides_low_average(self) -> None:
        """is_malicious=True if any source reports malicious, even if avg < 0.5."""
        mock_a = MagicMock()
        mock_a.check.return_value = _make_result("1.2.3.4", "abuseipdb", confidence=0.9, is_malicious=True)
        mock_b = MagicMock()
        mock_b.check.return_value = _make_result("1.2.3.4", "virustotal", confidence=0.0, is_malicious=False)
        agg = ThreatIntelAggregator.__new__(ThreatIntelAggregator)
        agg._use_mock = False
        agg._clients = [mock_a, mock_b]
        agg._cache = {}

        result = agg.check("1.2.3.4")
        # avg = 0.45 < 0.5, but any_malicious=True
        assert result.is_malicious is True

    def test_all_sources_error_falls_back_to_mock(self) -> None:
        """When all clients return error results, mock lookup is used."""
        mock_client = MagicMock()
        mock_client.check.return_value = _make_result("8.8.8.8", "abuseipdb-error")
        agg = ThreatIntelAggregator.__new__(ThreatIntelAggregator)
        agg._use_mock = False
        agg._clients = [mock_client]
        agg._cache = {}

        result = agg.check("8.8.8.8")
        assert result.source == "synthetic-no-match"

    def test_tags_deduplicated_across_sources(self) -> None:
        """Duplicate tags from different sources appear only once."""
        mock_a = MagicMock()
        mock_a.check.return_value = _make_result("1.2.3.4", "abuseipdb", tags=["c2", "scanner"])
        mock_b = MagicMock()
        mock_b.check.return_value = _make_result("1.2.3.4", "otx", tags=["c2", "botnet"])
        agg = ThreatIntelAggregator.__new__(ThreatIntelAggregator)
        agg._use_mock = False
        agg._clients = [mock_a, mock_b]
        agg._cache = {}

        result = agg.check("1.2.3.4")
        assert result.tags.count("c2") == 1
        assert "scanner" in result.tags
        assert "botnet" in result.tags

    # -- Cache tests --

    def test_cache_deduplicates_client_calls(self) -> None:
        """Two calls with the same IP trigger exactly one round of client.check()."""
        mock_client = MagicMock()
        mock_client.check.return_value = _make_result("1.2.3.4", "abuseipdb", confidence=0.8, is_malicious=True)
        agg = ThreatIntelAggregator.__new__(ThreatIntelAggregator)
        agg._use_mock = False
        agg._clients = [mock_client]
        agg._cache = {}

        result1 = agg.check("1.2.3.4")
        result2 = agg.check("1.2.3.4")

        assert mock_client.check.call_count == 1
        assert result1 is result2  # same object returned from cache

    def test_cache_isolates_different_ips(self) -> None:
        """Cached result for one IP does not affect lookups for another."""
        mock_client = MagicMock()
        mock_client.check.side_effect = [
            _make_result("1.2.3.4", "abuseipdb", confidence=0.8, is_malicious=True),
            _make_result("5.6.7.8", "abuseipdb", confidence=0.1, is_malicious=False),
        ]
        agg = ThreatIntelAggregator.__new__(ThreatIntelAggregator)
        agg._use_mock = False
        agg._clients = [mock_client]
        agg._cache = {}

        r1 = agg.check("1.2.3.4")
        r2 = agg.check("5.6.7.8")

        assert mock_client.check.call_count == 2
        assert r1.is_malicious is True
        assert r2.is_malicious is False

    # -- Private IP short-circuit --

    def test_loopback_ip_short_circuited(self) -> None:
        """127.x.x.x returns private-ip result without querying clients."""
        mock_client = MagicMock()
        agg = ThreatIntelAggregator.__new__(ThreatIntelAggregator)
        agg._use_mock = False
        agg._clients = [mock_client]
        agg._cache = {}

        result = agg.check("127.0.0.1")
        mock_client.check.assert_not_called()
        assert result.source == "private-ip"
        assert result.is_malicious is False
        assert "private" in result.tags

    def test_rfc1918_10_short_circuited(self) -> None:
        """10.x.x.x returns private-ip result."""
        mock_client = MagicMock()
        agg = ThreatIntelAggregator.__new__(ThreatIntelAggregator)
        agg._use_mock = False
        agg._clients = [mock_client]
        agg._cache = {}

        result = agg.check("10.0.0.1")
        mock_client.check.assert_not_called()
        assert result.source == "private-ip"

    def test_rfc1918_172_short_circuited(self) -> None:
        """172.16.x.x returns private-ip result."""
        mock_client = MagicMock()
        agg = ThreatIntelAggregator.__new__(ThreatIntelAggregator)
        agg._use_mock = False
        agg._clients = [mock_client]
        agg._cache = {}

        result = agg.check("172.16.5.10")
        mock_client.check.assert_not_called()
        assert result.source == "private-ip"

    def test_rfc1918_192_168_short_circuited(self) -> None:
        """192.168.x.x returns private-ip result."""
        mock_client = MagicMock()
        agg = ThreatIntelAggregator.__new__(ThreatIntelAggregator)
        agg._use_mock = False
        agg._clients = [mock_client]
        agg._cache = {}

        result = agg.check("192.168.1.100")
        mock_client.check.assert_not_called()
        assert result.source == "private-ip"

    def test_private_ip_cached(self) -> None:
        """Private IP result is cached; second call does not re-compute."""
        mock_client = MagicMock()
        agg = ThreatIntelAggregator.__new__(ThreatIntelAggregator)
        agg._use_mock = False
        agg._clients = [mock_client]
        agg._cache = {}

        r1 = agg.check("10.0.0.1")
        r2 = agg.check("10.0.0.1")
        mock_client.check.assert_not_called()
        assert r1 is r2

    def test_public_ip_not_short_circuited(self) -> None:
        """Public IP addresses are not treated as private."""
        mock_client = MagicMock()
        mock_client.check.return_value = _make_result("8.8.8.8", "abuseipdb")
        agg = ThreatIntelAggregator.__new__(ThreatIntelAggregator)
        agg._use_mock = False
        agg._clients = [mock_client]
        agg._cache = {}

        agg.check("8.8.8.8")
        mock_client.check.assert_called_once_with("8.8.8.8")


# ---------------------------------------------------------------------------
# FP registry tests (unchanged)
# ---------------------------------------------------------------------------


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
