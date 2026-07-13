"""Tests for adte.intel file-hash reputation lookups (Phase 32b).

Mirrors tests/test_intel.py's structure and conventions for the new
check_file_hash() / VirusTotalClient.check_hash() / Aggregator.check_hash()
path.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
import responses as resp
from unittest.mock import MagicMock

from adte.intel.aggregator import ThreatIntelAggregator, _DailyQuota
from adte.intel.threat_intel import check_file_hash
from adte.intel.virustotal import VirusTotalClient
from adte.models import FileReputationResult, ThreatIntelResult

# Well-known EICAR test-file digests, present in the mock hash table.
_EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
_EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"
_EICAR_SHA1 = "3395856ce81f2b7382dee72602f798b642f14140"
_UNKNOWN_SHA256 = "0" * 64


# ---------------------------------------------------------------------------
# check_file_hash() — validation + mock-fallback mode
# ---------------------------------------------------------------------------


class TestCheckFileHash:
    """Tests for check_file_hash() in mock-fallback mode (no API keys set)."""

    def test_valid_md5_recognized(self) -> None:
        """A 32-char hex string is classified as md5."""
        result = check_file_hash(_EICAR_MD5)
        assert result.hash_type == "md5"
        assert result.is_malicious is True

    def test_valid_sha1_recognized(self) -> None:
        """A 40-char hex string is classified as sha1."""
        result = check_file_hash(_EICAR_SHA1)
        assert result.hash_type == "sha1"
        assert result.is_malicious is True

    def test_valid_sha256_recognized(self) -> None:
        """A 64-char hex string is classified as sha256."""
        result = check_file_hash(_EICAR_SHA256)
        assert result.hash_type == "sha256"
        assert result.is_malicious is True

    def test_uppercase_input_lowercased_in_result(self) -> None:
        """Uppercase hex input is normalised to lowercase before lookup."""
        result = check_file_hash(_EICAR_MD5.upper())
        assert result.file_hash == _EICAR_MD5
        assert result.is_malicious is True  # still matches after normalisation

    def test_invalid_too_short_raises(self) -> None:
        """A hex string shorter than 32 chars raises ValueError."""
        with pytest.raises(ValueError, match="Invalid file hash"):
            check_file_hash("abc123")

    def test_invalid_non_hex_raises(self) -> None:
        """A 32-char string with non-hex characters raises ValueError."""
        with pytest.raises(ValueError, match="Invalid file hash"):
            check_file_hash("g" * 32)

    def test_invalid_empty_raises(self) -> None:
        """An empty string raises ValueError."""
        with pytest.raises(ValueError, match="Invalid file hash"):
            check_file_hash("")

    def test_invalid_ipv4_string_raises(self) -> None:
        """An IPv4 address string is not a valid hash and raises ValueError."""
        with pytest.raises(ValueError, match="Invalid file hash"):
            check_file_hash("198.51.100.14")


# ---------------------------------------------------------------------------
# VirusTotalClient.check_hash() tests
# ---------------------------------------------------------------------------


class TestVirusTotalClientHash:
    """Tests for VirusTotalClient.check_hash — always use rate_limit_sleep=0."""

    @resp.activate
    def test_malicious_hash_returns_malicious_result(self) -> None:
        """58 malicious / 72 total engines -> is_malicious True, positives=58."""
        resp.add(
            resp.GET,
            f"https://www.virustotal.com/api/v3/files/{_EICAR_SHA256}",
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 58,
                            "suspicious": 2,
                            "undetected": 10,
                            "harmless": 2,
                            "timeout": 0,
                        },
                        "popular_threat_classification": {
                            "suggested_threat_label": "trojan.eicar/test"
                        },
                    }
                }
            },
            status=200,
        )
        result = VirusTotalClient(api_key="fake-key", rate_limit_sleep=0).check_hash(
            _EICAR_SHA256, "sha256"
        )
        assert result.is_malicious is True
        assert result.positives == 58
        assert result.total == 72
        assert result.confidence == pytest.approx(58 / 72)
        assert result.source == "virustotal"
        assert result.permalink == f"https://www.virustotal.com/gui/file/{_EICAR_SHA256}"
        assert result.tags == ["trojan.eicar/test"]

    @resp.activate
    def test_clean_hash_returns_benign_result(self) -> None:
        """0 malicious engines -> is_malicious False, confidence 0.0, no tags."""
        resp.add(
            resp.GET,
            f"https://www.virustotal.com/api/v3/files/{_EICAR_MD5}",
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 0,
                            "suspicious": 0,
                            "undetected": 68,
                            "harmless": 4,
                            "timeout": 0,
                        }
                    }
                }
            },
            status=200,
        )
        result = VirusTotalClient(api_key="fake-key", rate_limit_sleep=0).check_hash(
            _EICAR_MD5, "md5"
        )
        assert result.is_malicious is False
        assert result.confidence == 0.0
        assert result.positives == 0
        assert result.tags == []

    @resp.activate
    def test_http_404_returns_neutral(self) -> None:
        """HTTP 404 (hash unknown to VT) returns neutral virustotal-error."""
        resp.add(
            resp.GET,
            f"https://www.virustotal.com/api/v3/files/{_EICAR_SHA1}",
            status=404,
        )
        result = VirusTotalClient(api_key="fake-key", rate_limit_sleep=0).check_hash(
            _EICAR_SHA1, "sha1"
        )
        assert result.source == "virustotal-error"
        assert result.confidence == 0.0
        assert result.is_malicious is False

    @resp.activate
    def test_http_500_returns_neutral(self) -> None:
        """HTTP 500 returns neutral virustotal-error."""
        resp.add(
            resp.GET,
            f"https://www.virustotal.com/api/v3/files/{_EICAR_SHA1}",
            status=500,
        )
        result = VirusTotalClient(api_key="fake-key", rate_limit_sleep=0).check_hash(
            _EICAR_SHA1, "sha1"
        )
        assert result.source == "virustotal-error"

    def test_no_api_key_returns_neutral_without_http_call(self) -> None:
        """Missing API key returns neutral result without making HTTP calls."""
        result = VirusTotalClient(api_key=None, rate_limit_sleep=0).check_hash(
            _EICAR_MD5, "md5"
        )
        assert result.source == "virustotal-error"
        assert result.file_hash == _EICAR_MD5
        assert result.hash_type == "md5"


# ---------------------------------------------------------------------------
# ThreatIntelAggregator.check_hash() tests
# ---------------------------------------------------------------------------


class TestThreatIntelAggregatorHash:
    """Tests for ThreatIntelAggregator.check_hash()."""

    # -- Mock mode --

    def test_mock_mode_eicar_sha256_malicious(self) -> None:
        """EICAR sha256 hits the mock table: malicious, confidence 0.95."""
        agg = ThreatIntelAggregator()  # no keys -> mock mode
        result = agg.check_hash(_EICAR_SHA256, "sha256")
        assert result.is_malicious is True
        assert result.confidence == pytest.approx(0.95)
        assert result.source == "mock-vt-file-feed"

    def test_mock_mode_eicar_md5_malicious(self) -> None:
        """EICAR md5 hits the mock table: malicious, confidence 0.95."""
        agg = ThreatIntelAggregator()
        result = agg.check_hash(_EICAR_MD5, "md5")
        assert result.is_malicious is True
        assert result.confidence == pytest.approx(0.95)

    def test_mock_mode_eicar_sha1_malicious(self) -> None:
        """EICAR sha1 hits the mock table: malicious, confidence 0.95."""
        agg = ThreatIntelAggregator()
        result = agg.check_hash(_EICAR_SHA1, "sha1")
        assert result.is_malicious is True
        assert result.confidence == pytest.approx(0.95)

    def test_mock_mode_unknown_hash_clean(self) -> None:
        """A hash absent from the mock table returns a clean result."""
        agg = ThreatIntelAggregator()
        result = agg.check_hash(_UNKNOWN_SHA256, "sha256")
        assert result.is_malicious is False
        assert result.confidence == 0.0
        assert result.source == "mock-no-match"

    # -- Cache namespacing --

    def test_cache_key_uses_hash_prefix_namespace(self) -> None:
        """check_hash() keys the cache as "hash:<value>", not the bare hash.

        Seeds a poisoned entry under the bare (unprefixed) hash string —
        what the cache would hold if check_hash() forgot to namespace its
        key — and proves the real lookup does not read it back.
        """
        agg = ThreatIntelAggregator()  # no keys -> mock mode

        agg._cache[_UNKNOWN_SHA256] = ThreatIntelResult(
            ip=_UNKNOWN_SHA256,
            is_malicious=True,
            confidence=1.0,
            source="poisoned",
            tags=[],
            queried_at=datetime.now(timezone.utc),
        )

        result = agg.check_hash(_UNKNOWN_SHA256, "sha256")

        assert result.source == "mock-no-match"  # not "poisoned"
        namespaced = agg._cache.get(f"hash:{_UNKNOWN_SHA256}")
        assert namespaced is not None
        assert namespaced.source == "mock-no-match"

    # -- VT-unavailable fallbacks --

    def test_quota_exhausted_falls_back_to_mock(self) -> None:
        """VT configured but its daily quota is exhausted -> mock fallback."""
        vt_client = MagicMock()
        agg = ThreatIntelAggregator.__new__(ThreatIntelAggregator)
        agg._use_mock = False
        agg._cache = {}
        agg._vt_client = vt_client
        agg._vt_quota = _DailyQuota(limit=0)

        result = agg.check_hash(_EICAR_SHA256, "sha256")

        vt_client.check_hash.assert_not_called()
        assert result.source == "mock-vt-file-feed"

    def test_vt_not_configured_falls_back_to_mock(self) -> None:
        """VirusTotal not configured at all -> mock fallback."""
        agg = ThreatIntelAggregator.__new__(ThreatIntelAggregator)
        agg._use_mock = False
        agg._cache = {}
        agg._vt_client = None
        agg._vt_quota = None

        result = agg.check_hash(_UNKNOWN_SHA256, "sha256")
        assert result.source == "mock-no-match"

    def test_vt_client_error_falls_back_to_mock(self) -> None:
        """VirusTotal returning an error result -> mock fallback."""
        vt_client = MagicMock()
        vt_client.check_hash.return_value = FileReputationResult(
            file_hash=_EICAR_SHA256,
            hash_type="sha256",
            is_malicious=False,
            confidence=0.0,
            source="virustotal-error",
            tags=[],
            queried_at=datetime.now(timezone.utc),
        )
        agg = ThreatIntelAggregator.__new__(ThreatIntelAggregator)
        agg._use_mock = False
        agg._cache = {}
        agg._vt_client = vt_client
        agg._vt_quota = _DailyQuota(limit=100)

        result = agg.check_hash(_EICAR_SHA256, "sha256")

        vt_client.check_hash.assert_called_once_with(_EICAR_SHA256, "sha256")
        assert result.source == "mock-vt-file-feed"

    # -- Caching --

    def test_result_cached_second_call_uses_cache(self) -> None:
        """A repeated hash is served from cache; the client is called once."""
        vt_client = MagicMock()
        vt_client.check_hash.return_value = FileReputationResult(
            file_hash=_EICAR_SHA256,
            hash_type="sha256",
            is_malicious=True,
            confidence=0.9,
            source="virustotal",
            tags=[],
            queried_at=datetime.now(timezone.utc),
        )
        agg = ThreatIntelAggregator.__new__(ThreatIntelAggregator)
        agg._use_mock = False
        agg._cache = {}
        agg._vt_client = vt_client
        agg._vt_quota = _DailyQuota(limit=100)

        first = agg.check_hash(_EICAR_SHA256, "sha256")
        second = agg.check_hash(_EICAR_SHA256, "sha256")

        assert vt_client.check_hash.call_count == 1
        assert first is second
