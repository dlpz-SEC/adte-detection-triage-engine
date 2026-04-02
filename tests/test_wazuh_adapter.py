"""Tests for adte.adapters.wazuh — Wazuh Indexer source adapter."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from adte.adapters.wazuh import (
    WazuhAdapter,
    _extract_srcip,
    _extract_user,
    _severity_from_level,
)
from adte.engine import TriageEngine
from adte.intel.sigma_fp_registry import FPRegistry
from adte.models import NormalizedIncident
from adte.store.user_history import get_user_profile

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

_OUTPUT_KEYS = {
    "verdict",
    "risk_score",
    "confidence",
    "recommended_action",
    "actions",
    "rationale",
    "evidence",
    "safety",
    "report",
}


@pytest.fixture()
def wazuh_fixture() -> dict[str, Any]:
    """Load the wazuh_alerts.json fixture (OpenSearch _search response)."""
    return json.loads((FIXTURES_DIR / "wazuh_alerts.json").read_text(encoding="utf-8"))


def _source(wazuh_fixture: dict[str, Any], index: int) -> dict[str, Any]:
    """Extract a _source doc from the fixture and inject _id as id."""
    hit = wazuh_fixture["hits"]["hits"][index]
    return {**hit["_source"], "id": hit["_id"]}


@pytest.fixture()
def ssh_alert(wazuh_fixture: dict[str, Any]) -> dict[str, Any]:
    """Alert 1 — SSH brute force with srcip and dstuser (level 10)."""
    return _source(wazuh_fixture, 0)


@pytest.fixture()
def windows_alert(wazuh_fixture: dict[str, Any]) -> dict[str, Any]:
    """Alert 2 — Windows auth failure with win.eventdata (level 7)."""
    return _source(wazuh_fixture, 1)


@pytest.fixture()
def shellshock_alert(wazuh_fixture: dict[str, Any]) -> dict[str, Any]:
    """Alert 3 — Shellshock with no user fields, srcip present (level 12)."""
    return _source(wazuh_fixture, 2)


@pytest.fixture()
def level0_alert(wazuh_fixture: dict[str, Any]) -> dict[str, Any]:
    """Alert 4 — Informational, level 0 (should be filtered)."""
    return _source(wazuh_fixture, 3)


@pytest.fixture()
def fp_registry() -> FPRegistry:
    """Default false-positive registry."""
    return FPRegistry.load()


# ---------------------------------------------------------------------------
# _severity_from_level
# ---------------------------------------------------------------------------


class TestSeverityFromLevel:
    """Tests for the _severity_from_level helper."""

    def test_all_bands(self) -> None:
        """Each Wazuh level band maps to the correct severity string."""
        assert _severity_from_level(1) == "Low"
        assert _severity_from_level(3) == "Low"
        assert _severity_from_level(4) == "Medium"
        assert _severity_from_level(7) == "Medium"
        assert _severity_from_level(8) == "High"
        assert _severity_from_level(11) == "High"
        assert _severity_from_level(12) == "Critical"
        assert _severity_from_level(15) == "Critical"

    def test_clamp_below_one(self) -> None:
        """Level 0 (or negative) clamps to Low."""
        assert _severity_from_level(0) == "Low"
        assert _severity_from_level(-5) == "Low"

    def test_clamp_above_fifteen(self) -> None:
        """Level 16 and above clamp to Critical."""
        assert _severity_from_level(16) == "Critical"
        assert _severity_from_level(100) == "Critical"


# ---------------------------------------------------------------------------
# _extract_user
# ---------------------------------------------------------------------------


class TestExtractUser:
    """Tests for the _extract_user helper."""

    def test_dstuser_preferred(self) -> None:
        """data.dstuser is returned when present and non-trivial."""
        alert = {"data": {"dstuser": "admin"}, "agent": {"name": "srv-01"}}
        assert _extract_user(alert) == "admin"

    def test_user_field(self) -> None:
        """data.user is used when dstuser is absent."""
        alert = {"data": {"user": "deploy"}, "agent": {"name": "srv-01"}}
        assert _extract_user(alert) == "deploy"

    def test_srcuser_field(self) -> None:
        """data.srcuser is used when dstuser and user are absent."""
        alert = {"data": {"srcuser": "attacker"}, "agent": {"name": "srv-01"}}
        assert _extract_user(alert) == "attacker"

    def test_skip_trivial_values(self) -> None:
        """Values like '-', 'root', 'SYSTEM' are skipped."""
        alert = {"data": {"dstuser": "-", "user": "SYSTEM"}, "agent": {"name": "host"}}
        # Falls through to Windows path, then to fallback.
        result = _extract_user(alert)
        assert result == "host\\system"

    def test_windows_eventdata_target_user(self) -> None:
        """data.win.eventdata.targetUserName is extracted."""
        alert = {
            "data": {
                "win": {
                    "eventdata": {
                        "targetUserName": "jsmith",
                        "subjectUserName": "SYSTEM",
                    }
                }
            },
            "agent": {"name": "dc-01"},
        }
        assert _extract_user(alert) == "jsmith"

    def test_fallback_to_agent_name(self) -> None:
        """No user fields → fallback to agent.name\\system."""
        alert = {"data": {}, "agent": {"name": "web-server-01"}}
        assert _extract_user(alert) == "web-server-01\\system"


# ---------------------------------------------------------------------------
# _extract_srcip
# ---------------------------------------------------------------------------


class TestExtractSrcip:
    """Tests for the _extract_srcip helper."""

    def test_data_srcip_preferred(self) -> None:
        """data.srcip is returned when present."""
        alert = {"data": {"srcip": "198.51.100.23"}, "agent": {"ip": "10.0.0.1"}}
        assert _extract_srcip(alert) == "198.51.100.23"

    def test_fallback_to_agent_ip(self) -> None:
        """agent.ip is used when data.srcip is absent."""
        alert = {"data": {}, "agent": {"ip": "10.0.0.1"}}
        assert _extract_srcip(alert) == "10.0.0.1"

    def test_empty_when_no_ip(self) -> None:
        """Returns empty string when no IP is available."""
        alert = {"data": {}, "agent": {}}
        assert _extract_srcip(alert) == ""


# ---------------------------------------------------------------------------
# normalize_alert
# ---------------------------------------------------------------------------


class TestNormalizeAlert:
    """Tests for WazuhAdapter.normalize_alert."""

    def test_ssh_brute_force(self, ssh_alert: dict[str, Any]) -> None:
        """SSH brute force alert maps to correct severity, ip, and user."""
        inc = WazuhAdapter.normalize_alert(ssh_alert)
        assert inc.severity == "High"        # level 10
        assert inc.sign_in_events[0].ip_address == "198.51.100.23"
        assert inc.user == "admin"
        assert inc.sign_in_events[0].device_name == "web-server-01"

    def test_windows_event_user(self, windows_alert: dict[str, Any]) -> None:
        """Windows auth alert extracts targetUserName."""
        inc = WazuhAdapter.normalize_alert(windows_alert)
        assert inc.user == "jsmith"
        assert inc.severity == "Medium"      # level 7

    def test_location_is_none(self, ssh_alert: dict[str, Any]) -> None:
        """location is None for all Wazuh alerts (no geo data)."""
        inc = WazuhAdapter.normalize_alert(ssh_alert)
        assert inc.sign_in_events[0].location is None

    def test_mfa_result_not_attempted(self, ssh_alert: dict[str, Any]) -> None:
        """mfa_result is always NotAttempted for Wazuh alerts."""
        inc = WazuhAdapter.normalize_alert(ssh_alert)
        assert inc.sign_in_events[0].mfa_result == "NotAttempted"

    def test_no_geo_fallback_no_srcip(self, windows_alert: dict[str, Any]) -> None:
        """Windows alert with no srcip falls back to agent.ip."""
        inc = WazuhAdapter.normalize_alert(windows_alert)
        # The windows_alert has no data.srcip but agent.ip = 10.0.1.20.
        assert inc.sign_in_events[0].ip_address == "10.0.1.20"

    def test_host_entity_always_present(self, ssh_alert: dict[str, Any]) -> None:
        """Host entity is always in the entities list."""
        inc = WazuhAdapter.normalize_alert(ssh_alert)
        host_entities = [e for e in inc.entities if e.entity_type == "Host"]
        assert len(host_entities) == 1
        assert host_entities[0].identifier == "web-server-01"

    def test_ip_entity_when_srcip_present(self, ssh_alert: dict[str, Any]) -> None:
        """IP entity is added when srcip is available."""
        inc = WazuhAdapter.normalize_alert(ssh_alert)
        ip_entities = [e for e in inc.entities if e.entity_type == "IP"]
        assert len(ip_entities) == 1
        assert ip_entities[0].identifier == "198.51.100.23"

    def test_account_entity_for_real_user(self, ssh_alert: dict[str, Any]) -> None:
        """Account entity is added when a real user (not fallback) is extracted."""
        inc = WazuhAdapter.normalize_alert(ssh_alert)
        account_entities = [e for e in inc.entities if e.entity_type == "Account"]
        assert len(account_entities) == 1
        assert account_entities[0].identifier == "admin"

    def test_no_account_entity_for_fallback_user(
        self, level0_alert: dict[str, Any]
    ) -> None:
        """No Account entity when only the agent.name\\system fallback was used."""
        # Modify to have no user fields.
        alert = {**level0_alert, "rule": {"level": 5, "description": "test"}}
        alert["data"] = {}
        inc = WazuhAdapter.normalize_alert(alert)
        account_entities = [e for e in inc.entities if e.entity_type == "Account"]
        assert len(account_entities) == 0

    def test_produces_valid_normalized_incident(self, ssh_alert: dict[str, Any]) -> None:
        """normalize_alert returns a NormalizedIncident with required fields."""
        inc = WazuhAdapter.normalize_alert(ssh_alert)
        assert isinstance(inc, NormalizedIncident)
        assert inc.incident_id != ""
        assert inc.user != ""
        assert len(inc.sign_in_events) == 1

    def test_triage_pipeline_runs_on_normalized(
        self,
        ssh_alert: dict[str, Any],
        fp_registry: FPRegistry,
    ) -> None:
        """A normalized Wazuh alert can run through the full triage pipeline."""
        inc = WazuhAdapter.normalize_alert(ssh_alert)
        profile = get_user_profile(inc.user)
        engine = TriageEngine(inc, profile, fp_registry)
        output = engine.enrich().score().decide().to_output()
        assert _OUTPUT_KEYS.issubset(output.keys())

    def test_wazuh_incident_high_risk_reachable(
        self, fp_registry: FPRegistry
    ) -> None:
        """Wazuh alert with malicious IP + unknown device reaches high_risk.

        Both impossible_travel and mfa_fatigue are skipped (no geo, no MFA).
        IP rep (20) + device novelty (15) = 35 raw pts.
        available_weight = 45 → round(35 * 100/45) = 78 → high_risk.
        """
        alert = {
            "id": "test-high-risk",
            "@timestamp": "2024-01-15T10:30:00.000Z",
            "rule": {
                "level": 12,
                "id": "99999",
                "description": "Shellshock attack detected.",
            },
            "agent": {"id": "agent-001", "name": "dmz-host", "ip": "10.0.0.1"},
            "data": {"srcip": "198.51.100.23"},  # malicious C2 range
        }
        inc = WazuhAdapter.normalize_alert(alert)
        # Use an unknown user profile so the device is novel.
        profile = get_user_profile("dmz-host\\system")
        engine = TriageEngine(inc, profile, fp_registry)
        output = engine.enrich().score().decide().to_output()
        assert output["risk_score"] == 78
        assert output["verdict"] == "high_risk"

    def test_wazuh_signal_skips_documented(
        self, ssh_alert: dict[str, Any], fp_registry: FPRegistry
    ) -> None:
        """impossible_travel and mfa_fatigue rationale entries say 'skipped'."""
        inc = WazuhAdapter.normalize_alert(ssh_alert)
        profile = get_user_profile(inc.user)
        engine = TriageEngine(inc, profile, fp_registry)
        output = engine.enrich().score().decide().to_output()
        rationale_map = {r["signal"]: r["detail"] for r in output["rationale"]}
        assert "skipped" in rationale_map["impossible_travel"].lower()
        assert "skipped" in rationale_map["mfa_fatigue"].lower()


# ---------------------------------------------------------------------------
# Level-0 filter
# ---------------------------------------------------------------------------


class TestLevel0Filter:
    """Test that level-0 alerts are filtered before normalization."""

    def test_fetch_alerts_filters_level0(self) -> None:
        """Level-0 alerts are excluded from the return value of fetch_alerts."""
        mock_response = {
            "hits": {
                "total": {"value": 2, "relation": "eq"},
                "hits": [
                    {"_id": "keep-me", "_source": {"rule": {"level": 5}}},
                    {"_id": "drop-me", "_source": {"rule": {"level": 0}}},
                ],
            }
        }
        with patch("adte.adapters.wazuh.requests.Session") as MockSession:
            mock_session = MockSession.return_value
            post_resp = MagicMock()
            post_resp.json.return_value = mock_response
            post_resp.raise_for_status = MagicMock()
            mock_session.post.return_value = post_resp

            adapter = WazuhAdapter(url="https://localhost:9200", user="u", password="p")
            adapter._session = mock_session
            results = adapter.fetch_alerts(hours=1, limit=500)

        assert len(results) == 1
        assert results[0]["id"] == "keep-me"


# ---------------------------------------------------------------------------
# from_env
# ---------------------------------------------------------------------------


class TestFromEnv:
    """Tests for WazuhAdapter.from_env."""

    def test_missing_user_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Missing ADTE_WAZUH_USER raises EnvironmentError."""
        monkeypatch.delenv("ADTE_WAZUH_USER", raising=False)
        monkeypatch.setenv("ADTE_WAZUH_PASS", "secret")
        with pytest.raises(EnvironmentError, match="ADTE_WAZUH_USER"):
            WazuhAdapter.from_env()

    def test_missing_pass_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Missing ADTE_WAZUH_PASS raises EnvironmentError."""
        monkeypatch.setenv("ADTE_WAZUH_USER", "admin")
        monkeypatch.delenv("ADTE_WAZUH_PASS", raising=False)
        with pytest.raises(EnvironmentError, match="ADTE_WAZUH_PASS"):
            WazuhAdapter.from_env()

    def test_default_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """ADTE_WAZUH_INDEXER_URL defaults to https://localhost:9200."""
        monkeypatch.setenv("ADTE_WAZUH_USER", "admin")
        monkeypatch.setenv("ADTE_WAZUH_PASS", "secret")
        monkeypatch.delenv("ADTE_WAZUH_INDEXER_URL", raising=False)
        adapter = WazuhAdapter.from_env()
        assert adapter._url == "https://localhost:9200"

    def test_custom_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """ADTE_WAZUH_INDEXER_URL override is respected."""
        monkeypatch.setenv("ADTE_WAZUH_INDEXER_URL", "https://wazuh-indexer.internal:9200")
        monkeypatch.setenv("ADTE_WAZUH_USER", "admin")
        monkeypatch.setenv("ADTE_WAZUH_PASS", "secret")
        adapter = WazuhAdapter.from_env()
        assert adapter._url == "https://wazuh-indexer.internal:9200"

    def test_indexer_uses_basic_auth(self) -> None:
        """WazuhAdapter sets HTTP Basic Auth on the session at construction."""
        adapter = WazuhAdapter(
            url="https://localhost:9200", user="admin", password="pass"
        )
        assert adapter._session.auth == ("admin", "pass")


# ---------------------------------------------------------------------------
# fetch_alerts
# ---------------------------------------------------------------------------


class TestFetchAlerts:
    """Tests for WazuhAdapter.fetch_alerts."""

    def _make_page(
        self, items: list[dict[str, Any]], total: int
    ) -> MagicMock:
        """Return a mock HTTP response for a page of OpenSearch hits."""
        resp = MagicMock()
        hits = [
            {"_id": item.get("id", str(i)), "_source": item}
            for i, item in enumerate(items)
        ]
        resp.json.return_value = {
            "hits": {
                "total": {"value": total, "relation": "eq"},
                "hits": hits,
            }
        }
        resp.raise_for_status = MagicMock()
        return resp

    def test_time_filter_in_query(self) -> None:
        """fetch_alerts passes a timestamp cutoff in the @timestamp range query."""
        with patch("adte.adapters.wazuh.requests.Session") as MockSession:
            mock_session = MockSession.return_value
            mock_session.post.return_value = self._make_page([], 0)

            adapter = WazuhAdapter(url="https://localhost:9200", user="u", password="p")
            adapter._session = mock_session
            adapter.fetch_alerts(hours=6, limit=500)

        call_kwargs = mock_session.post.call_args
        body = call_kwargs[1]["json"]
        must = body["query"]["bool"]["must"]
        ts_filter = next(c for c in must if "range" in c and "@timestamp" in c["range"])
        assert ts_filter["range"]["@timestamp"]["gte"]  # non-empty cutoff string

    def test_level_filter_in_query(self) -> None:
        """fetch_alerts includes rule.level >= min_level in the bool/must query."""
        with patch("adte.adapters.wazuh.requests.Session") as MockSession:
            mock_session = MockSession.return_value
            mock_session.post.return_value = self._make_page([], 0)

            adapter = WazuhAdapter(url="https://localhost:9200", user="u", password="p")
            adapter._session = mock_session
            adapter.fetch_alerts(hours=6, limit=500, min_level=7)

        body = mock_session.post.call_args[1]["json"]
        must = body["query"]["bool"]["must"]
        level_filter = next(c for c in must if "range" in c and "rule.level" in c["range"])
        assert level_filter["range"]["rule.level"]["gte"] == 7

    def test_truncation_warning_logged(self, caplog: pytest.LogCaptureFixture) -> None:
        """A warning is logged when total > limit."""
        items = [{"rule": {"level": 5}, "id": f"a{i}"} for i in range(10)]
        with patch("adte.adapters.wazuh.requests.Session") as MockSession:
            mock_session = MockSession.return_value
            # total = 1000 but limit = 10 → should warn
            mock_session.post.return_value = self._make_page(items, total=1000)

            adapter = WazuhAdapter(url="https://localhost:9200", user="u", password="p")
            adapter._session = mock_session
            with caplog.at_level(logging.WARNING, logger="adte.adapters.wazuh"):
                adapter.fetch_alerts(hours=1, limit=10)

        assert any("truncated" in r.message.lower() for r in caplog.records)

    def test_pagination_fetches_multiple_pages(self) -> None:
        """Two pages of results (500 + 200) are concatenated correctly."""
        page1 = [{"rule": {"level": 5}, "id": f"p1-{i}"} for i in range(500)]
        page2 = [{"rule": {"level": 5}, "id": f"p2-{i}"} for i in range(200)]

        responses = [
            self._make_page(page1, total=700),
            self._make_page(page2, total=700),
        ]
        with patch("adte.adapters.wazuh.requests.Session") as MockSession:
            mock_session = MockSession.return_value
            mock_session.post.side_effect = responses

            adapter = WazuhAdapter(url="https://localhost:9200", user="u", password="p")
            adapter._session = mock_session
            results = adapter.fetch_alerts(hours=24, limit=700)

        assert len(results) == 700
        assert mock_session.post.call_count == 2


# ---------------------------------------------------------------------------
# fetch_incidents (end-to-end with mocked HTTP)
# ---------------------------------------------------------------------------


class TestFetchIncidents:
    """End-to-end tests for fetch_incidents."""

    def test_returns_list_of_normalized_incidents(self) -> None:
        """fetch_incidents returns NormalizedIncident objects without explicit auth."""
        source = {
            "@timestamp": "2024-01-15T10:30:00.000Z",
            "rule": {"level": 10, "description": "SSH brute force"},
            "agent": {"id": "001", "name": "host-01", "ip": "10.0.0.1"},
            "data": {"srcip": "198.51.100.23", "dstuser": "root-account"},
        }
        api_response = {
            "hits": {
                "total": {"value": 1, "relation": "eq"},
                "hits": [{"_id": "e2e-001", "_source": source}],
            }
        }

        with patch("adte.adapters.wazuh.requests.Session") as MockSession:
            mock_session = MockSession.return_value
            post_resp = MagicMock()
            post_resp.json.return_value = api_response
            post_resp.raise_for_status = MagicMock()
            mock_session.post.return_value = post_resp

            adapter = WazuhAdapter(url="https://localhost:9200", user="u", password="p")
            adapter._session = mock_session
            incidents = adapter.fetch_incidents(hours=1, limit=50)

        assert len(incidents) == 1
        assert isinstance(incidents[0], NormalizedIncident)
        assert incidents[0].incident_id == "e2e-001"
        assert incidents[0].user == "root-account"
