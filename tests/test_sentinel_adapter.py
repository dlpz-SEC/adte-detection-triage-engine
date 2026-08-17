"""Tests for adte.adapters.sentinel — Microsoft Sentinel source adapter."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
import requests

from adte.adapters.sentinel import (
    SentinelAdapter,
    _event_risk_from_severity,
    _parse_api_timestamp,
    _parse_entities,
    _parse_techniques,
    _rows_as_dicts,
    _validate_guid,
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

_TENANT = "11111111-2222-3333-4444-555555555555"
_CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_WORKSPACE = "99999999-8888-7777-6666-555555555555"
_SECRET = "super-secret-value"

_ENV_VARS = {
    "ADTE_SENTINEL_TENANT_ID": _TENANT,
    "ADTE_SENTINEL_CLIENT_ID": _CLIENT,
    "ADTE_SENTINEL_CLIENT_SECRET": _SECRET,
    "ADTE_SENTINEL_WORKSPACE_ID": _WORKSPACE,
}


@pytest.fixture()
def sentinel_fixture() -> dict[str, Any]:
    """Load the sentinel_incidents.json fixture (Query API response)."""
    return json.loads(
        (FIXTURES_DIR / "sentinel_incidents.json").read_text(encoding="utf-8")
    )


@pytest.fixture()
def fixture_rows(sentinel_fixture: dict[str, Any]) -> list[dict[str, Any]]:
    """The fixture's rows converted to dicts (as fetch_incidents_raw returns)."""
    return _rows_as_dicts(sentinel_fixture["tables"][0])


@pytest.fixture()
def adapter() -> SentinelAdapter:
    """An adapter built from explicit (valid) parameters."""
    return SentinelAdapter(
        tenant_id=_TENANT,
        client_id=_CLIENT,
        client_secret=_SECRET,
        workspace_id=_WORKSPACE,
    )


@pytest.fixture()
def fp_registry() -> FPRegistry:
    """Default false-positive registry."""
    return FPRegistry.load()


def _mock_response(payload: dict[str, Any]) -> MagicMock:
    """A requests.Response stand-in returning the given JSON payload."""
    resp = MagicMock()
    resp.json.return_value = payload
    resp.raise_for_status.return_value = None
    return resp


_TOKEN_PAYLOAD = {"access_token": "test-token", "expires_in": 3600}


# ---------------------------------------------------------------------------
# GUID validation (path-injection guard)
# ---------------------------------------------------------------------------


class TestGuidValidation:
    """Tests for the _validate_guid path-injection guard."""

    def test_canonical_guid_accepted(self) -> None:
        """A well-formed GUID passes without raising."""
        _validate_guid(_TENANT, "ADTE_SENTINEL_TENANT_ID")

    def test_uppercase_guid_accepted(self) -> None:
        """Hex case is irrelevant."""
        _validate_guid(_TENANT.upper(), "ADTE_SENTINEL_TENANT_ID")

    @pytest.mark.parametrize(
        "bad",
        [
            "not-a-guid",
            "11111111-2222-3333-4444-55555555555",  # one hex digit short
            "../../v1/workspaces/other",
            f"{_TENANT}/query?x=1",
            f"{_TENANT}\n",
            "",
        ],
    )
    def test_malformed_values_rejected(self, bad: str) -> None:
        """Anything that is not a strict GUID raises, naming the variable."""
        with pytest.raises(EnvironmentError, match="ADTE_SENTINEL_TENANT_ID"):
            _validate_guid(bad, "ADTE_SENTINEL_TENANT_ID")

    def test_constructor_validates_all_guids(self) -> None:
        """The constructor rejects a malformed workspace ID."""
        with pytest.raises(EnvironmentError, match="ADTE_SENTINEL_WORKSPACE_ID"):
            SentinelAdapter(
                tenant_id=_TENANT,
                client_id=_CLIENT,
                client_secret=_SECRET,
                workspace_id="../../etc/passwd",
            )


# ---------------------------------------------------------------------------
# from_env
# ---------------------------------------------------------------------------


class TestFromEnv:
    """Tests for SentinelAdapter.from_env."""

    def test_all_vars_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """With all four variables set, an adapter is returned."""
        for var, value in _ENV_VARS.items():
            monkeypatch.setenv(var, value)
        adapter = SentinelAdapter.from_env()
        assert isinstance(adapter, SentinelAdapter)

    @pytest.mark.parametrize("missing", list(_ENV_VARS))
    def test_each_missing_var_raises(
        self, monkeypatch: pytest.MonkeyPatch, missing: str
    ) -> None:
        """Each unset variable raises an error naming exactly that variable."""
        for var, value in _ENV_VARS.items():
            if var == missing:
                monkeypatch.delenv(var, raising=False)
            else:
                monkeypatch.setenv(var, value)
        with pytest.raises(EnvironmentError, match=missing):
            SentinelAdapter.from_env()

    def test_error_mentions_cli_flag(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The error message tells the operator which CLI flag it unblocks."""
        for var in _ENV_VARS:
            monkeypatch.delenv(var, raising=False)
        with pytest.raises(EnvironmentError, match="--source sentinel"):
            SentinelAdapter.from_env()


# ---------------------------------------------------------------------------
# Credential safety
# ---------------------------------------------------------------------------


class TestReprCredentialSafety:
    """The repr must never leak the client secret."""

    def test_secret_absent_from_repr(self, adapter: SentinelAdapter) -> None:
        """repr() carries tenant/client/workspace but never the secret."""
        rendered = repr(adapter)
        assert _SECRET not in rendered
        assert _TENANT in rendered
        assert _WORKSPACE in rendered


# ---------------------------------------------------------------------------
# Timestamp parsing
# ---------------------------------------------------------------------------


class TestParseApiTimestamp:
    """Tests for the defensive _parse_api_timestamp helper."""

    def test_z_suffix(self) -> None:
        """A trailing Z parses to a UTC-aware datetime."""
        parsed = _parse_api_timestamp("2026-08-15T14:00:00Z")
        assert parsed == datetime(2026, 8, 15, 14, 0, 0, tzinfo=timezone.utc)

    def test_seven_digit_fraction_trimmed(self) -> None:
        """ADX 100 ns (7-digit) fractions are trimmed, not rejected."""
        parsed = _parse_api_timestamp("2026-08-15T14:05:00.1234567Z")
        assert parsed is not None
        assert parsed.microsecond == 123456

    def test_offset_form(self) -> None:
        """An explicit +00:00 offset parses unchanged."""
        parsed = _parse_api_timestamp("2026-08-15T16:30:00+00:00")
        assert parsed is not None
        assert parsed.tzinfo is not None

    def test_naive_gets_utc(self) -> None:
        """A timestamp without any zone info is assumed UTC."""
        parsed = _parse_api_timestamp("2026-08-15T14:00:00")
        assert parsed is not None
        assert parsed.tzinfo == timezone.utc

    @pytest.mark.parametrize("bad", ["", None, 42, "not-a-date", "2026-99-99T00:00:00Z"])
    def test_malformed_returns_none(self, bad: Any) -> None:
        """Malformed or missing values degrade to None — never raise."""
        assert _parse_api_timestamp(bad) is None


# ---------------------------------------------------------------------------
# Severity → event_risk
# ---------------------------------------------------------------------------


class TestEventRiskFromSeverity:
    """Tests for the _event_risk_from_severity mapping."""

    def test_all_bands(self) -> None:
        """Each Sentinel severity maps to the correct event_risk value."""
        assert _event_risk_from_severity("Informational") == "none"
        assert _event_risk_from_severity("Low") == "suspicious"
        assert _event_risk_from_severity("Medium") == "high"
        assert _event_risk_from_severity("High") == "confirmed"

    def test_case_insensitive(self) -> None:
        """Severity comparison ignores case."""
        assert _event_risk_from_severity("HIGH") == "confirmed"

    @pytest.mark.parametrize("odd", ["", None, "Unknown", 3])
    def test_unknown_maps_to_none(self, odd: Any) -> None:
        """Unrecognised severities degrade to 'none'."""
        assert _event_risk_from_severity(odd) == "none"


# ---------------------------------------------------------------------------
# Techniques parsing
# ---------------------------------------------------------------------------


class TestParseTechniques:
    """Tests for the _parse_techniques helper."""

    def test_json_array(self) -> None:
        """A JSON-encoded array yields the technique IDs."""
        assert _parse_techniques('["T1110","T1078"]') == ["T1110", "T1078"]

    def test_empty_and_falsy_filtered(self) -> None:
        """Empty entries are dropped."""
        assert _parse_techniques('["T1110", "", null]') == ["T1110"]

    @pytest.mark.parametrize("bad", ["", None, "not json", '{"a": 1}', 7])
    def test_malformed_degrades_to_empty(self, bad: Any) -> None:
        """Anything unparseable degrades to []."""
        assert _parse_techniques(bad) == []


# ---------------------------------------------------------------------------
# Entities parsing
# ---------------------------------------------------------------------------


class TestParseEntities:
    """Tests for the _parse_entities helper."""

    def test_account_upn_built(self) -> None:
        """Account entities combine Name and UPNSuffix into a UPN."""
        raw = '[{"Type":"account","Name":"eve","UPNSuffix":"contoso.com"}]'
        entities = _parse_entities(raw)
        assert len(entities) == 1
        assert entities[0].entity_type == "Account"
        assert entities[0].identifier == "eve@contoso.com"

    def test_account_name_only(self) -> None:
        """An account without a UPN suffix falls back to the bare name."""
        entities = _parse_entities('[{"Type":"account","Name":"eve"}]')
        assert entities[0].identifier == "eve"

    def test_ip_host_file_process(self) -> None:
        """Each mappable kind resolves its identifier field."""
        raw = json.dumps(
            [
                {"Type": "ip", "Address": "203.0.113.50"},
                {"Type": "host", "HostName": "CLOUD-SVC"},
                {"Type": "file", "Name": "evil.exe"},
                {"Type": "process", "ProcessId": "4242"},
            ]
        )
        kinds = [(e.entity_type, e.identifier) for e in _parse_entities(raw)]
        assert kinds == [
            ("IP", "203.0.113.50"),
            ("Host", "CLOUD-SVC"),
            ("File", "evil.exe"),
            ("Process", "4242"),
        ]

    def test_unknown_kinds_skipped(self) -> None:
        """Kinds outside the AlertEntity Literal (url, dns, ...) are skipped."""
        raw = '[{"Type":"url","Url":"https://x.invalid"},{"Type":"ip","Address":"1.2.3.4"}]'
        entities = _parse_entities(raw)
        assert [e.entity_type for e in entities] == ["IP"]

    def test_identifierless_entities_skipped(self) -> None:
        """An entity with no usable identifier is dropped."""
        assert _parse_entities('[{"Type":"ip"}]') == []

    @pytest.mark.parametrize("bad", ["", None, "not json", '{"Type":"ip"}', 5])
    def test_malformed_degrades_to_empty(self, bad: Any) -> None:
        """Anything unparseable degrades to []."""
        assert _parse_entities(bad) == []


# ---------------------------------------------------------------------------
# Query-table row conversion
# ---------------------------------------------------------------------------


class TestRowsAsDicts:
    """Tests for the _rows_as_dicts helper."""

    def test_zip_columns_over_rows(self) -> None:
        """Column names zip over each row array."""
        table = {
            "columns": [{"name": "A"}, {"name": "B"}],
            "rows": [[1, "x"], [2, "y"]],
        }
        assert _rows_as_dicts(table) == [{"A": 1, "B": "x"}, {"A": 2, "B": "y"}]

    def test_ragged_rows_skipped(self) -> None:
        """Rows whose length mismatches the column count are dropped."""
        table = {"columns": [{"name": "A"}], "rows": [[1], [1, 2], "junk"]}
        assert _rows_as_dicts(table) == [{"A": 1}]

    def test_malformed_table_degrades(self) -> None:
        """Missing/odd columns or rows degrade to an empty list."""
        assert _rows_as_dicts({}) == []
        assert _rows_as_dicts({"columns": "x", "rows": "y"}) == []


# ---------------------------------------------------------------------------
# normalize_incident
# ---------------------------------------------------------------------------


class TestNormalizeIncident:
    """Tests for the pure static normalize_incident."""

    def test_empty_rows_raise(self) -> None:
        """Zero rows is a caller bug — surfaced as ValueError."""
        with pytest.raises(ValueError):
            SentinelAdapter.normalize_incident([])

    def test_field_mapping(self, fixture_rows: list[dict[str, Any]]) -> None:
        """Incident 42's two rows map to one incident with two events."""
        rows = [r for r in fixture_rows if r["IncidentNumber"] == 42]
        inc = SentinelAdapter.normalize_incident(rows)
        assert isinstance(inc, NormalizedIncident)
        assert inc.incident_id == "sentinel-42"
        assert inc.source == "azure_ad"
        assert inc.user == "testuser1@securitylabzz.onmicrosoft.com"
        assert len(inc.events) == 2
        # Events are sorted chronologically.
        assert inc.events[0].timestamp <= inc.events[1].timestamp
        assert inc.events[0].app_display_name == "Failed sign-in burst"
        assert inc.events[0].event_risk == "high"  # Medium → high band
        assert inc.events[1].event_risk == "confirmed"  # High → confirmed
        assert inc.events[1].technique_ids == ["T1110", "T1078"]
        assert inc.events[0].ip_address == "203.0.113.50"

    def test_location_is_none_not_null_island(
        self, fixture_rows: list[dict[str, Any]]
    ) -> None:
        """No geo at alert level → location None (engine skips travel).

        Regression guard for the from_sentinel default that would have
        produced GeoLocation(0, 0) — "Null Island" — and could mis-fire
        the impossible-travel signal against real geo events.
        """
        rows = [r for r in fixture_rows if r["IncidentNumber"] == 42]
        inc = SentinelAdapter.normalize_incident(rows)
        assert all(e.location is None for e in inc.events)

    def test_auth_status_is_none(self, fixture_rows: list[dict[str, Any]]) -> None:
        """No MFA outcome at alert level → auth_status None (skip MFA-fatigue)."""
        rows = [r for r in fixture_rows if r["IncidentNumber"] == 42]
        inc = SentinelAdapter.normalize_incident(rows)
        assert all(e.auth_status is None for e in inc.events)

    def test_entities_merged_and_deduped(
        self, fixture_rows: list[dict[str, Any]]
    ) -> None:
        """Entities across rows merge without duplicates, first-seen order."""
        rows = [r for r in fixture_rows if r["IncidentNumber"] == 42]
        inc = SentinelAdapter.normalize_incident(rows)
        keys = [(e.entity_type, e.identifier) for e in inc.entities]
        assert keys == [
            ("Account", "testuser1@securitylabzz.onmicrosoft.com"),
            ("IP", "203.0.113.50"),
            ("Host", "CLOUD-SVC"),
        ]

    def test_malformed_timestamp_falls_back(self) -> None:
        """A malformed AlertTime falls back to IncidentCreated, never raises."""
        rows = [
            {
                "IncidentNumber": 7,
                "IncidentCreated": "2026-08-15T10:00:00Z",
                "AlertTime": "garbage",
                "AlertName": "x",
                "AlertSeverity": "Low",
                "Entities": "[]",
                "Techniques": "[]",
            }
        ]
        inc = SentinelAdapter.normalize_incident(rows)
        assert inc.events[0].timestamp == datetime(
            2026, 8, 15, 10, 0, 0, tzinfo=timezone.utc
        )

    def test_all_timestamps_malformed_uses_epoch(self) -> None:
        """With no parseable timestamp anywhere, the epoch fallback holds."""
        rows = [
            {
                "IncidentNumber": 8,
                "IncidentCreated": None,
                "AlertTime": None,
                "AlertName": "x",
                "AlertSeverity": "Low",
                "Entities": "[]",
                "Techniques": "[]",
            }
        ]
        inc = SentinelAdapter.normalize_incident(rows)
        assert inc.events[0].timestamp == datetime(1970, 1, 1, tzinfo=timezone.utc)

    def test_triage_pipeline_runs_on_normalized(
        self,
        fixture_rows: list[dict[str, Any]],
        fp_registry: FPRegistry,
    ) -> None:
        """A normalized Sentinel incident runs the full triage pipeline."""
        rows = [r for r in fixture_rows if r["IncidentNumber"] == 42]
        inc = SentinelAdapter.normalize_incident(rows)
        profile = get_user_profile(inc.user)
        engine = TriageEngine(inc, profile, fp_registry)
        output = engine.enrich().score().decide().to_output()
        assert _OUTPUT_KEYS.issubset(output.keys())

    def test_signal_skips_documented(
        self,
        fixture_rows: list[dict[str, Any]],
        fp_registry: FPRegistry,
    ) -> None:
        """impossible_travel and mfa_fatigue rationale entries say 'skipped'."""
        rows = [r for r in fixture_rows if r["IncidentNumber"] == 42]
        inc = SentinelAdapter.normalize_incident(rows)
        profile = get_user_profile(inc.user)
        engine = TriageEngine(inc, profile, fp_registry)
        output = engine.enrich().score().decide().to_output()
        rationale_map = {r["signal"]: r["detail"] for r in output["rationale"]}
        assert "skipped" in rationale_map["impossible_travel"].lower()
        assert "skipped" in rationale_map["mfa_fatigue"].lower()


# ---------------------------------------------------------------------------
# Token acquisition and caching
# ---------------------------------------------------------------------------


class TestTokenCache:
    """Tests for OAuth token fetch and expiry-aware caching."""

    def test_token_fetched_once_within_ttl(self, adapter: SentinelAdapter) -> None:
        """Two calls inside the TTL make exactly one HTTP request."""
        adapter._session.post = MagicMock(return_value=_mock_response(_TOKEN_PAYLOAD))
        assert adapter._get_token() == "test-token"
        assert adapter._get_token() == "test-token"
        assert adapter._session.post.call_count == 1

    def test_expired_token_refreshes(self, adapter: SentinelAdapter) -> None:
        """After expiry, the next call fetches a fresh token."""
        adapter._session.post = MagicMock(return_value=_mock_response(_TOKEN_PAYLOAD))
        adapter._get_token()
        adapter._token_expires_at = 0.0  # Force expiry.
        adapter._get_token()
        assert adapter._session.post.call_count == 2

    def test_token_request_shape(self, adapter: SentinelAdapter) -> None:
        """The token request is a client-credentials form POST to the tenant."""
        adapter._session.post = MagicMock(return_value=_mock_response(_TOKEN_PAYLOAD))
        adapter._get_token()
        args, kwargs = adapter._session.post.call_args
        assert _TENANT in args[0]
        assert kwargs["data"]["grant_type"] == "client_credentials"
        assert kwargs["data"]["client_secret"] == _SECRET

    def test_token_http_error_propagates(self, adapter: SentinelAdapter) -> None:
        """A failing token call raises requests.HTTPError to the caller."""
        resp = MagicMock()
        resp.raise_for_status.side_effect = requests.HTTPError("401")
        adapter._session.post = MagicMock(return_value=resp)
        with pytest.raises(requests.HTTPError):
            adapter._get_token()


# ---------------------------------------------------------------------------
# fetch_incidents_raw
# ---------------------------------------------------------------------------


class TestFetchIncidentsRaw:
    """Tests for the Query API call (all HTTP mocked)."""

    def test_rows_returned(
        self, adapter: SentinelAdapter, sentinel_fixture: dict[str, Any]
    ) -> None:
        """The fixture response converts to one dict per row."""
        adapter._session.post = MagicMock(
            side_effect=[
                _mock_response(_TOKEN_PAYLOAD),
                _mock_response(sentinel_fixture),
            ]
        )
        rows = adapter.fetch_incidents_raw(hours=24, limit=100)
        assert len(rows) == 3
        assert rows[0]["IncidentNumber"] == 42

    def test_query_request_shape(
        self, adapter: SentinelAdapter, sentinel_fixture: dict[str, Any]
    ) -> None:
        """The query POST targets the workspace with a bearer token and KQL."""
        adapter._session.post = MagicMock(
            side_effect=[
                _mock_response(_TOKEN_PAYLOAD),
                _mock_response(sentinel_fixture),
            ]
        )
        adapter.fetch_incidents_raw(hours=6, limit=50)
        args, kwargs = adapter._session.post.call_args
        assert _WORKSPACE in args[0]
        assert kwargs["headers"]["Authorization"] == "Bearer test-token"
        assert "SecurityIncident" in kwargs["json"]["query"]
        assert "ago(6h)" in kwargs["json"]["query"]
        assert "take 50" in kwargs["json"]["query"]

    def test_query_http_error_propagates(self, adapter: SentinelAdapter) -> None:
        """A failing query call raises requests.HTTPError to the caller."""
        bad = MagicMock()
        bad.raise_for_status.side_effect = requests.HTTPError("403")
        adapter._session.post = MagicMock(
            side_effect=[_mock_response(_TOKEN_PAYLOAD), bad]
        )
        with pytest.raises(requests.HTTPError):
            adapter.fetch_incidents_raw()

    def test_malformed_response_degrades(self, adapter: SentinelAdapter) -> None:
        """A response without a tables array yields zero rows, no crash."""
        adapter._session.post = MagicMock(
            side_effect=[
                _mock_response(_TOKEN_PAYLOAD),
                _mock_response({"unexpected": True}),
            ]
        )
        assert adapter.fetch_incidents_raw() == []


# ---------------------------------------------------------------------------
# fetch_incidents (grouping + end-to-end)
# ---------------------------------------------------------------------------


class TestFetchIncidents:
    """Tests for row grouping into NormalizedIncidents."""

    def test_groups_by_incident_number(
        self, adapter: SentinelAdapter, sentinel_fixture: dict[str, Any]
    ) -> None:
        """Three fixture rows collapse into two incidents (42 has two alerts)."""
        adapter._session.post = MagicMock(
            side_effect=[
                _mock_response(_TOKEN_PAYLOAD),
                _mock_response(sentinel_fixture),
            ]
        )
        incidents = adapter.fetch_incidents(hours=24)
        assert [i.incident_id for i in incidents] == ["sentinel-42", "sentinel-43"]
        assert len(incidents[0].events) == 2
        assert len(incidents[1].events) == 1

    def test_fixture_roundtrip_through_triage(
        self,
        adapter: SentinelAdapter,
        sentinel_fixture: dict[str, Any],
        fp_registry: FPRegistry,
    ) -> None:
        """Every fixture incident triages end-to-end (mock intel, offline)."""
        adapter._session.post = MagicMock(
            side_effect=[
                _mock_response(_TOKEN_PAYLOAD),
                _mock_response(sentinel_fixture),
            ]
        )
        for inc in adapter.fetch_incidents():
            profile = get_user_profile(inc.user)
            engine = TriageEngine(inc, profile, fp_registry)
            output = engine.enrich().score().decide().to_output()
            assert _OUTPUT_KEYS.issubset(output.keys())
            assert 0 <= output["risk_score"] <= 100
