"""Tests for native MITRE ATT&CK ingestion (Wazuh ``rule.mitre.id`` → ``technique_ids``).

Covers the three A1 layers:
  1. Adapter extraction — ``rule.mitre.id`` lands on the event, defensively.
  2. Model field — additive ``technique_ids`` defaults empty and round-trips.
  3. Route union — native IDs merge into ``mitre_techniques`` after the
     signal-derived IDs, deduplicated.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from adte.adapters.wazuh import WazuhAdapter
from adte.models import NormalizedIncident, SentinelIncident
from adte.store.audit_log import init_db

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _wazuh_alert(rule_extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build a minimal valid Wazuh alert dict with optional rule overrides.

    Args:
        rule_extra: Extra keys merged into the ``rule`` object.

    Returns:
        A raw alert dict shaped like a fetched OpenSearch ``_source``.
    """
    rule: dict[str, Any] = {"level": 10, "description": "SSH brute force"}
    if rule_extra:
        rule.update(rule_extra)
    return {
        "id": "alert-native-mitre",
        "@timestamp": "2024-01-15T10:30:00.000Z",
        "rule": rule,
        "agent": {"id": "001", "name": "host-01", "ip": "10.0.0.1"},
        "data": {"srcip": "198.51.100.23", "dstuser": "root-account"},
    }


# ---------------------------------------------------------------------------
# 1. Adapter extraction
# ---------------------------------------------------------------------------


class TestWazuhNativeMitreExtraction:
    """normalize_alert must carry rule.mitre.id onto the event, defensively."""

    def test_mitre_id_list_populates_technique_ids(self) -> None:
        """A standard rule.mitre.id list lands verbatim on the event."""
        alert = _wazuh_alert({"mitre": {"id": ["T1110", "T1078.004"]}})
        incident = WazuhAdapter.normalize_alert(alert)
        assert incident.events[0].technique_ids == ["T1110", "T1078.004"]

    def test_missing_mitre_yields_empty_list(self) -> None:
        """No rule.mitre object → technique_ids defaults to []."""
        incident = WazuhAdapter.normalize_alert(_wazuh_alert())
        assert incident.events[0].technique_ids == []

    def test_bare_string_id_is_wrapped(self) -> None:
        """A bare-string rule.mitre.id is tolerated and wrapped in a list."""
        alert = _wazuh_alert({"mitre": {"id": "T1110"}})
        incident = WazuhAdapter.normalize_alert(alert)
        assert incident.events[0].technique_ids == ["T1110"]

    def test_non_dict_mitre_is_tolerated(self) -> None:
        """A malformed non-dict rule.mitre → empty list, no crash."""
        alert = _wazuh_alert({"mitre": "T1110"})
        incident = WazuhAdapter.normalize_alert(alert)
        assert incident.events[0].technique_ids == []

    def test_non_list_id_is_tolerated(self) -> None:
        """A malformed non-list/non-string id value → empty list, no crash."""
        alert = _wazuh_alert({"mitre": {"id": 42}})
        incident = WazuhAdapter.normalize_alert(alert)
        assert incident.events[0].technique_ids == []

    def test_falsy_entries_filtered_and_values_stringified(self) -> None:
        """Empty/None entries drop; non-string entries stringify."""
        alert = _wazuh_alert({"mitre": {"id": ["T1110", "", None, 1059]}})
        incident = WazuhAdapter.normalize_alert(alert)
        assert incident.events[0].technique_ids == ["T1110", "1059"]


# ---------------------------------------------------------------------------
# 2. Model field
# ---------------------------------------------------------------------------


class TestTechniqueIdsModelField:
    """The additive technique_ids field defaults empty and round-trips."""

    def test_from_sentinel_events_default_empty(
        self, incident_true_positive: NormalizedIncident
    ) -> None:
        """Sentinel-format incidents (no native IDs) get [] on every event."""
        assert all(e.technique_ids == [] for e in incident_true_positive.events)

    def test_round_trips_through_json_dump(self) -> None:
        """technique_ids survives model_dump(mode='json') → model_validate."""
        alert = _wazuh_alert({"mitre": {"id": ["T1021.004"]}})
        incident = WazuhAdapter.normalize_alert(alert)
        dumped = incident.model_dump(mode="json")
        assert dumped["events"][0]["technique_ids"] == ["T1021.004"]
        revalidated = NormalizedIncident.model_validate(dumped)
        assert revalidated.events[0].technique_ids == ["T1021.004"]


# ---------------------------------------------------------------------------
# 3. Route union
# ---------------------------------------------------------------------------


@pytest.fixture()
def triage_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Flask test client with DB_PATH redirected to an isolated tmp database."""
    db_path = tmp_path / "test_native_mitre.db"

    import adte.server as srv

    monkeypatch.setattr(srv, "DB_PATH", db_path)
    init_db(db_path)

    srv.app.config["TESTING"] = True
    with srv.app.test_client() as client:
        yield client


class TestTriageRouteUnion:
    """POST /api/triage unions native event technique_ids into the output."""

    @staticmethod
    def _payload_with_native_ids(
        incident: NormalizedIncident, ids: list[str], event_indices: list[int]
    ) -> dict[str, Any]:
        """Dump an incident and inject native IDs onto the given events."""
        payload = incident.model_dump(mode="json")
        for idx in event_indices:
            payload["events"][idx]["technique_ids"] = list(ids)
        return payload

    def test_native_ids_appear_in_mitre_techniques(
        self, triage_client, incident_true_positive: NormalizedIncident
    ) -> None:
        """A native ID not derivable from signals shows up in the output."""
        payload = self._payload_with_native_ids(
            incident_true_positive, ["T1105"], [0]
        )
        resp = triage_client.post("/api/triage", json=payload)
        assert resp.status_code == 200
        assert "T1105" in resp.get_json()["mitre_techniques"]

    def test_native_ids_deduplicated_across_events(
        self, triage_client, incident_true_positive: NormalizedIncident
    ) -> None:
        """The same native ID on two events appears exactly once."""
        assert len(incident_true_positive.events) >= 2
        payload = self._payload_with_native_ids(
            incident_true_positive, ["T1105"], [0, 1]
        )
        resp = triage_client.post("/api/triage", json=payload)
        assert resp.status_code == 200
        assert resp.get_json()["mitre_techniques"].count("T1105") == 1

    def test_signal_derived_ids_keep_first_position(
        self, triage_client, incident_true_positive: NormalizedIncident
    ) -> None:
        """Signal-derived IDs precede native additions in the output list."""
        payload = self._payload_with_native_ids(
            incident_true_positive, ["T1105"], [0]
        )
        resp = triage_client.post("/api/triage", json=payload)
        assert resp.status_code == 200
        techniques = resp.get_json()["mitre_techniques"]
        # The true-positive example fires signals, so the list has signal-derived
        # entries before the native one — the native ID must be last.
        assert len(techniques) >= 2
        assert techniques[-1] == "T1105"

    def test_incident_without_native_ids_unchanged(
        self, triage_client, incident_true_positive: NormalizedIncident
    ) -> None:
        """No native IDs → output matches the signal-derived set only."""
        payload = incident_true_positive.model_dump(mode="json")
        resp = triage_client.post("/api/triage", json=payload)
        assert resp.status_code == 200
        body = resp.get_json()
        assert "T1105" not in body["mitre_techniques"]
        assert all(t for t in body["mitre_techniques"])
