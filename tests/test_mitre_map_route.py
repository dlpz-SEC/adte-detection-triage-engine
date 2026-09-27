"""Tests for the public ``GET /api/mitre/map`` technique reference route.

The SPA used to resolve technique cards from a hand-maintained client-side
dict, so any ID outside it (e.g. the critical example's native ``T1090.003``)
rendered as a bare ID with no tactic or NIST mapping.  The route serves the
server's own technique table instead.  Pinned here: the route is genuinely
public in secured mode, its exact shape, full YAML coverage in first-seen
order, the first-wins rule it shares with ``get_technique_details``, and the
detail shape for IDs the map does not know.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from adte import case_policy
from adte.intel import mitre_mapper
from adte.intel.mitre_mapper import MitreMapper, get_technique_details
from adte.store.audit_log import init_db

_YAML_PATH = (
    Path(__file__).resolve().parent.parent / "adte" / "data" / "mitre_technique_map.yaml"
)
_ENTRY_KEYS = {"id", "name", "tactic", "nist_csf", "nist_csf_name"}
_DETAIL_KEYS = _ENTRY_KEYS | {"source"}
# Map-entry field -> the raw YAML key it is sourced from.
_YAML_SOURCE = {
    "name": "mitre_technique_name",
    "tactic": "mitre_tactic",
    "nist_csf": "nist_detect",
    "nist_csf_name": "nist_category",
}
_ADMIN_KEY = "admin-test-key"


def _raw_mappings() -> list[dict[str, Any]]:
    """Load the raw YAML entries directly, bypassing the mapper under test."""
    return yaml.safe_load(_YAML_PATH.read_text(encoding="utf-8"))["mappings"]


def _first_seen_ids() -> list[str]:
    """Return the distinct non-empty technique IDs in raw YAML first-seen order."""
    seen: list[str] = []
    for entry in _raw_mappings():
        tid = entry.get("mitre_technique_id") or ""
        if tid and tid not in seen:
            seen.append(tid)
    return seen


def _expected_fields(entry: dict[str, Any]) -> dict[str, str]:
    """Project one raw YAML entry onto the map-entry field names."""
    return {field: entry.get(src, "") for field, src in _YAML_SOURCE.items()}


@pytest.fixture()
def anon_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Anonymous Flask test client in SECURED mode.

    TESTING is off (so ``require_role`` enforces auth) and an admin key is
    configured (so the server is not in open/demo mode), but the client sends
    no key header and holds no session cookie.
    """
    import adte.server as srv

    db_path = tmp_path / "test_mitre_map_route.db"
    monkeypatch.setattr(srv, "DB_PATH", db_path)
    monkeypatch.setattr(srv.limiter, "enabled", False)
    monkeypatch.setenv("ADTE_API_KEY_ADMIN", _ADMIN_KEY)
    monkeypatch.setitem(srv.app.config, "TESTING", False)
    init_db(db_path)
    with srv.app.test_client() as client:
        yield client


def _get_map(client) -> dict[str, Any]:
    """GET /api/mitre/map anonymously and return the parsed JSON body."""
    resp = client.get("/api/mitre/map")
    assert resp.status_code == 200
    return resp.get_json()


class TestPublicAccess:
    """The map is static reference data the SPA needs before any login."""

    def test_anonymous_get_succeeds_in_secured_mode(self, anon_client) -> None:
        """No key, no cookie, auth enforced: the map still answers 200."""
        # Precondition: this setup really is secured mode — an auth-gated
        # GET is refused for the same anonymous client.
        assert anon_client.get("/api/verdicts").status_code == 401
        resp = anon_client.get("/api/mitre/map")
        assert resp.status_code == 200
        assert resp.is_json

    def test_route_is_get_only(self, anon_client) -> None:
        """The route accepts no mutating verb."""
        assert anon_client.post("/api/mitre/map", json={}).status_code == 405


class TestShape:
    """Exact response contract shared with the SPA."""

    def test_top_level_keys(self, anon_client) -> None:
        """Only the technique table and the tactic order are exposed."""
        assert set(_get_map(anon_client)) == {"techniques", "kill_chain_order"}

    def test_kill_chain_order_matches_case_policy(self, anon_client) -> None:
        """Tactic order is the case layer's canonical 14-tactic list."""
        body = _get_map(anon_client)
        assert body["kill_chain_order"] == list(case_policy.KILL_CHAIN_ORDER)
        assert len(body["kill_chain_order"]) == 14

    def test_entry_shape(self, anon_client) -> None:
        """Every entry has exactly the five display fields, keyed by its own ID."""
        techniques = _get_map(anon_client)["techniques"]
        assert techniques
        assert "" not in techniques
        for key, entry in techniques.items():
            assert set(entry) == _ENTRY_KEYS
            assert entry["id"] == key
            assert "rule_keywords" not in entry
            assert all(isinstance(value, str) for value in entry.values())


class TestCoverage:
    """The map covers the YAML completely and groups onto known tactics."""

    def test_every_yaml_id_present_in_first_seen_order(self, anon_client) -> None:
        """One entry per distinct YAML ID, no extras, in YAML first-seen order."""
        techniques = _get_map(anon_client)["techniques"]
        assert list(techniques) == _first_seen_ids()

    def test_every_tactic_is_in_kill_chain_order(self, anon_client) -> None:
        """Each technique's tactic can be placed in the kill-chain grouping."""
        body = _get_map(anon_client)
        for entry in body["techniques"].values():
            assert entry["tactic"] in body["kill_chain_order"], entry["id"]


class TestFirstWins:
    """The map and get_technique_details resolve repeated IDs identically."""

    def test_map_agrees_with_get_technique_details(self, anon_client) -> None:
        """For every ID, the map entry equals the detail lookup's fields."""
        techniques = _get_map(anon_client)["techniques"]
        for tid, entry in techniques.items():
            detail = get_technique_details([tid])[0]
            assert {k: detail[k] for k in _ENTRY_KEYS} == entry

    def test_duplicate_ids_carry_first_occurrence(self, anon_client) -> None:
        """An ID repeated in the YAML resolves to its FIRST entry's fields."""
        techniques = _get_map(anon_client)["techniques"]
        first: dict[str, dict[str, Any]] = {}
        counts: dict[str, int] = {}
        for entry in _raw_mappings():
            tid = entry.get("mitre_technique_id") or ""
            if not tid:
                continue
            first.setdefault(tid, entry)
            counts[tid] = counts.get(tid, 0) + 1
        for tid in (t for t, n in counts.items() if n > 1):
            expected = _expected_fields(first[tid])
            assert {k: techniques[tid][k] for k in _YAML_SOURCE} == expected, tid

    def test_rule_on_a_controlled_mapping(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """First entry wins and ID-less entries are skipped, in both lookups."""
        synthetic = MitreMapper(
            [
                {"rule_keywords": ["a"], "mitre_technique_name": "No ID"},
                {"mitre_technique_id": "", "mitre_technique_name": "Empty ID"},
                {
                    "mitre_technique_id": "T0001",
                    "mitre_technique_name": "First",
                    "mitre_tactic": "Execution",
                    "nist_detect": "DE.X-1",
                    "nist_category": "First category",
                },
                {
                    "mitre_technique_id": "T0001",
                    "mitre_technique_name": "Second",
                    "mitre_tactic": "Impact",
                    "nist_detect": "DE.X-2",
                    "nist_category": "Second category",
                },
            ]
        )
        monkeypatch.setattr(mitre_mapper, "_singleton", synthetic)
        expected = {
            "id": "T0001",
            "name": "First",
            "tactic": "Execution",
            "nist_csf": "DE.X-1",
            "nist_csf_name": "First category",
        }
        assert mitre_mapper.get_technique_map() == {"T0001": expected}
        assert get_technique_details(["T0001"]) == [{**expected, "source": "signal"}]


class TestDetails:
    """get_technique_details carries the NIST fields the map exposes."""

    def test_unknown_id_shape(self) -> None:
        """An ID outside the map keeps its slot with every display field empty."""
        assert get_technique_details(["T9999"]) == [
            {
                "id": "T9999",
                "name": "",
                "tactic": "",
                "source": "signal",
                "nist_csf": "",
                "nist_csf_name": "",
            }
        ]

    def test_known_id_carries_yaml_nist_fields(self) -> None:
        """T1090.003 (the blank card) resolves every field from its YAML entry."""
        raw = next(e for e in _raw_mappings() if e.get("mitre_technique_id") == "T1090.003")
        detail = get_technique_details(["T1090.003"], {"T1090.003": "native"})[0]
        assert set(detail) == _DETAIL_KEYS
        assert detail["source"] == "native"
        assert {k: detail[k] for k in _YAML_SOURCE} == _expected_fields(raw)
        assert detail["nist_csf"] and detail["nist_csf_name"]

    def test_triage_details_match_the_map(self, anon_client) -> None:
        """Triage mitre_details and the map are one source of truth."""
        techniques = _get_map(anon_client)["techniques"]
        examples = anon_client.get("/api/examples").get_json()
        resp = anon_client.post(
            "/api/triage", json=examples["critical"], headers={"X-ADTE-Key": _ADMIN_KEY}
        )
        assert resp.status_code == 200
        details = resp.get_json()["mitre_details"]
        by_id = {d["id"]: d for d in details}
        assert "T1090.003" in by_id
        for d in details:
            assert set(d) == _DETAIL_KEYS
            entry = techniques.get(d["id"])
            if entry is None:
                assert d["name"] == d["tactic"] == d["nist_csf"] == d["nist_csf_name"] == ""
            else:
                assert {k: d[k] for k in _ENTRY_KEYS} == entry


class TestMapperFunction:
    """get_technique_map's own contract, independent of the route."""

    def test_returns_fresh_copies(self) -> None:
        """Mutating one result cannot corrupt the shared index or later calls."""
        first = mitre_mapper.get_technique_map()
        original_name = first["T1090.003"]["name"]
        first["T1090.003"]["name"] = "tampered"
        first.clear()
        assert mitre_mapper.get_technique_map()["T1090.003"]["name"] == original_name
        assert get_technique_details(["T1090.003"])[0]["name"] == original_name

    def test_missing_yaml_yields_empty_map(
        self, anon_client, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No YAML: empty map, empty-field details, and the route still answers."""
        monkeypatch.setattr(mitre_mapper, "_singleton", None)
        monkeypatch.setattr(mitre_mapper, "_MAPPING_PATH", tmp_path / "missing.yaml")
        assert mitre_mapper.get_technique_map() == {}
        assert get_technique_details(["T1090.003"])[0]["nist_csf"] == ""
        body = _get_map(anon_client)
        assert body == {
            "techniques": {},
            "kill_chain_order": list(case_policy.KILL_CHAIN_ORDER),
        }
