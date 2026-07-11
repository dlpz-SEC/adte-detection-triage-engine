"""Tests for adte/store/case_store.py — correlation persistence."""

from __future__ import annotations

import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from adte.models import NormalizedIncident, SignInMetadata
from adte.store import case_store
from adte.store.case_store import (
    clear_cases,
    extract_correlation_keys,
    get_case,
    get_cases_by_ids,
    ingest_alert,
    list_cases,
)

_CASE_ID_RE = re.compile(r"^CASE-\d{8}-[0-9a-f]{6}$")
_T0 = datetime(2026, 7, 10, 12, 0, tzinfo=timezone.utc)


def make_incident(
    incident_id: str = "INC-1",
    user: str = "alice@contoso.com",
    ips: tuple[str, ...] = ("10.0.0.5",),
    event_time: datetime = _T0,
    rule: str = "sshd: brute force trying to get access",
) -> NormalizedIncident:
    """Build a minimal wazuh-flavoured incident for correlation tests."""
    events = [
        SignInMetadata(
            user_principal_name=user,
            ip_address=ip,
            type="authentication",
            timestamp=event_time,
            app_display_name=rule,
        )
        for ip in ips
    ]
    return NormalizedIncident(
        incident_id=incident_id, user=user, source="wazuh", events=events
    )


def make_output(
    risk: float = 55.0,
    verdict: str = "medium_risk",
    tactics: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Build a minimal finalized triage output blob."""
    details = [
        {"id": f"T99{i}", "name": "", "tactic": tactic, "source": "native"}
        for i, tactic in enumerate(tactics)
    ]
    return {
        "verdict": verdict,
        "risk_score": risk,
        "mitre_techniques": [d["id"] for d in details],
        "mitre_details": details,
    }


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    """Isolated per-test SQLite file."""
    return tmp_path / "cases_test.db"


def _backdate_case(db_path: Path, case_id: str, delta: timedelta) -> None:
    """Rewind a case's last_activity by delta (raw connection)."""
    stale = (datetime.now(timezone.utc) - delta).isoformat()
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "UPDATE cases SET last_activity = ? WHERE case_id = ?", (stale, case_id)
        )
        conn.commit()


class TestExtractCorrelationKeys:
    def test_regular_user_and_ip(self) -> None:
        user, ips = extract_correlation_keys(make_incident())
        assert user == "alice@contoso.com"
        assert ips == ["10.0.0.5"]

    def test_system_pseudo_user_not_correlatable(self) -> None:
        incident = make_incident(user="WEBSRV01\\system")
        user, ips = extract_correlation_keys(incident)
        assert user is None
        assert ips == ["10.0.0.5"]  # IP still correlates

    def test_loopback_excluded_rfc1918_included(self) -> None:
        incident = make_incident(ips=("127.0.0.1", "192.168.1.10"))
        _, ips = extract_correlation_keys(incident)
        assert ips == ["192.168.1.10"]

    def test_unparseable_ip_skipped(self) -> None:
        incident = make_incident(ips=("not-an-ip", "203.0.113.7"))
        _, ips = extract_correlation_keys(incident)
        assert ips == ["203.0.113.7"]


class TestIngest:
    def test_tables_created_lazily_and_idempotent(self, db_path: Path) -> None:
        assert ingest_alert(make_output(), make_incident(), db_path) is not None
        assert ingest_alert(make_output(), make_incident("INC-2"), db_path) is not None
        with sqlite3.connect(str(db_path)) as conn:
            tables = {
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
        assert {"cases", "case_members"} <= tables

    def test_first_alert_creates_case(self, db_path: Path) -> None:
        blob = ingest_alert(make_output(), make_incident(), db_path)
        assert blob is not None
        assert _CASE_ID_RE.match(blob["case_id"])
        assert blob["alert_count"] == 1
        assert blob["case_verdict"] == "medium_risk"
        assert blob["escalated"] is False
        assert blob["related_incident_ids"] == []
        assert blob["window_minutes"] == case_store.CASE_WINDOW_MINUTES

    def test_blob_shape(self, db_path: Path) -> None:
        blob = ingest_alert(make_output(), make_incident(), db_path)
        assert set(blob.keys()) == {
            "case_id",
            "alert_count",
            "case_score",
            "case_verdict",
            "escalated",
            "escalation_rationale",
            "kill_chain",
            "related_incident_ids",
            "correlation_keys",
            "window_minutes",
        }
        assert blob["correlation_keys"] == {
            "user": "alice@contoso.com",
            "ips": ["10.0.0.5"],
        }

    def test_same_ip_joins_case(self, db_path: Path) -> None:
        first = ingest_alert(
            make_output(), make_incident("INC-1", user="alice@contoso.com"), db_path
        )
        second = ingest_alert(
            make_output(), make_incident("INC-2", user="bob@contoso.com"), db_path
        )
        assert second["case_id"] == first["case_id"]
        assert second["alert_count"] == 2
        assert second["related_incident_ids"] == ["INC-1"]

    def test_same_user_different_ip_joins_case(self, db_path: Path) -> None:
        first = ingest_alert(
            make_output(), make_incident("INC-1", ips=("10.0.0.5",)), db_path
        )
        second = ingest_alert(
            make_output(), make_incident("INC-2", ips=("203.0.113.9",)), db_path
        )
        assert second["case_id"] == first["case_id"]

    def test_disjoint_keys_create_separate_cases(self, db_path: Path) -> None:
        first = ingest_alert(
            make_output(),
            make_incident("INC-1", user="alice@contoso.com", ips=("10.0.0.5",)),
            db_path,
        )
        second = ingest_alert(
            make_output(),
            make_incident("INC-2", user="bob@contoso.com", ips=("203.0.113.9",)),
            db_path,
        )
        assert second["case_id"] != first["case_id"]

    def test_system_user_alerts_correlate_by_ip_only(self, db_path: Path) -> None:
        a = ingest_alert(
            make_output(),
            make_incident("INC-1", user="SRV1\\system", ips=("10.0.0.5",)),
            db_path,
        )
        # Same pseudo-user, different IP: must NOT join.
        b = ingest_alert(
            make_output(),
            make_incident("INC-2", user="SRV1\\system", ips=("10.0.0.6",)),
            db_path,
        )
        # Same IP: joins even with the pseudo-user.
        c = ingest_alert(
            make_output(),
            make_incident("INC-3", user="SRV2\\system", ips=("10.0.0.5",)),
            db_path,
        )
        assert b["case_id"] != a["case_id"]
        assert c["case_id"] == a["case_id"]

    def test_no_correlatable_keys_returns_none(self, db_path: Path) -> None:
        incident = make_incident(user="HOST\\system", ips=("127.0.0.1",))
        assert ingest_alert(make_output(), incident, db_path) is None
        assert list_cases(db_path) == []

    def test_transitive_key_growth(self, db_path: Path) -> None:
        a = ingest_alert(
            make_output(),
            make_incident("INC-1", user="alice@contoso.com", ips=("10.0.0.5",)),
            db_path,
        )
        # Bob shares alice's IP -> joins; his user key is unioned in.
        b = ingest_alert(
            make_output(),
            make_incident("INC-2", user="bob@contoso.com", ips=("10.0.0.5",)),
            db_path,
        )
        # Bob again from a brand-new IP -> joins via the unioned user key.
        c = ingest_alert(
            make_output(),
            make_incident("INC-3", user="bob@contoso.com", ips=("198.51.100.4",)),
            db_path,
        )
        assert a["case_id"] == b["case_id"] == c["case_id"]
        assert c["alert_count"] == 3

    def test_ambiguous_match_joins_newest_active(self, db_path: Path) -> None:
        a = ingest_alert(
            make_output(),
            make_incident("INC-1", user="alice@contoso.com", ips=("10.0.0.5",)),
            db_path,
        )
        b = ingest_alert(
            make_output(),
            make_incident("INC-2", user="bob@contoso.com", ips=("203.0.113.9",)),
            db_path,
        )
        assert a["case_id"] != b["case_id"]
        # Matches case A by IP and case B by user; B is newer-active.
        c = ingest_alert(
            make_output(),
            make_incident("INC-3", user="bob@contoso.com", ips=("10.0.0.5",)),
            db_path,
        )
        assert c["case_id"] == b["case_id"]

    def test_window_expiry_starts_new_case(self, db_path: Path) -> None:
        first = ingest_alert(make_output(), make_incident("INC-1"), db_path)
        _backdate_case(
            db_path,
            first["case_id"],
            timedelta(minutes=case_store.CASE_WINDOW_MINUTES + 5),
        )
        second = ingest_alert(make_output(), make_incident("INC-2"), db_path)
        assert second["case_id"] != first["case_id"]

    def test_retention_prune_hard_deletes(self, db_path: Path) -> None:
        first = ingest_alert(make_output(), make_incident("INC-1"), db_path)
        _backdate_case(
            db_path,
            first["case_id"],
            timedelta(days=case_store.CASE_RETENTION_DAYS + 1),
        )
        ingest_alert(
            make_output(),
            make_incident("INC-2", user="bob@contoso.com", ips=("203.0.113.9",)),
            db_path,
        )
        with sqlite3.connect(str(db_path)) as conn:
            remaining = [
                r[0] for r in conn.execute("SELECT case_id FROM cases").fetchall()
            ]
        assert first["case_id"] not in remaining

    def test_related_ids_capped(
        self, db_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(case_store, "CASE_MAX_RELATED_IDS", 2)
        blob = None
        for i in range(4):
            blob = ingest_alert(make_output(), make_incident(f"INC-{i}"), db_path)
        assert blob is not None
        assert len(blob["related_incident_ids"]) == 2

    def test_kill_chain_across_members_escalates(self, db_path: Path) -> None:
        tactic_seq = ["Credential Access", "Lateral Movement", "Exfiltration"]
        blob = None
        for i, tactic in enumerate(tactic_seq):
            blob = ingest_alert(
                make_output(risk=55.0, tactics=(tactic,)),
                make_incident(
                    f"INC-{i}", event_time=_T0 + timedelta(minutes=i)
                ),
                db_path,
            )
        assert blob["kill_chain"]["detected"] is True
        assert blob["kill_chain"]["tactics_in_order"] == tactic_seq
        # 55 base + 10 multi + 10 breadth + 20 chain = 95 -> high, escalated.
        assert blob["case_score"] == 95
        assert blob["case_verdict"] == "high_risk"
        assert blob["escalated"] is True

    def test_fail_open_on_broken_store(self, tmp_path: Path) -> None:
        broken = tmp_path / "a_directory"
        broken.mkdir()
        assert ingest_alert(make_output(), make_incident(), broken) is None

    def test_same_incident_reingest_refreshes_not_duplicates(
        self, db_path: Path
    ) -> None:
        """Replaying one alert must not inflate the case or fake a chain:
        two copies of a single 3-tactic alert would otherwise satisfy the
        cross-member kill-chain rule."""
        tactics = ("Credential Access", "Lateral Movement", "Exfiltration")
        first = ingest_alert(
            make_output(risk=40.0, tactics=tactics), make_incident("INC-1"), db_path
        )
        second = ingest_alert(
            make_output(risk=62.0, tactics=tactics), make_incident("INC-1"), db_path
        )
        assert second["case_id"] == first["case_id"]
        assert second["alert_count"] == 1
        assert second["kill_chain"]["detected"] is False
        detail = get_case(second["case_id"], db_path)
        assert len(detail["members"]) == 1
        assert detail["members"][0]["risk_score"] == 62.0  # refreshed in place

    def test_ipv4_mapped_ipv6_correlates_with_plain_ipv4(
        self, db_path: Path
    ) -> None:
        first = ingest_alert(
            make_output(),
            make_incident("INC-1", user="alice@contoso.com", ips=("198.51.100.7",)),
            db_path,
        )
        second = ingest_alert(
            make_output(),
            make_incident(
                "INC-2", user="bob@contoso.com", ips=("::ffff:198.51.100.7",)
            ),
            db_path,
        )
        assert second["case_id"] == first["case_id"]
        assert second["correlation_keys"]["ips"] == ["198.51.100.7"]

    def test_case_id_collision_retried(
        self, db_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A same-day 6-hex ID collision retries with a fresh token instead
        of aborting the ingest."""
        tokens = iter(["c0ffee", "c0ffee", "def123"])
        monkeypatch.setattr(
            case_store.secrets, "token_hex", lambda n: next(tokens)
        )
        first = ingest_alert(make_output(), make_incident("INC-1"), db_path)
        assert first["case_id"].endswith("c0ffee")
        # Disjoint keys -> new case; first token collides, retry succeeds.
        second = ingest_alert(
            make_output(),
            make_incident("INC-2", user="bob@contoso.com", ips=("203.0.113.9",)),
            db_path,
        )
        assert second is not None
        assert second["case_id"].endswith("def123")

    def test_ips_capped_per_member(
        self, db_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(case_store, "CASE_MAX_IPS_PER_MEMBER", 3)
        many_ips = tuple(f"203.0.113.{i}" for i in range(10))
        blob = ingest_alert(make_output(), make_incident(ips=many_ips), db_path)
        assert len(blob["correlation_keys"]["ips"]) == 3
        detail = get_case(blob["case_id"], db_path)
        assert len(detail["members"][0]["ips"]) == 3

    def test_case_ip_union_capped(
        self, db_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(case_store, "CASE_MAX_CASE_IPS", 4)
        ingest_alert(
            make_output(), make_incident("INC-1", ips=("203.0.113.1",)), db_path
        )
        blob = ingest_alert(
            make_output(),
            make_incident(
                "INC-2", ips=tuple(f"203.0.113.{i}" for i in range(1, 10))
            ),
            db_path,
        )
        cases = list_cases(db_path)
        assert [c["case_id"] for c in cases] == [blob["case_id"]]
        assert len(cases[0]["ips"]) == 4  # union stopped at the cap

    def test_full_case_stops_accepting_joins(
        self, db_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A case at CASE_MAX_MEMBERS never matches — the next related alert
        opens a fresh case (bounds the per-ingest recompute)."""
        monkeypatch.setattr(case_store, "CASE_MAX_MEMBERS", 2)
        a = ingest_alert(make_output(), make_incident("INC-1"), db_path)
        b = ingest_alert(make_output(), make_incident("INC-2"), db_path)
        c = ingest_alert(make_output(), make_incident("INC-3"), db_path)
        assert a["case_id"] == b["case_id"]
        assert b["alert_count"] == 2
        assert c["case_id"] != a["case_id"]
        assert c["alert_count"] == 1

    def test_technique_ids_truncated_per_member(
        self, db_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(case_store, "CASE_MAX_TECHNIQUE_IDS", 5)
        output = make_output()
        output["mitre_techniques"] = [f"T{1000 + i}" for i in range(40)]
        blob = ingest_alert(output, make_incident(), db_path)
        detail = get_case(blob["case_id"], db_path)
        assert len(detail["members"][0]["technique_ids"]) == 5

    def test_event_time_normalised_to_utc(self, db_path: Path) -> None:
        """A +02:00 event timestamp must sort correctly against UTC values
        (stored comparisons are lexicographic)."""
        from datetime import timedelta as td

        offset_tz = timezone(td(hours=2))
        # 12:00+02:00 == 10:00Z — earlier than the second member's 11:00Z.
        first = ingest_alert(
            make_output(),
            make_incident(
                "INC-OFFSET",
                event_time=datetime(2026, 7, 10, 12, 0, tzinfo=offset_tz),
            ),
            db_path,
        )
        ingest_alert(
            make_output(),
            make_incident(
                "INC-UTC",
                event_time=datetime(2026, 7, 10, 11, 0, tzinfo=timezone.utc),
            ),
            db_path,
        )
        detail = get_case(first["case_id"], db_path)
        assert detail["members"][0]["event_time"].endswith("+00:00")
        assert [m["incident_id"] for m in detail["members"]] == [
            "INC-OFFSET",
            "INC-UTC",
        ]


class TestQueries:
    def test_cross_connection_visibility(self, db_path: Path) -> None:
        """Every store call opens a fresh connection — simulating two gunicorn
        workers sharing only the DB file (the 731600d sessions lesson)."""
        blob = ingest_alert(make_output(), make_incident(), db_path)
        for _ in range(3):
            cases = list_cases(db_path)
            assert [c["case_id"] for c in cases] == [blob["case_id"]]
        detail = get_case(blob["case_id"], db_path)
        assert detail is not None
        assert len(detail["members"]) == 1
        assert detail["members"][0]["incident_id"] == "INC-1"

    def test_list_status_filter(self, db_path: Path) -> None:
        blob = ingest_alert(make_output(), make_incident(), db_path)
        assert [c["case_id"] for c in list_cases(db_path, status="open")] == [
            blob["case_id"]
        ]
        assert list_cases(db_path, status="closed") == []
        _backdate_case(
            db_path,
            blob["case_id"],
            timedelta(minutes=case_store.CASE_WINDOW_MINUTES + 5),
        )
        assert list_cases(db_path, status="open") == []
        closed = list_cases(db_path, status="closed")
        assert [c["case_id"] for c in closed] == [blob["case_id"]]
        assert closed[0]["status"] == "closed"

    def test_get_case_detail_shape(self, db_path: Path) -> None:
        blob = ingest_alert(
            make_output(tactics=("Credential Access",)), make_incident(), db_path
        )
        detail = get_case(blob["case_id"], db_path)
        assert detail["escalation_rationale"] == blob["escalation_rationale"]
        member = detail["members"][0]
        assert member["user"] == "alice@contoso.com"
        assert member["ips"] == ["10.0.0.5"]
        assert member["tactics"] == ["Credential Access"]
        assert member["rule_name"].startswith("sshd")
        assert member["event_time"] is not None

    def test_get_case_unknown_returns_none(self, db_path: Path) -> None:
        ingest_alert(make_output(), make_incident(), db_path)
        assert get_case("CASE-19700101-000000", db_path) is None

    def test_get_cases_by_ids_preserves_order(self, db_path: Path) -> None:
        a = ingest_alert(make_output(), make_incident("INC-1"), db_path)
        b = ingest_alert(
            make_output(),
            make_incident("INC-2", user="bob@contoso.com", ips=("203.0.113.9",)),
            db_path,
        )
        summaries = get_cases_by_ids([b["case_id"], a["case_id"]], db_path)
        assert [s["case_id"] for s in summaries] == [b["case_id"], a["case_id"]]
        assert get_cases_by_ids([], db_path) == []

    def test_clear_cases_soft_deletes(self, db_path: Path) -> None:
        blob = ingest_alert(make_output(), make_incident(), db_path)
        assert clear_cases(db_path) is True
        assert list_cases(db_path) == []
        assert get_case(blob["case_id"], db_path) is None
        with sqlite3.connect(str(db_path)) as conn:
            row = conn.execute(
                "SELECT deleted_at FROM cases WHERE case_id = ?", (blob["case_id"],)
            ).fetchone()
        assert row[0] is not None

    def test_soft_deleted_case_not_rejoined(self, db_path: Path) -> None:
        first = ingest_alert(make_output(), make_incident("INC-1"), db_path)
        clear_cases(db_path)
        second = ingest_alert(make_output(), make_incident("INC-2"), db_path)
        assert second["case_id"] != first["case_id"]

    def test_reads_fail_closed_on_broken_store(self, tmp_path: Path) -> None:
        broken = tmp_path / "a_directory"
        broken.mkdir()
        assert list_cases(broken) == []
        assert get_case("CASE-20260710-abcdef", broken) is None
        assert get_cases_by_ids(["CASE-20260710-abcdef"], broken) == []
        assert clear_cases(broken) is False


def test_member_event_time_none_when_no_events(db_path: Path) -> None:
    incident = NormalizedIncident(
        incident_id="INC-NE", user="alice@contoso.com", source="generic", events=[]
    )
    blob = ingest_alert(make_output(), incident, db_path)
    # No events -> no IPs, but the user key still correlates.
    assert blob is not None
    detail = get_case(blob["case_id"], db_path)
    assert detail["members"][0]["event_time"] is None
