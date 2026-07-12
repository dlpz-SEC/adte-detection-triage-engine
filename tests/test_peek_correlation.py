"""Tests for peek_correlation_context — the read-only pre-scoring look-ahead.

The peek feeds the engine's additive ``cluster_context`` signal (Phase 31).
It must mirror ingest's matching rules, exclude the incident itself from
every sibling fact, never write, and fail open.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from adte.decision_policy import ClusterContext
from adte.models import NormalizedIncident, SignInMetadata
from adte.store import case_store
from adte.store.case_store import (
    clear_cases,
    ingest_alert,
    peek_correlation_context,
)

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
    return tmp_path / "peek_test.db"


def _backdate_case(db_path: Path, case_id: str, delta: timedelta) -> None:
    """Rewind a case's last_activity by delta (raw connection)."""
    stale = (datetime.now(timezone.utc) - delta).isoformat()
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "UPDATE cases SET last_activity = ? WHERE case_id = ?", (stale, case_id)
        )
        conn.commit()


def _row_counts(db_path: Path) -> tuple[int, int]:
    """Return (cases, case_members) row counts."""
    with sqlite3.connect(str(db_path)) as conn:
        cases = conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
        members = conn.execute("SELECT COUNT(*) FROM case_members").fetchone()[0]
    return cases, members


class TestPeekReturnsNone:
    def test_no_correlatable_keys_returns_none(self, db_path: Path) -> None:
        incident = make_incident(user="WEBSRV01\\system", ips=("127.0.0.1",))
        assert peek_correlation_context(incident, db_path) is None

    def test_fresh_db_returns_none(self, db_path: Path) -> None:
        assert peek_correlation_context(make_incident(), db_path) is None

    def test_self_only_case_returns_none(self, db_path: Path) -> None:
        """A singleton case containing only this incident is not context."""
        assert ingest_alert(make_output(), make_incident("INC-1"), db_path)
        assert peek_correlation_context(make_incident("INC-1"), db_path) is None

    def test_window_expired_case_ignored(self, db_path: Path) -> None:
        case = ingest_alert(make_output(), make_incident("INC-1"), db_path)
        _backdate_case(db_path, case["case_id"], timedelta(minutes=61))
        assert peek_correlation_context(make_incident("INC-2"), db_path) is None

    def test_soft_deleted_case_ignored(self, db_path: Path) -> None:
        assert ingest_alert(make_output(), make_incident("INC-1"), db_path)
        assert clear_cases(db_path)
        assert peek_correlation_context(make_incident("INC-2"), db_path) is None

    def test_full_case_yields_no_context(
        self, db_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Inherits the full-case skip from _find_matching_case."""
        assert ingest_alert(make_output(), make_incident("INC-1"), db_path)
        monkeypatch.setattr(case_store, "CASE_MAX_MEMBERS", 1)
        assert peek_correlation_context(make_incident("INC-2"), db_path) is None

    def test_fail_open_on_corrupt_db_path(self, tmp_path: Path) -> None:
        """db_path pointing at a directory must return None, not raise."""
        assert peek_correlation_context(make_incident(), tmp_path) is None


class TestPeekContext:
    def test_sibling_fields_populated(self, db_path: Path) -> None:
        seeded = ingest_alert(
            make_output(risk=70.0, tactics=("Credential Access", "Lateral Movement")),
            make_incident("INC-1"),
            db_path,
        )
        ctx = peek_correlation_context(make_incident("INC-2"), db_path)
        assert isinstance(ctx, ClusterContext)
        assert ctx.case_id == seeded["case_id"]
        assert ctx.sibling_count == 1
        assert ctx.distinct_sibling_tactics == 2
        assert ctx.kill_chain_detected is False
        assert ctx.max_sibling_risk_score == 70.0
        assert ctx.window_minutes == case_store.CASE_WINDOW_MINUTES

    def test_user_key_correlation_without_shared_ip(self, db_path: Path) -> None:
        assert ingest_alert(
            make_output(), make_incident("INC-1", ips=("10.0.0.5",)), db_path
        )
        ctx = peek_correlation_context(
            make_incident("INC-2", ips=("203.0.113.9",)), db_path
        )
        assert ctx is not None
        assert ctx.sibling_count == 1

    def test_sibling_facts_exclude_self_on_reingest(self, db_path: Path) -> None:
        """Re-triaging INC-2 after it joined sees only INC-1's facts."""
        assert ingest_alert(make_output(risk=40.0), make_incident("INC-1"), db_path)
        assert ingest_alert(
            make_output(risk=90.0, tactics=("Exfiltration",)),
            make_incident("INC-2"),
            db_path,
        )
        ctx = peek_correlation_context(make_incident("INC-2"), db_path)
        assert ctx is not None
        assert ctx.sibling_count == 1  # INC-1 only, not itself
        assert ctx.max_sibling_risk_score == 40.0  # not its own 90
        assert ctx.distinct_sibling_tactics == 0  # INC-1 carried none

    def test_kill_chain_detected_over_siblings(self, db_path: Path) -> None:
        sequence = [
            ("INC-KC1", ("Credential Access",), _T0),
            ("INC-KC2", ("Lateral Movement",), _T0 + timedelta(minutes=5)),
            ("INC-KC3", ("Exfiltration",), _T0 + timedelta(minutes=10)),
        ]
        for incident_id, tactics, event_time in sequence:
            assert ingest_alert(
                make_output(tactics=tactics),
                make_incident(incident_id, event_time=event_time),
                db_path,
            )
        ctx = peek_correlation_context(make_incident("INC-4"), db_path)
        assert ctx is not None
        assert ctx.sibling_count == 3
        assert ctx.kill_chain_detected is True
        assert ctx.distinct_sibling_tactics == 3

    def test_reingested_member_excludes_own_tactics_from_kill_chain(
        self, db_path: Path
    ) -> None:
        """Re-triaging a member never self-awards the kill-chain bonus: the
        chain is recomputed over siblings only, not read from the case row
        (which still counts this incident). Phase-31 review fix."""
        assert ingest_alert(
            make_output(tactics=("Credential Access", "Lateral Movement")),
            make_incident("INC-X", event_time=_T0),
            db_path,
        )
        assert ingest_alert(
            make_output(tactics=("Exfiltration",)),
            make_incident("INC-Y", event_time=_T0 + timedelta(minutes=5)),
            db_path,
        )
        # A fresh, non-member alert sees the full two-member chain.
        fresh = peek_correlation_context(make_incident("INC-Z"), db_path)
        assert fresh is not None and fresh.kill_chain_detected is True
        # Re-triaging INC-X excludes its own two tactics; the lone sibling
        # INC-Y (one tactic) cannot form a chain on its own.
        re_x = peek_correlation_context(make_incident("INC-X"), db_path)
        assert re_x is not None
        assert re_x.sibling_count == 1
        assert re_x.kill_chain_detected is False
        # Same for INC-Y: sibling INC-X's two tactics sit in one member.
        re_y = peek_correlation_context(make_incident("INC-Y"), db_path)
        assert re_y is not None
        assert re_y.kill_chain_detected is False

    def test_peek_is_read_only(self, db_path: Path) -> None:
        assert ingest_alert(make_output(), make_incident("INC-1"), db_path)
        before = _row_counts(db_path)
        assert peek_correlation_context(make_incident("INC-2"), db_path) is not None
        assert _row_counts(db_path) == before
