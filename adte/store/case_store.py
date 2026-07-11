"""SQLite-backed case store for the alert-correlation layer.

Groups triaged alerts into **cases**: alerts that share an entity (source IP
or user) within a rolling time window.  Case scoring/escalation policy lives
in :mod:`adte.case_policy`; this module owns persistence and the
join-or-create decision.

Design notes:

- **Zero module-level mutable state.**  Sessions taught this lesson the hard
  way (commit ``731600d``): gunicorn runs 2 worker processes, so any Python
  dict/cache here would be per-worker and correlation would randomly miss
  cases created by the other worker.  Every public function opens a fresh
  connection to the shared SQLite file — the only cross-worker store in ADTE.
- **Race-safe join-or-create.**  Two workers ingesting related alerts at the
  same instant must not create duplicate cases.  ``_connect`` opens with
  ``isolation_level=None`` (a deliberate deviation from ``session_store``) so
  ``ingest_alert`` can wrap SELECT-then-INSERT in an explicit
  ``BEGIN IMMEDIATE`` transaction, which takes the write lock up front and
  serialises the two workers.  ``PRAGMA busy_timeout`` makes the loser wait
  briefly instead of erroring.
- **Fail-open ingest.**  Correlation is a non-blocking enrichment: a broken
  case store must never block a verdict.  ``ingest_alert`` catches every
  exception and returns ``None`` (the route renders ``"case": null``).  Reads
  fail closed-empty, matching ``query_verdicts``.
- **Windowing clock is ingestion time** (arrival at ADTE) — immune to source
  clock skew, and replayed demo fixtures with historical event timestamps
  still correlate.  Member **event time** is kept separately and drives
  kill-chain ordering.
- **Cases are derived data.**  The ``verdicts`` audit table remains the
  forensic record, so idle cases past retention are hard-deleted
  opportunistically on ingest (the audit log itself is soft-delete-only).
  The admin clear is a soft delete, mirroring ``clear_verdicts``.
- Tables are created lazily on every connect (``CREATE TABLE IF NOT
  EXISTS``), and live in the audit database (``ADTE_AUDIT_DB``) — on an
  ephemeral disk (Railway without a volume) a redeploy clears open cases,
  same as sessions.

NIST 800-61 Phase: Detection & Analysis — correlation of related events
(SP 800-61r2 §3.2.4).
"""

from __future__ import annotations

import json
import logging
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from adte.case_policy import (
    CASE_MAX_CASE_IPS,
    CASE_MAX_IPS_PER_MEMBER,
    CASE_MAX_MEMBERS,
    CASE_MAX_RELATED_IDS,
    CASE_MAX_TECHNIQUE_IDS,
    CASE_RETENTION_DAYS,
    CASE_WINDOW_MINUTES,
    NON_CORRELATABLE_USER_LOCALS,
    detect_kill_chain,
    score_case,
)
from adte.models import NormalizedIncident

_log = logging.getLogger(__name__)

_CREATE_CASES_SQL: str = """
CREATE TABLE IF NOT EXISTS cases (
    case_id              TEXT PRIMARY KEY,
    created_at           TEXT NOT NULL,
    last_activity        TEXT NOT NULL,
    users                TEXT NOT NULL DEFAULT '[]',
    ips                  TEXT NOT NULL DEFAULT '[]',
    alert_count          INTEGER NOT NULL DEFAULT 0,
    case_score           INTEGER NOT NULL DEFAULT 0,
    case_verdict         TEXT NOT NULL DEFAULT 'low_risk',
    escalated            INTEGER NOT NULL DEFAULT 0,
    escalation_rationale TEXT NOT NULL DEFAULT '[]',
    kill_chain           TEXT NOT NULL DEFAULT '{"detected": false, "tactics_in_order": []}',
    deleted_at           TEXT
)
"""

_CREATE_MEMBERS_SQL: str = """
CREATE TABLE IF NOT EXISTS case_members (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id       TEXT NOT NULL,
    incident_id   TEXT NOT NULL,
    verdict       TEXT NOT NULL,
    risk_score    REAL NOT NULL,
    user          TEXT,
    ips           TEXT NOT NULL DEFAULT '[]',
    technique_ids TEXT NOT NULL DEFAULT '[]',
    tactics       TEXT NOT NULL DEFAULT '[]',
    rule_name     TEXT,
    event_time    TEXT,
    ingested_at   TEXT NOT NULL
)
"""

_CREATE_INDEX_SQL: tuple[str, ...] = (
    "CREATE INDEX IF NOT EXISTS idx_case_members_case_id ON case_members(case_id)",
    "CREATE INDEX IF NOT EXISTS idx_cases_last_activity ON cases(last_activity)",
)


def _ensure_aware(dt: datetime) -> datetime:
    """Coerce a naive datetime to UTC-aware (assume-UTC semantics).

    Deliberate 3-line duplication of the engine's private helper
    (``engine.py`` ``_ensure_aware``): importing it would couple this module
    to change-controlled code.  Both assume naive timestamps are UTC — if the
    engine's convention ever changes, update this copy too.

    Args:
        dt: Possibly-naive datetime (e.g. ``NormalizedIncident.created_time``
            defaults to naive ``utcnow``).

    Returns:
        The same instant as a timezone-aware UTC datetime.
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _connect(db_path: str | Path) -> sqlite3.Connection:
    """Open a connection with tables guaranteed present.

    ``isolation_level=None`` puts the connection in autocommit mode so that
    ``ingest_alert`` controls its own ``BEGIN IMMEDIATE`` transaction
    explicitly (see module docstring).  ``busy_timeout`` makes a worker that
    loses the write-lock race wait instead of failing — 5 s to match the
    default budget every other writer on this DB file already gets
    (``audit_log`` and ``session_store`` use sqlite3's 5 s default), so the
    case store is never the first to give up under contention.

    Args:
        db_path: Path to the SQLite database file (shared with the audit log).

    Returns:
        An open ``sqlite3.Connection`` with ``row_factory`` set.
    """
    conn = sqlite3.connect(str(db_path), check_same_thread=False, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute(_CREATE_CASES_SQL)
    conn.execute(_CREATE_MEMBERS_SQL)
    for stmt in _CREATE_INDEX_SQL:
        conn.execute(stmt)
    return conn


def extract_correlation_keys(
    incident: NormalizedIncident,
) -> tuple[str | None, list[str]]:
    """Derive the entity keys an incident can correlate on.

    Args:
        incident: The normalized incident being triaged.

    Returns:
        ``(user_key, ip_keys)`` where ``user_key`` is the lower-cased user
        principal (or ``None`` when it is a non-correlatable service identity
        such as Wazuh's ``AGENT\\system``) and ``ip_keys`` are the unique,
        normalised event source IPs eligible for matching — loopback and
        unspecified addresses excluded, private RFC1918 deliberately
        *included* (internal lateral movement is the correlation story).
    """
    import ipaddress

    user_key: str | None = (incident.user or "").strip().lower()
    local_part = user_key.split("\\")[-1] if user_key else ""
    if local_part in NON_CORRELATABLE_USER_LOCALS:
        user_key = None

    ip_keys: list[str] = []
    for event in incident.events:
        raw = (event.ip_address or "").strip()
        if not raw:
            continue
        try:
            addr = ipaddress.ip_address(raw)
        except ValueError:
            continue  # unparseable strings never match, but stay on display
        # Unwrap IPv4-mapped IPv6 (::ffff:198.51.100.7): dual-stack daemons
        # log IPv4 clients in mapped form, which must correlate with the
        # plain IPv4 string another source logs for the same host.  Also
        # ensures the loopback check below sees ::ffff:127.0.0.1 correctly
        # on every CPython version.
        mapped = getattr(addr, "ipv4_mapped", None)
        if mapped is not None:
            addr = mapped
        if addr.is_loopback or addr.is_unspecified:
            continue
        normalised = str(addr)
        if normalised not in ip_keys and len(ip_keys) < CASE_MAX_IPS_PER_MEMBER:
            ip_keys.append(normalised)
    return user_key, ip_keys


def _member_display_fields(
    incident: NormalizedIncident,
) -> tuple[list[str], str | None, str | None]:
    """Extract per-member display metadata from the incident.

    Args:
        incident: The normalized incident being triaged.

    Returns:
        ``(display_ips, rule_name, event_time_iso)`` — all unique raw event
        IPs in first-seen order (unfiltered, for the UI), the first non-empty
        event ``app_display_name`` (the Wazuh rule description), and the
        earliest UTC-aware event timestamp in ISO form (``None`` when the
        incident has no events).
    """
    display_ips: list[str] = []
    rule_name: str | None = None
    earliest: datetime | None = None
    for event in incident.events:
        raw_ip = (event.ip_address or "").strip()
        if (
            raw_ip
            and raw_ip not in display_ips
            and len(display_ips) < CASE_MAX_IPS_PER_MEMBER
        ):
            display_ips.append(raw_ip)
        if rule_name is None and (event.app_display_name or "").strip():
            rule_name = event.app_display_name.strip()
        ts = _ensure_aware(event.timestamp)
        if earliest is None or ts < earliest:
            earliest = ts
    # Normalise to UTC before serialising: stored timestamps are compared
    # lexicographically (COALESCE with ingested_at), which is only correct
    # when every value carries the same +00:00 offset.
    return (
        display_ips,
        rule_name,
        earliest.astimezone(timezone.utc).isoformat() if earliest else None,
    )


def _find_matching_case(
    rows: list[sqlite3.Row], user_key: str | None, ip_keys: list[str]
) -> sqlite3.Row | None:
    """Return the newest-active open case sharing an IP or user key.

    Args:
        rows: Candidate case rows ordered by ``last_activity`` DESC.
        user_key: Correlatable user key, or ``None``.
        ip_keys: Correlation-eligible source IPs.

    Returns:
        The first (newest-active) matching row, or ``None``.  When an alert
        matches two different cases (IP hits one, user hits another) it joins
        the newest — cases are never merged in v1.  Full cases
        (``CASE_MAX_MEMBERS`` reached) never match: the next related alert
        opens a fresh case, bounding the per-ingest recompute.
    """
    ip_set = set(ip_keys)
    for row in rows:
        if row["alert_count"] >= CASE_MAX_MEMBERS:
            continue
        if ip_set & set(json.loads(row["ips"])):
            return row
        if user_key is not None and user_key in json.loads(row["users"]):
            return row
    return None


def _recompute_case(
    conn: sqlite3.Connection, case_id: str
) -> tuple[list[sqlite3.Row], int, str, bool, list[dict[str, Any]], dict[str, Any]]:
    """Recompute score, verdict, and kill-chain from all members of a case.

    Args:
        conn: Open connection (inside the ingest transaction).
        case_id: The case to recompute.

    Returns:
        ``(members, case_score, case_verdict, escalated, rationale,
        kill_chain)`` with members ordered chronologically (event time,
        falling back to ingestion time).
    """
    members = conn.execute(
        "SELECT * FROM case_members WHERE case_id = ? "
        "ORDER BY COALESCE(event_time, ingested_at), id",
        (case_id,),
    ).fetchall()
    member_tactics = [(m["id"], json.loads(m["tactics"])) for m in members]
    kill_chain = detect_kill_chain(member_tactics)
    distinct_tactics = {t for _, tactics in member_tactics for t in tactics}
    scores = [m["risk_score"] for m in members]
    top_member = max(members, key=lambda m: m["risk_score"])
    case_score, case_verdict, escalated, rationale = score_case(
        scores, len(distinct_tactics), kill_chain, top_member["incident_id"]
    )
    return members, case_score, case_verdict, escalated, rationale, kill_chain


def ingest_alert(
    output: dict[str, Any],
    incident: NormalizedIncident,
    db_path: str | Path,
) -> dict[str, Any] | None:
    """Join-or-create a case for a freshly triaged alert.  Never raises.

    Called from the triage routes *after* ``log_verdict`` — the audit trail
    is written before correlation runs and is never affected by it.  The
    member's technique list is taken from the finalized output's
    ``mitre_techniques`` union (signal + native + rule-text), so the case
    sees the same MITRE picture the analyst does.

    Args:
        output: Finalized triage output (post ``_finalize_output``).
        incident: The normalized incident that produced ``output``.
        db_path: Path to the SQLite database file.

    Returns:
        The ``case`` blob to attach to the triage response, or ``None`` when
        the alert has no correlatable keys or the store is unavailable
        (fail-open: correlation must never block a verdict).
    """
    try:
        user_key, ip_keys = extract_correlation_keys(incident)
        if user_key is None and not ip_keys:
            return None

        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        window_cutoff = (now - timedelta(minutes=CASE_WINDOW_MINUTES)).isoformat()
        retention_cutoff = (now - timedelta(days=CASE_RETENTION_DAYS)).isoformat()

        technique_ids = list(output.get("mitre_techniques") or [])[
            :CASE_MAX_TECHNIQUE_IDS
        ]
        tactics: list[str] = []
        for detail in output.get("mitre_details") or []:
            tactic = detail.get("tactic", "")
            if tactic and tactic not in tactics:
                tactics.append(tactic)
        display_ips, rule_name, event_time = _member_display_fields(incident)

        conn = _connect(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            # Opportunistic retention prune (cases are derived data).
            conn.execute(
                "DELETE FROM case_members WHERE case_id IN "
                "(SELECT case_id FROM cases WHERE last_activity < ?)",
                (retention_cutoff,),
            )
            conn.execute(
                "DELETE FROM cases WHERE last_activity < ?", (retention_cutoff,)
            )

            candidates = conn.execute(
                "SELECT * FROM cases WHERE deleted_at IS NULL "
                "AND last_activity >= ? ORDER BY last_activity DESC",
                (window_cutoff,),
            ).fetchall()
            match = _find_matching_case(candidates, user_key, ip_keys)

            if match is None:
                case_users = [user_key] if user_key else []
                case_ips = list(ip_keys)
                # Retry on the (rare) same-day 6-hex ID collision rather than
                # aborting the transaction and silently losing correlation.
                for attempt in range(3):
                    case_id = f"CASE-{now:%Y%m%d}-{secrets.token_hex(3)}"
                    try:
                        conn.execute(
                            "INSERT INTO cases (case_id, created_at, "
                            "last_activity, users, ips) VALUES (?, ?, ?, ?, ?)",
                            (
                                case_id,
                                now_iso,
                                now_iso,
                                json.dumps(case_users),
                                json.dumps(case_ips),
                            ),
                        )
                        break
                    except sqlite3.IntegrityError:
                        if attempt == 2:
                            raise
            else:
                case_id = match["case_id"]
                case_users = json.loads(match["users"])
                case_ips = json.loads(match["ips"])
                if user_key and user_key not in case_users:
                    case_users.append(user_key)
                for ip in ip_keys:
                    if ip not in case_ips and len(case_ips) < CASE_MAX_CASE_IPS:
                        case_ips.append(ip)

            member_fields = (
                output.get("verdict", ""),
                float(output.get("risk_score", 0)),
                incident.user,
                json.dumps(display_ips),
                json.dumps(technique_ids),
                json.dumps(tactics),
                rule_name,
                event_time,
                now_iso,
            )
            # Same incident re-ingested (replayed paste, batch retry after a
            # timeout) refreshes its existing member row instead of inserting
            # a duplicate: duplicate members would inflate the multi-alert
            # bonus and let one alert's tactics fake a cross-alert kill chain.
            existing = conn.execute(
                "SELECT id FROM case_members WHERE case_id = ? AND incident_id = ?",
                (case_id, incident.incident_id),
            ).fetchone()
            if existing:
                conn.execute(
                    "UPDATE case_members SET verdict = ?, risk_score = ?, "
                    "user = ?, ips = ?, technique_ids = ?, tactics = ?, "
                    "rule_name = ?, event_time = ?, ingested_at = ? "
                    "WHERE id = ?",
                    (*member_fields, existing["id"]),
                )
            else:
                conn.execute(
                    "INSERT INTO case_members (case_id, incident_id, verdict, "
                    "risk_score, user, ips, technique_ids, tactics, rule_name, "
                    "event_time, ingested_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (case_id, incident.incident_id, *member_fields),
                )

            members, case_score, case_verdict, escalated, rationale, kill_chain = (
                _recompute_case(conn, case_id)
            )
            conn.execute(
                "UPDATE cases SET last_activity = ?, users = ?, ips = ?, "
                "alert_count = ?, case_score = ?, case_verdict = ?, "
                "escalated = ?, escalation_rationale = ?, kill_chain = ? "
                "WHERE case_id = ?",
                (
                    now_iso,
                    json.dumps(case_users),
                    json.dumps(case_ips),
                    len(members),
                    case_score,
                    case_verdict,
                    int(escalated),
                    json.dumps(rationale),
                    json.dumps(kill_chain),
                    case_id,
                ),
            )
            conn.execute("COMMIT")
        except BaseException:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

        related: list[str] = []
        for member in members:
            mid = member["incident_id"]
            if mid != incident.incident_id and mid not in related:
                related.append(mid)
        return {
            "case_id": case_id,
            "alert_count": len(members),
            "case_score": case_score,
            "case_verdict": case_verdict,
            "escalated": escalated,
            "escalation_rationale": rationale,
            "kill_chain": kill_chain,
            "related_incident_ids": related[:CASE_MAX_RELATED_IDS],
            "correlation_keys": {"user": user_key, "ips": ip_keys},
            "window_minutes": CASE_WINDOW_MINUTES,
        }
    except Exception as exc:
        _log.warning(
            "case correlation failed (%s) — triage unaffected", type(exc).__name__
        )
        return None


def _row_to_summary(row: sqlite3.Row, window_cutoff: str) -> dict[str, Any]:
    """Convert a cases row to the API summary shape.

    Args:
        row: A ``cases`` table row.
        window_cutoff: ISO timestamp; rows with ``last_activity`` at or after
            it are ``open``, otherwise ``closed`` (status is always computed,
            never stored).

    Returns:
        Case summary dict.
    """
    return {
        "case_id": row["case_id"],
        "status": "open" if row["last_activity"] >= window_cutoff else "closed",
        "alert_count": row["alert_count"],
        "case_score": row["case_score"],
        "case_verdict": row["case_verdict"],
        "escalated": bool(row["escalated"]),
        "users": json.loads(row["users"]),
        "ips": json.loads(row["ips"]),
        "kill_chain": json.loads(row["kill_chain"]),
        "created_at": row["created_at"],
        "last_activity": row["last_activity"],
    }


def _window_cutoff_iso() -> str:
    """Return the ISO timestamp separating open from closed cases."""
    return (
        datetime.now(timezone.utc) - timedelta(minutes=CASE_WINDOW_MINUTES)
    ).isoformat()


def list_cases(
    db_path: str | Path, status: str = "all", limit: int = 50
) -> list[dict[str, Any]]:
    """List case summaries, newest activity first.  Fail-closed to ``[]``.

    Args:
        db_path: Path to the SQLite database file.
        status: ``"open"``, ``"closed"``, or ``"all"``.
        limit: Maximum rows returned.

    Returns:
        List of case summary dicts (see :func:`_row_to_summary`).
    """
    try:
        cutoff = _window_cutoff_iso()
        query = "SELECT * FROM cases WHERE deleted_at IS NULL"
        params: list[Any] = []
        if status == "open":
            query += " AND last_activity >= ?"
            params.append(cutoff)
        elif status == "closed":
            query += " AND last_activity < ?"
            params.append(cutoff)
        query += " ORDER BY last_activity DESC LIMIT ?"
        params.append(limit)
        conn = _connect(db_path)
        try:
            rows = conn.execute(query, params).fetchall()
        finally:
            conn.close()
        return [_row_to_summary(row, cutoff) for row in rows]
    except Exception as exc:
        _log.warning("case_store.list_cases failed: %s", type(exc).__name__)
        return []


def get_case(case_id: str, db_path: str | Path) -> dict[str, Any] | None:
    """Return one case with rationale and members, or ``None`` if unknown.

    Fail-closed: any store error returns ``None`` (the route 404s).

    Args:
        case_id: The case identifier (``CASE-YYYYMMDD-xxxxxx``).
        db_path: Path to the SQLite database file.

    Returns:
        Case detail dict (summary + ``escalation_rationale`` + ``members``),
        or ``None`` when the case is unknown or soft-deleted.
    """
    try:
        cutoff = _window_cutoff_iso()
        conn = _connect(db_path)
        try:
            # Deferred read transaction: without it the two SELECTs are
            # independent autocommit statements and a concurrent ingest can
            # commit between them, returning a case row and member list from
            # different snapshots (alert_count != len(members)).
            conn.execute("BEGIN")
            row = conn.execute(
                "SELECT * FROM cases WHERE case_id = ? AND deleted_at IS NULL",
                (case_id,),
            ).fetchone()
            if row is None:
                return None
            members = conn.execute(
                "SELECT * FROM case_members WHERE case_id = ? "
                "ORDER BY COALESCE(event_time, ingested_at), id",
                (case_id,),
            ).fetchall()
            conn.execute("COMMIT")
        finally:
            conn.close()
        detail = _row_to_summary(row, cutoff)
        detail["escalation_rationale"] = json.loads(row["escalation_rationale"])
        detail["members"] = [
            {
                "incident_id": m["incident_id"],
                "verdict": m["verdict"],
                "risk_score": m["risk_score"],
                "user": m["user"],
                "ips": json.loads(m["ips"]),
                "technique_ids": json.loads(m["technique_ids"]),
                "tactics": json.loads(m["tactics"]),
                "rule_name": m["rule_name"],
                "event_time": m["event_time"],
                "ingested_at": m["ingested_at"],
            }
            for m in members
        ]
        return detail
    except Exception as exc:
        _log.warning("case_store.get_case failed: %s", type(exc).__name__)
        return None


def get_cases_by_ids(
    case_ids: list[str], db_path: str | Path
) -> list[dict[str, Any]]:
    """Return summaries for specific cases, preserving input order.

    Used by the batch route to report final per-case counts after all
    elements have been ingested.  Fail-closed to ``[]``.

    Args:
        case_ids: Case identifiers in desired output order.
        db_path: Path to the SQLite database file.

    Returns:
        Case summary dicts for the IDs that exist and are not soft-deleted.
    """
    if not case_ids:
        return []
    try:
        cutoff = _window_cutoff_iso()
        placeholders = ",".join("?" * len(case_ids))
        conn = _connect(db_path)
        try:
            rows = conn.execute(
                f"SELECT * FROM cases WHERE case_id IN ({placeholders}) "
                "AND deleted_at IS NULL",
                case_ids,
            ).fetchall()
        finally:
            conn.close()
        by_id = {row["case_id"]: row for row in rows}
        return [
            _row_to_summary(by_id[cid], cutoff) for cid in case_ids if cid in by_id
        ]
    except Exception as exc:
        _log.warning("case_store.get_cases_by_ids failed: %s", type(exc).__name__)
        return []


def clear_cases(db_path: str | Path) -> bool:
    """Soft-delete all active cases (admin clear).  Never raises.

    Mirrors ``audit_log.clear_verdicts``: rows are stamped ``deleted_at``
    and vanish from all queries; members are left in place (their parent
    case is tombstoned).

    Args:
        db_path: Path to the SQLite database file.

    Returns:
        ``True`` on success, ``False`` on any error.
    """
    try:
        now = datetime.now(timezone.utc).isoformat()
        conn = _connect(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE cases SET deleted_at = ? WHERE deleted_at IS NULL", (now,)
            )
            conn.execute("COMMIT")
        finally:
            conn.close()
        return True
    except Exception as exc:
        _log.warning("case_store.clear_cases failed: %s", type(exc).__name__)
        return False
