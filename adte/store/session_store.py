"""SQLite-backed browser session store for ADTE RBAC.

Replaces the previous in-process ``dict`` session store, which broke under
gunicorn with more than one worker: each worker process held its own private
dict, so a login handled by worker A was invisible to worker B and roughly
half of all authenticated requests failed with "Session expired" even though
the user had just logged in.  Persisting sessions in SQLite (the same file as
the audit log) gives every worker process a single shared source of truth.

Design notes:

- **Tokens are stored hashed** (SHA-256).  A read of the database file never
  yields a usable session token; only the browser holds the raw value.
- **Fail closed** — any SQLite error during lookup denies the session (logged
  as a warning).  Errors during creation propagate so a broken database
  surfaces at login rather than as silent auth flakiness.
- **Self-pruning** — expired rows are deleted opportunistically on every
  lookup and creation, so the table cannot grow unboundedly.
- The table is created lazily on first use (``CREATE TABLE IF NOT EXISTS``),
  mirroring how the tests re-point ``DB_PATH`` at per-test temp files.
- **Sessions are bound to the key that minted them** (2026-10-23, after the
  Railway env-var exposure).  Each row carries ``key_fp``, a fingerprint of
  the API key used at login; the server only honours a session while that
  fingerprint still matches a configured key for the session's role, so
  rotating a key ends its sessions on the next request.  Rows written before
  the column existed have ``key_fp`` NULL and are denied by the server (one
  re-login).  The column is added lazily, like the table.
- Sessions live in the audit database (``ADTE_AUDIT_DB``).  On hosts with an
  ephemeral disk (e.g. Railway without a volume) a redeploy clears active
  sessions — operators simply log in again; the 8-hour TTL is otherwise
  enforced server-side regardless of what the cookie claims.

NIST 800-61 Phase: Detection & Analysis — operator session management for
the analyst-facing triage console.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

_log = logging.getLogger(__name__)

_CREATE_SESSIONS_SQL: str = """
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    role       TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    key_fp     TEXT
)
"""


def _hash_token(token: str) -> str:
    """Return the hex SHA-256 digest of a raw session token.

    Args:
        token: Raw session token (as held by the browser cookie).

    Returns:
        64-character lowercase hex digest used as the storage key.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _connect(db_path: Path) -> sqlite3.Connection:
    """Open a connection and ensure the sessions table exists.

    Args:
        db_path: Path to the SQLite database file.

    Returns:
        An open ``sqlite3.Connection`` with the table guaranteed present.
    """
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.execute(_CREATE_SESSIONS_SQL)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(sessions)")}
    if "key_fp" not in columns:
        # Lazy migration for a database created before sessions were bound
        # to their key.  Existing rows get NULL, which the server denies.
        try:
            conn.execute("ALTER TABLE sessions ADD COLUMN key_fp TEXT")
        except sqlite3.OperationalError as exc:
            # Another thread migrated between the PRAGMA and the ALTER.
            if "duplicate column" not in str(exc).lower():
                raise
    return conn


def _prune_expired(conn: sqlite3.Connection, now_iso: str) -> None:
    """Delete all expired session rows.

    Args:
        conn: Open database connection.
        now_iso: Current UTC time in ISO-8601 (comparison is lexicographic,
            which is correct for fixed-format UTC ISO strings).
    """
    conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now_iso,))


def create_session(role: str, db_path: Path, ttl_hours: int, key_fp: str | None = None) -> str:
    """Create a session and return its raw token.

    Args:
        role: RBAC role to associate with the session.
        db_path: Path to the SQLite database file.
        ttl_hours: Session lifetime in hours (server-side enforced).
        key_fp: Fingerprint of the API key that minted the session (never
            the key itself).  ``None`` stores NULL, which the server's
            binding check denies.

    Returns:
        A 64-character hex session token for the browser cookie.  Only its
        SHA-256 hash is persisted.

    Raises:
        sqlite3.Error: If the database is unavailable — a broken store must
            surface at login, not as intermittent auth failures later.
    """
    token = secrets.token_hex(32)
    now = datetime.now(timezone.utc)
    expires = (now + timedelta(hours=ttl_hours)).isoformat()
    with _connect(db_path) as conn:
        _prune_expired(conn, now.isoformat())
        conn.execute(
            "INSERT INTO sessions (token_hash, role, expires_at, key_fp) VALUES (?, ?, ?, ?)",
            (_hash_token(token), role, expires, key_fp),
        )
    return token


def resolve_session(token: str, db_path: Path) -> str | None:
    """Return the role for a session token, or None if expired/unknown.

    Fail-closed: any database error denies the session.

    Args:
        token: Raw session token from the ``adte_session`` cookie.
        db_path: Path to the SQLite database file.

    Returns:
        Role string, or None if the token is invalid, expired, or the
        store is unreadable.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        with _connect(db_path) as conn:
            _prune_expired(conn, now_iso)
            row = conn.execute(
                "SELECT role FROM sessions WHERE token_hash = ? AND expires_at > ?",
                (_hash_token(token), now_iso),
            ).fetchone()
        return row[0] if row else None
    except sqlite3.Error as exc:
        _log.warning("Session lookup failed (%s) — denying session", type(exc).__name__)
        return None


def resolve_session_binding(token: str, db_path: Path) -> tuple[str, str | None] | None:
    """Return ``(role, key_fp)`` for a live session token, or None.

    Same lookup and fail-closed rules as ``resolve_session``; the caller
    decides whether the stored key fingerprint is still acceptable.

    Args:
        token: Raw session token from the ``adte_session`` cookie.
        db_path: Path to the SQLite database file.

    Returns:
        ``(role, key_fp)`` where ``key_fp`` is None for a row written before
        sessions were bound to keys, or None if the token is invalid,
        expired, or the store is unreadable.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        with _connect(db_path) as conn:
            _prune_expired(conn, now_iso)
            row = conn.execute(
                "SELECT role, key_fp FROM sessions WHERE token_hash = ? AND expires_at > ?",
                (_hash_token(token), now_iso),
            ).fetchone()
        return (row[0], row[1]) if row else None
    except sqlite3.Error as exc:
        _log.warning("Session lookup failed (%s) — denying session", type(exc).__name__)
        return None


def delete_session(token: str, db_path: Path) -> None:
    """Remove a session (logout).  Missing tokens are a silent no-op.

    Args:
        token: Raw session token from the ``adte_session`` cookie.
        db_path: Path to the SQLite database file.
    """
    try:
        with _connect(db_path) as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_hash_token(token),))
    except sqlite3.Error as exc:
        _log.warning("Session delete failed (%s)", type(exc).__name__)
