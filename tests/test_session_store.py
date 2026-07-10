"""Tests for adte/store/session_store.py and the cookie-session auth flow.

Regression guard for the multi-worker session bug: the previous in-process
dict store meant a login handled by one gunicorn worker was invisible to the
other, so authenticated requests randomly failed with "Session expired"
while the Settings view still showed the operator as logged in.  Sessions
now live in SQLite so every worker shares one store.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from adte.store import session_store
from adte.store.audit_log import init_db

# ---------------------------------------------------------------------------
# Store unit tests
# ---------------------------------------------------------------------------


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    """Isolated SQLite file per test."""
    return tmp_path / "sessions_test.db"


class TestSessionStore:
    """create/resolve/delete round-trips against the SQLite store."""

    def test_create_then_resolve_returns_role(self, db_path: Path) -> None:
        """A freshly created token resolves to its role."""
        token = session_store.create_session("analyst", db_path, ttl_hours=8)
        assert session_store.resolve_session(token, db_path) == "analyst"

    def test_unknown_token_resolves_none(self, db_path: Path) -> None:
        """A token that was never issued is denied."""
        session_store.create_session("analyst", db_path, ttl_hours=8)
        assert session_store.resolve_session("f" * 64, db_path) is None

    def test_cross_connection_visibility(self, db_path: Path) -> None:
        """A token created by one 'worker' resolves from another.

        Every store call opens a fresh connection — exactly how two gunicorn
        worker processes share the file. The old dict store failed this by
        construction.
        """
        token = session_store.create_session("admin", db_path, ttl_hours=8)
        # Simulate the second worker: no shared Python state, same DB file.
        for _ in range(5):
            assert session_store.resolve_session(token, db_path) == "admin"

    def test_expired_token_denied_and_pruned(self, db_path: Path) -> None:
        """An expired session is denied and its row removed."""
        token = session_store.create_session("analyst", db_path, ttl_hours=8)
        past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute("UPDATE sessions SET expires_at = ?", (past,))
        assert session_store.resolve_session(token, db_path) is None
        with sqlite3.connect(str(db_path)) as conn:
            count = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        assert count == 0  # self-pruned

    def test_ttl_is_eight_hours(self, db_path: Path) -> None:
        """The stored expiry honours the requested TTL (~8h from now)."""
        session_store.create_session("analyst", db_path, ttl_hours=8)
        with sqlite3.connect(str(db_path)) as conn:
            expires_at = conn.execute("SELECT expires_at FROM sessions").fetchone()[0]
        delta = datetime.fromisoformat(expires_at) - datetime.now(timezone.utc)
        assert timedelta(hours=7, minutes=59) < delta <= timedelta(hours=8)

    def test_delete_session_revokes(self, db_path: Path) -> None:
        """delete_session (logout) makes the token unusable immediately."""
        token = session_store.create_session("analyst", db_path, ttl_hours=8)
        session_store.delete_session(token, db_path)
        assert session_store.resolve_session(token, db_path) is None

    def test_raw_token_never_stored(self, db_path: Path) -> None:
        """Only the SHA-256 hash is persisted — a DB read can't steal sessions."""
        token = session_store.create_session("analyst", db_path, ttl_hours=8)
        with sqlite3.connect(str(db_path)) as conn:
            stored = conn.execute("SELECT token_hash FROM sessions").fetchone()[0]
        assert stored != token

    def test_resolve_fails_closed_on_broken_db(self, tmp_path: Path) -> None:
        """An unreadable store denies the session instead of raising."""
        bad_path = tmp_path / "no_such_dir" / "sessions.db"
        assert session_store.resolve_session("a" * 64, bad_path) is None


# ---------------------------------------------------------------------------
# End-to-end cookie flow through the Flask app (auth enforced)
# ---------------------------------------------------------------------------


@pytest.fixture()
def secured_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Flask client with RBAC ENFORCED (TESTING=False) and one analyst key."""
    import adte.server as srv

    db = tmp_path / "test_session_flow.db"
    monkeypatch.setattr(srv, "DB_PATH", db)
    init_db(db)
    monkeypatch.setenv("ADTE_API_KEY_ANALYST", "analyst-test-key")
    monkeypatch.setitem(srv.app.config, "TESTING", False)
    with srv.app.test_client() as client:
        yield client


class TestCookieSessionFlow:
    """Login → authenticated request → logout, with real RBAC enforcement."""

    def test_login_sets_cookie_and_authenticates(self, secured_client) -> None:
        """A valid key yields a session cookie that authenticates GETs."""
        resp = secured_client.post(
            "/api/auth/login", json={"api_key": "analyst-test-key"}
        )
        assert resp.status_code == 200
        assert resp.get_json()["role"] == "analyst"
        # The test client retains cookies — this exercises the cookie path.
        check = secured_client.get("/api/auth-check")
        assert check.status_code == 200
        assert check.get_json()["role"] == "analyst"

    def test_session_survives_fresh_lookup_every_request(self, secured_client) -> None:
        """Repeated requests all resolve via the shared store (no flakiness)."""
        secured_client.post("/api/auth/login", json={"api_key": "analyst-test-key"})
        for _ in range(10):
            assert secured_client.get("/api/auth-check").status_code == 200

    def test_logout_invalidates_session_server_side(self, secured_client) -> None:
        """After logout the old token is dead even if the cookie is replayed."""
        secured_client.post("/api/auth/login", json={"api_key": "analyst-test-key"})
        import adte.server as srv

        # Capture the raw token before logout deletes the client's cookie jar.
        cookie = secured_client.get_cookie(srv._SESSION_COOKIE)
        assert cookie is not None
        secured_client.post("/api/auth/logout")
        # Replay the captured token — must be rejected by the shared store.
        secured_client.set_cookie(srv._SESSION_COOKIE, cookie.value)
        resp = secured_client.get("/api/auth-check")
        assert resp.status_code == 401
        assert "expired" in resp.get_json()["error"].lower()

    def test_expired_session_is_rejected_with_clear_message(
        self, secured_client, tmp_path: Path
    ) -> None:
        """A session past its 8h TTL gets the 'Session expired' 401."""
        import adte.server as srv

        secured_client.post("/api/auth/login", json={"api_key": "analyst-test-key"})
        past = (datetime.now(timezone.utc) - timedelta(hours=9)).isoformat()
        with sqlite3.connect(str(srv.DB_PATH)) as conn:
            conn.execute("UPDATE sessions SET expires_at = ?", (past,))
        resp = secured_client.get("/api/auth-check")
        assert resp.status_code == 401
        assert "expired" in resp.get_json()["error"].lower()
