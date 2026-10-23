"""Tests for binding browser sessions to the API key that minted them.

Regression guard from the 2026-10-21 Railway env-var exposure: sessions used
to store only a role, so rotating ``ADTE_API_KEY_*`` left every session the
old key had opened alive until its 8 h TTL (on a persistent volume).  A
session is now honoured only while the key that minted it is still the
configured key for its role.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from adte.store import session_store
from adte.store.audit_log import init_db

_ANALYST_KEY = "analyst-test-key"
_RECRUITER_KEY = "recruiter-test-key"


@pytest.fixture()
def secured_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Flask client with RBAC ENFORCED, an analyst key and a recruiter alias key."""
    import adte.server as srv

    db = tmp_path / "test_key_binding.db"
    monkeypatch.setattr(srv, "DB_PATH", db)
    init_db(db)
    monkeypatch.setenv("ADTE_API_KEY_ANALYST", _ANALYST_KEY)
    monkeypatch.setenv("ADTE_API_KEY_RECRUITER", _RECRUITER_KEY)
    monkeypatch.setitem(srv.app.config, "TESTING", False)
    with srv.app.test_client() as client:
        yield client


def _login(client, api_key: str) -> None:
    """Log in with *api_key* and assert it succeeded."""
    resp = client.post("/api/auth/login", json={"api_key": api_key})
    assert resp.status_code == 200


class TestRotationEndsSessions:
    """Rotating or removing a key ends the sessions it minted."""

    def test_unchanged_key_keeps_session(self, secured_client) -> None:
        """With no rotation the session keeps authenticating."""
        _login(secured_client, _ANALYST_KEY)
        assert secured_client.get("/api/auth-check").status_code == 200

    def test_rotated_key_ends_session(
        self, secured_client, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A new value for the minting key's env var turns the old session into a 401."""
        _login(secured_client, _ANALYST_KEY)
        monkeypatch.setenv("ADTE_API_KEY_ANALYST", "analyst-rotated-key")
        resp = secured_client.get("/api/auth-check")
        assert resp.status_code == 401
        assert "expired" in resp.get_json()["error"].lower()

    def test_removed_key_ends_session(
        self, secured_client, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Unsetting the minting key ends its session while other keys keep secured mode."""
        _login(secured_client, _ANALYST_KEY)
        monkeypatch.delenv("ADTE_API_KEY_ANALYST")
        assert secured_client.get("/api/auth-check").status_code == 401

    def test_new_key_logs_in_after_rotation(
        self, secured_client, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The rotated key opens a fresh, working session."""
        _login(secured_client, _ANALYST_KEY)
        monkeypatch.setenv("ADTE_API_KEY_ANALYST", "analyst-rotated-key")
        _login(secured_client, "analyst-rotated-key")
        resp = secured_client.get("/api/auth-check")
        assert resp.status_code == 200
        assert resp.get_json()["role"] == "analyst"


class TestAliasBinding:
    """The recruiter alias shares the analyst role but has its own binding."""

    def test_rotating_analyst_key_keeps_recruiter_session(
        self, secured_client, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A session minted by the alias survives rotation of the real analyst key."""
        _login(secured_client, _RECRUITER_KEY)
        monkeypatch.setenv("ADTE_API_KEY_ANALYST", "analyst-rotated-key")
        resp = secured_client.get("/api/auth-check")
        assert resp.status_code == 200
        assert resp.get_json()["role"] == "analyst"

    def test_rotating_recruiter_key_ends_recruiter_session(
        self, secured_client, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Rotating the alias key ends the sessions it minted."""
        _login(secured_client, _RECRUITER_KEY)
        monkeypatch.setenv("ADTE_API_KEY_RECRUITER", "recruiter-rotated-key")
        assert secured_client.get("/api/auth-check").status_code == 401

    def test_same_value_under_other_role_does_not_carry_session(
        self, secured_client, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Moving the old key to a different role's env var does not revive its session."""
        _login(secured_client, _ANALYST_KEY)
        monkeypatch.setenv("ADTE_API_KEY_ANALYST", "analyst-rotated-key")
        monkeypatch.setenv("ADTE_API_KEY_READONLY", _ANALYST_KEY)
        assert secured_client.get("/api/auth-check").status_code == 401


class TestLegacyAndStorage:
    """Rows from before key binding, and what the store keeps."""

    def test_legacy_row_without_fingerprint_is_denied(self, secured_client) -> None:
        """A session row with NULL key_fp (pre-binding) fails closed."""
        import adte.server as srv

        token = session_store.create_session("analyst", srv.DB_PATH, ttl_hours=8)
        secured_client.set_cookie(srv._SESSION_COOKIE, token)
        assert secured_client.get("/api/auth-check").status_code == 401

    def test_store_never_holds_the_raw_key(self, secured_client) -> None:
        """Only a fingerprint of the key reaches the database."""
        import adte.server as srv

        _login(secured_client, _ANALYST_KEY)
        with sqlite3.connect(str(srv.DB_PATH)) as conn:
            rows = conn.execute("SELECT key_fp FROM sessions").fetchall()
        assert len(rows) == 1
        stored = rows[0][0]
        assert stored and _ANALYST_KEY not in stored
        assert stored == srv._key_fingerprint(_ANALYST_KEY)

    def test_old_schema_is_migrated_in_place(self, tmp_path: Path) -> None:
        """A sessions table without key_fp gains the column; old rows read back as None."""
        db = tmp_path / "old_schema.db"
        with sqlite3.connect(str(db)) as conn:
            conn.execute(
                "CREATE TABLE sessions (token_hash TEXT PRIMARY KEY, role TEXT NOT NULL, "
                "expires_at TEXT NOT NULL)"
            )
            conn.execute(
                "INSERT INTO sessions VALUES (?, ?, ?)",
                (session_store._hash_token("a" * 64), "analyst", "9999-01-01T00:00:00+00:00"),
            )
        assert session_store.resolve_session_binding("a" * 64, db) == ("analyst", None)
        token = session_store.create_session("admin", db, ttl_hours=8, key_fp="fp")
        assert session_store.resolve_session_binding(token, db) == ("admin", "fp")

    def test_binding_lookup_fails_closed_on_db_error(self, tmp_path: Path) -> None:
        """An unreadable store denies rather than raising."""
        bad = tmp_path / "missing_dir" / "x.db"
        assert session_store.resolve_session_binding("a" * 64, bad) is None
