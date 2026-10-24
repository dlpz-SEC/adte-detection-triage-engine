"""Tests that template placeholder API keys never authenticate.

Regression guard from the 2026-10-21 Railway env-var exposure (postmortem
F11): ``.env.example`` ships ``changeme-admin-key`` and friends, which are
public in the repo.  A deploy that still carries one must not accept it on
any route to a role: the ``X-ADTE-Key`` header, ``/api/auth/login``, or a
session cookie.  The key still counts as configured, so the app stays locked
rather than falling into demo mode's anonymous GETs.

Also pins postmortem F10: ``/api/config`` reports keys as present or absent
and returns no character of any key.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from adte.store.audit_log import init_db

_KEY_ENVS = (
    "ADTE_API_KEY_ADMIN",
    "ADTE_API_KEY_SENIOR",
    "ADTE_API_KEY_ANALYST",
    "ADTE_API_KEY_READONLY",
    "ADTE_API_KEY_RECRUITER",
)
_PLACEHOLDER_ADMIN = "changeme-admin-key"
_SENIOR_KEY = "senior-test-key"


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Flask client with RBAC enforced and every key env var cleared."""
    import adte.server as srv

    db = tmp_path / "placeholder_keys.db"
    monkeypatch.setattr(srv, "DB_PATH", db)
    init_db(db)
    for env in _KEY_ENVS:
        monkeypatch.delenv(env, raising=False)
    monkeypatch.setitem(srv.app.config, "TESTING", False)
    with srv.app.test_client() as c:
        yield c


class TestPlaceholderNeverAuthenticates:
    """Every route to a role refuses a placeholder key."""

    @pytest.fixture(autouse=True)
    def _keys(self, client, monkeypatch: pytest.MonkeyPatch) -> None:
        """A placeholder admin key next to a real senior key."""
        monkeypatch.setenv("ADTE_API_KEY_ADMIN", _PLACEHOLDER_ADMIN)
        monkeypatch.setenv("ADTE_API_KEY_SENIOR", _SENIOR_KEY)

    def test_header_with_placeholder_is_rejected(self, client) -> None:
        """X-ADTE-Key carrying the template value gets 401."""
        resp = client.get("/api/auth-check", headers={"X-ADTE-Key": _PLACEHOLDER_ADMIN})
        assert resp.status_code == 401

    def test_header_on_protected_route_is_rejected(self, client) -> None:
        """The require_role header path refuses it too."""
        resp = client.get("/api/config", headers={"X-ADTE-Key": _PLACEHOLDER_ADMIN})
        assert resp.status_code == 401

    def test_login_with_placeholder_is_rejected(self, client) -> None:
        """/api/auth/login refuses the template value and sets no session cookie."""
        resp = client.post("/api/auth/login", json={"api_key": _PLACEHOLDER_ADMIN})
        assert resp.status_code == 401
        assert "adte_session" not in resp.headers.get("Set-Cookie", "")

    def test_session_minted_under_placeholder_is_refused(self, client) -> None:
        """A session opened by the placeholder before this fix stops working."""
        import adte.server as srv

        token = srv._create_session("admin", _PLACEHOLDER_ADMIN)
        client.set_cookie("adte_session", token)
        resp = client.get("/api/auth-check")
        assert resp.status_code == 401

    def test_real_key_beside_placeholder_still_works(self, client) -> None:
        """Only the placeholder is refused; the real senior key logs in."""
        resp = client.post("/api/auth/login", json={"api_key": _SENIOR_KEY})
        assert resp.status_code == 200
        check = client.get("/api/auth-check")
        assert check.status_code == 200
        assert check.get_json()["role"] == "senior_analyst"


class TestPlaceholderOnlyStaysLocked:
    """A deploy left entirely on template keys is locked, not in demo mode."""

    def test_anonymous_get_is_401_not_demo(self, client, monkeypatch) -> None:
        """Demo mode would answer 200 to an anonymous GET; locked mode answers 401."""
        monkeypatch.setenv("ADTE_API_KEY_ADMIN", _PLACEHOLDER_ADMIN)
        assert client.get("/api/config").status_code == 401

    def test_recruiter_alias_placeholder_is_refused(self, client, monkeypatch) -> None:
        """The alias key is held to the same rule."""
        monkeypatch.setenv("ADTE_API_KEY_RECRUITER", "changeme-recruiter-key")
        resp = client.post("/api/auth/login", json={"api_key": "changeme-recruiter-key"})
        assert resp.status_code == 401


class TestPlaceholderShape:
    """What counts as a placeholder: template prefixes, any case, nothing else."""

    @pytest.mark.parametrize(
        "value",
        [
            "changeme-admin-key",
            "CHANGEME-admin-key",
            "  changeme  ",
            "your-api-key",
            "Your_Key",
            "replace-me",
            "placeholder-key",
        ],
    )
    def test_template_values_are_placeholders(self, value: str) -> None:
        """Each template shape is detected."""
        import adte.server as srv

        assert srv._is_placeholder_key(value) is True

    @pytest.mark.parametrize(
        "value",
        ["senior-test-key", "x7Kq-changeme-9fA2", "yourself-is-a-word", ""],
    )
    def test_real_values_are_not_placeholders(self, value: str) -> None:
        """A template word inside a real key, or no key at all, is not a placeholder."""
        import adte.server as srv

        assert srv._is_placeholder_key(value) is False

    def test_key_containing_template_word_authenticates(self, client, monkeypatch) -> None:
        """Prefix match only: a real key with 'changeme' mid-string still works."""
        monkeypatch.setenv("ADTE_API_KEY_ANALYST", "x7Kq-changeme-9fA2")
        resp = client.get("/api/auth-check", headers={"X-ADTE-Key": "x7Kq-changeme-9fA2"})
        assert resp.status_code == 200


class TestConfigReportsPresenceOnly:
    """/api/config names refused keys and returns no key material."""

    def test_config_lists_placeholders_by_name_and_leaks_nothing(self, client, monkeypatch) -> None:
        """Booleans for every key, names for placeholders, no value or slice of any key."""
        senior = "SNRA" + "s" * 24 + "SNRZ"
        monkeypatch.setenv("ADTE_API_KEY_ADMIN", _PLACEHOLDER_ADMIN)
        monkeypatch.setenv("ADTE_API_KEY_SENIOR", senior)
        monkeypatch.setenv("ADTE_API_KEY_RECRUITER", "changeme-recruiter-key")
        resp = client.get("/api/config", headers={"X-ADTE-Key": senior})
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["api_keys"] == {
            "admin": False,
            "senior_analyst": True,
            "analyst": False,
            "readonly": False,
        }
        assert body["placeholder_keys"] == ["ADTE_API_KEY_ADMIN", "ADTE_API_KEY_RECRUITER"]
        text = resp.get_data(as_text=True)
        for fragment in ("SNRA", "SNRZ", "changeme", "****"):
            assert fragment not in text
