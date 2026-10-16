"""GET /version: proves which commit production runs (deploy-truth check).

/orient compares the live value with origin/main, so the route must report the
commit Railway deployed, stay public in secured mode like /health, and never
echo anything but a well-formed SHA.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import adte.version as version_mod
from adte.store.audit_log import init_db

SHA = "0123456789abcdef0123456789abcdef01234567"

_KEY_ENVS = (
    "ADTE_API_KEY_ADMIN",
    "ADTE_API_KEY_SENIOR",
    "ADTE_API_KEY_ANALYST",
    "ADTE_API_KEY_READONLY",
    "ADTE_API_KEY_RECRUITER",
)


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Flask client on a throwaway audit DB."""
    import adte.server as srv

    db = tmp_path / "version.db"
    monkeypatch.setattr(srv, "DB_PATH", db)
    init_db(db)
    with srv.app.test_client() as c:
        yield c


def test_version_reports_railway_sha(client, monkeypatch):
    monkeypatch.setenv("RAILWAY_GIT_COMMIT_SHA", SHA)
    r = client.get("/version")
    assert r.status_code == 200
    assert r.get_json() == {"commit": SHA, "source": "railway"}


def test_version_falls_back_to_git(client, monkeypatch):
    monkeypatch.delenv("RAILWAY_GIT_COMMIT_SHA", raising=False)
    monkeypatch.setattr(version_mod, "_git_head", lambda: SHA)
    assert client.get("/version").get_json() == {"commit": SHA, "source": "git"}


def test_version_unknown_when_nothing_available(client, monkeypatch):
    monkeypatch.delenv("RAILWAY_GIT_COMMIT_SHA", raising=False)
    monkeypatch.setattr(version_mod, "_git_head", lambda: None)
    assert client.get("/version").get_json() == {
        "commit": "unknown",
        "source": "unknown",
    }


def test_version_ignores_malformed_env_value(client, monkeypatch):
    monkeypatch.setenv("RAILWAY_GIT_COMMIT_SHA", "not a sha; DROP TABLE")
    monkeypatch.setattr(version_mod, "_git_head", lambda: None)
    assert client.get("/version").get_json() == {
        "commit": "unknown",
        "source": "unknown",
    }


def test_version_is_public_in_secured_mode(client, monkeypatch):
    """With RBAC keys set and no credentials sent, /version answers like /health."""
    import adte.server as srv

    for env in _KEY_ENVS:
        monkeypatch.delenv(env, raising=False)
    monkeypatch.setenv("ADTE_API_KEY_ANALYST", "analyst-test-key")
    monkeypatch.setitem(srv.app.config, "TESTING", False)
    monkeypatch.setenv("RAILWAY_GIT_COMMIT_SHA", SHA)
    r = client.get("/version")
    assert r.status_code == 200
    assert set(r.get_json()) == {"commit", "source"}
