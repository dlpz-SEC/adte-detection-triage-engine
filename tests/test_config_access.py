"""Who can read GET /api/config, in secured mode and in demo mode.

Guards, not regression tests: both behaviours already held when these were
written (2026-10-15).  They pin a decision taken after the 2026-09-27 audit
noted that /api/config needs senior_analyst in secured mode but is readable
anonymously in demo mode.  That is intended: demo mode is the unconfigured
local mode in which require_role lets every GET through so the UI works
without setup, and the public deployment runs in secured mode (CLAUDE.md:
at least one ADTE_API_KEY_* is required there), where the recruiter key is an
analyst alias and cannot read this route.  What demo mode can show is pinned
too: no RBAC key material exists to show, and threat-intel keys only ever
appear masked.
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


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Flask client with RBAC enforced and every key env var cleared."""
    import adte.server as srv

    db = tmp_path / "config_access.db"
    monkeypatch.setattr(srv, "DB_PATH", db)
    init_db(db)
    for env in _KEY_ENVS:
        monkeypatch.delenv(env, raising=False)
    monkeypatch.setitem(srv.app.config, "TESTING", False)
    with srv.app.test_client() as c:
        yield c


class TestSecuredMode:
    """With keys configured (the hosted demo), only senior_analyst and up read config."""

    @pytest.fixture(autouse=True)
    def _keys(self, client, monkeypatch: pytest.MonkeyPatch) -> None:
        """Set keys AFTER ``client`` has cleared every key env var."""
        monkeypatch.setenv("ADTE_API_KEY_SENIOR", "senior-test-key")
        monkeypatch.setenv("ADTE_API_KEY_ANALYST", "analyst-test-key")
        monkeypatch.setenv("ADTE_API_KEY_RECRUITER", "recruiter-test-key")

    @pytest.mark.parametrize(
        ("headers", "status"),
        [
            ({}, 401),
            ({"X-ADTE-Key": "analyst-test-key"}, 403),
            ({"X-ADTE-Key": "recruiter-test-key"}, 403),
            ({"X-ADTE-Key": "senior-test-key"}, 200),
        ],
        ids=["anonymous", "analyst", "recruiter", "senior"],
    )
    def test_role_gate(self, client, headers: dict[str, str], status: int) -> None:
        """Anonymous 401, analyst and the public recruiter key 403, senior 200."""
        assert client.get("/api/config", headers=headers).status_code == status


class TestDemoMode:
    """With no keys configured, config is readable but holds nothing secret."""

    def test_anonymous_read_shows_no_secret(self, client, monkeypatch) -> None:
        """200, RBAC key fields empty, a configured TI key only masked."""
        vt_key = "a" * 30 + "SECRETMIDDLE" + "b" * 22
        monkeypatch.setenv("ADTE_VT_API_KEY", vt_key)
        resp = client.get("/api/config")
        assert resp.status_code == 200
        body = resp.get_json()
        assert set(body["api_keys"].values()) == {""}
        assert body["intel_keys"]["virustotal"] == vt_key[:4] + "****" + vt_key[-4:]
        assert "SECRETMIDDLE" not in resp.get_data(as_text=True)
