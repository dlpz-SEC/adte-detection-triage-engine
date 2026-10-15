"""Hand-parsed JSON bodies reject non-object shapes with a JSON 400.

Regression guard for the 2026-09-27 audit finding: POST /api/auth/login and
POST /api/feedback parse their bodies by hand, and a JSON array such as ``[1]``
(or a bare string or number) reached ``.get()`` and raised AttributeError,
which Flask turned into a generic HTML 500.  RBAC is enforced here
(TESTING=False) so the responses are the ones production sends.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from adte.store.audit_log import init_db

_KEY_ENVS = (
    "ADTE_API_KEY_ADMIN",
    "ADTE_API_KEY_SENIOR",
    "ADTE_API_KEY_ANALYST",
    "ADTE_API_KEY_READONLY",
    "ADTE_API_KEY_RECRUITER",
)
_ANALYST = {"X-ADTE-Key": "analyst-test-key"}
_NON_OBJECT_BODIES: list[Any] = [[1], ["api_key", "analyst-test-key"], "text", 5, True]


@pytest.fixture()
def secured_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Flask client with RBAC enforced, one analyst key, isolated DB and registry."""
    import adte.server as srv

    db = tmp_path / "body_shapes.db"
    monkeypatch.setattr(srv, "DB_PATH", db)
    monkeypatch.setattr(srv, "REGISTRY_PATH", tmp_path / "fp_registry.yaml")
    init_db(db)
    for env in _KEY_ENVS:
        monkeypatch.delenv(env, raising=False)
    monkeypatch.setenv("ADTE_API_KEY_ANALYST", "analyst-test-key")
    monkeypatch.setitem(srv.app.config, "TESTING", False)
    with srv.app.test_client() as client:
        yield client


class TestLoginBody:
    """POST /api/auth/login."""

    @pytest.mark.parametrize("body", _NON_OBJECT_BODIES, ids=repr)
    def test_non_object_body_is_json_400(self, secured_client, body: Any) -> None:
        """An array, string, number or boolean body is a JSON 400, never a 500."""
        resp = secured_client.post("/api/auth/login", json=body)
        assert resp.status_code == 400
        assert resp.is_json
        assert resp.get_json()["error"] == "Request body must be a JSON object"

    def test_object_body_still_logs_in(self, secured_client) -> None:
        """The normal object body is unchanged: a valid key logs in."""
        resp = secured_client.post("/api/auth/login", json={"api_key": "analyst-test-key"})
        assert resp.status_code == 200
        assert resp.get_json()["role"] == "analyst"

    def test_empty_object_still_asks_for_a_key(self, secured_client) -> None:
        """{} keeps its existing 400 'api_key is required'."""
        resp = secured_client.post("/api/auth/login", json={})
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "api_key is required"


class TestFeedbackBody:
    """POST /api/feedback."""

    @pytest.mark.parametrize("body", _NON_OBJECT_BODIES, ids=repr)
    def test_non_object_body_is_json_400(self, secured_client, body: Any) -> None:
        """An array, string, number or boolean body is a JSON 400, never a 500."""
        resp = secured_client.post("/api/feedback", json=body, headers=_ANALYST)
        assert resp.status_code == 400
        assert resp.is_json
        assert resp.get_json()["error"] == "Request body must be a JSON object"

    @pytest.mark.parametrize(
        "body",
        [
            {"incident_id": {"nested": 1}, "label": "tp"},
            {"incident_id": ["INC-1"], "label": "tp"},
            {"incident_id": "INC-1", "label": "fp", "ip": ["198.51.100.7"]},
        ],
        ids=["dict-incident_id", "list-incident_id", "list-ip"],
    )
    def test_non_string_fields_are_400_and_not_stored(self, secured_client, body) -> None:
        """Wrong-typed fields are rejected instead of being written as junk rows."""
        import adte.server as srv
        from adte.store.audit_log import query_feedback

        resp = secured_client.post("/api/feedback", json=body, headers=_ANALYST)
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "incident_id and ip must be strings"
        assert query_feedback(srv.DB_PATH) == []

    def test_valid_feedback_still_recorded(self, secured_client) -> None:
        """A normal TP label from an analyst is unchanged (200)."""
        resp = secured_client.post(
            "/api/feedback", json={"incident_id": "INC-1", "label": "tp"}, headers=_ANALYST
        )
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "ok"
