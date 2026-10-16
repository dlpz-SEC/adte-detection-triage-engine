"""Rate limits on the authentication surface, with RBAC enforced.

Regression guard for the 2026-09-27 audit findings: POST /api/auth/login had no
limit (30 bad logins, 30 x 401, no 429), GET /api/auth-check had none either,
and every limited route listed @require_role ABOVE @limiter.limit.  flask-limiter
counts a decorated limit only when its own wrapper runs, so a request that
failed authentication returned 401 before the limit saw it, and keys could be
guessed without bound on any route.  The limiter now sits outside the role
check everywhere, and both auth routes carry their own limit.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

import pytest

from adte.store.audit_log import init_db

_KEY_ENVS = (
    "ADTE_API_KEY_ADMIN",
    "ADTE_API_KEY_SENIOR",
    "ADTE_API_KEY_ANALYST",
    "ADTE_API_KEY_READONLY",
    "ADTE_API_KEY_RECRUITER",
)
_BAD = {"X-ADTE-Key": "not-a-real-key"}
_GOOD = {"X-ADTE-Key": "analyst-test-key"}


@pytest.fixture()
def limited_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Flask client with RBAC enforced, one analyst key and the limiter ON.

    The conftest disables the limiter for every test because its in-memory
    counters span the pytest process; this fixture turns it back on and
    resets the counters on both sides so no other test inherits them.
    """
    import adte.server as srv

    db = tmp_path / "rate_limits.db"
    monkeypatch.setattr(srv, "DB_PATH", db)
    init_db(db)
    for env in _KEY_ENVS:
        monkeypatch.delenv(env, raising=False)
    monkeypatch.setenv("ADTE_API_KEY_ANALYST", "analyst-test-key")
    monkeypatch.setitem(srv.app.config, "TESTING", False)
    monkeypatch.setattr(srv.limiter, "enabled", True)
    srv.limiter.reset()
    try:
        with srv.app.test_client() as client:
            yield client
    finally:
        srv.limiter.reset()


def _statuses(send: Callable[[], Any], times: int) -> list[int]:
    """Send the same request ``times`` times and return the status codes."""
    return [send().status_code for _ in range(times)]


class TestLoginLimit:
    """POST /api/auth/login: 10 per minute per IP."""

    def test_bad_logins_hit_429_after_ten(self, limited_client) -> None:
        """Ten wrong keys get 401; the eleventh gets the JSON 429."""
        codes = _statuses(
            lambda: limited_client.post("/api/auth/login", json={"api_key": "wrong"}), 11
        )
        assert codes == [401] * 10 + [429]
        resp = limited_client.post("/api/auth/login", json={"api_key": "wrong"})
        assert resp.status_code == 429
        assert resp.get_json()["error"] == "Rate limit exceeded"

    def test_successful_logins_count_too(self, limited_client) -> None:
        """Valid logins count, so the public recruiter key cannot mint sessions unbounded."""
        codes = _statuses(
            lambda: limited_client.post("/api/auth/login", json={"api_key": "analyst-test-key"}),
            11,
        )
        assert codes == [200] * 10 + [429]


class TestFailedAuthIsCounted:
    """A failed role check must still spend the route's limit."""

    def test_bad_key_triage_hits_429_after_ten(self, limited_client) -> None:
        """POST /api/triage (10/min): ten bad-key 401s, then 429."""
        codes = _statuses(lambda: limited_client.post("/api/triage", json={}, headers=_BAD), 11)
        assert codes == [401] * 10 + [429]

    def test_missing_key_counts_on_a_read_route(self, limited_client) -> None:
        """GET /api/stats/verdicts (10/min) with no credentials at all: 401 x10, then 429."""
        codes = _statuses(lambda: limited_client.get("/api/stats/verdicts"), 11)
        assert codes == [401] * 10 + [429]

    def test_valid_requests_are_counted_once(self, limited_client) -> None:
        """Moving the limiter outward must not double-count: exactly 10 x 200 first."""
        codes = _statuses(lambda: limited_client.get("/api/stats/verdicts", headers=_GOOD), 11)
        assert codes == [200] * 10 + [429]


class TestAuthCheckLimit:
    """GET /api/auth-check: 30 per minute, so it is not an unlimited key oracle."""

    def test_bad_key_auth_check_hits_429_after_thirty(self, limited_client) -> None:
        """Thirty bad-key 401s, then 429."""
        codes = _statuses(lambda: limited_client.get("/api/auth-check", headers=_BAD), 31)
        assert codes == [401] * 30 + [429]


def _layer_kinds(view: Callable[..., Any]) -> list[str]:
    """Return the wrapper layers of a view, outermost first: "limit" or "rbac".

    Layers are identified by code object, not by attributes, because
    functools.wraps copies ``__dict__`` outward and would blur the order.
    """
    import adte.server as srv

    rbac_code = srv.require_role("readonly")(lambda: None).__code__
    kinds: list[str] = []
    fn: Any = view
    while fn is not None:
        code = getattr(fn, "__code__", None)
        if code is rbac_code:
            kinds.append("rbac")
        elif code is not None and "flask_limiter" in code.co_filename.replace("\\", "/"):
            kinds.append("limit")
        fn = getattr(fn, "__wrapped__", None)
    return kinds


class TestDecoratorOrder:
    """Structural pin: covers routes added later, not just the ones probed above."""

    def test_every_role_gated_route_is_limited_outside_the_role_check(self) -> None:
        """Each @require_role route has a limit, and the limit wraps the role check."""
        import adte.server as srv

        gated: dict[str, list[str]] = {}
        for endpoint, view in srv.app.view_functions.items():
            kinds = _layer_kinds(view)
            if "rbac" in kinds:
                gated[endpoint] = kinds
        # The walk must actually find the gated routes, or the check below is vacuous.
        assert {"triage", "auth_check", "config", "delete_cases"} <= set(gated)
        wrong = {
            endpoint: kinds
            for endpoint, kinds in gated.items()
            if "limit" not in kinds or kinds.index("limit") > kinds.index("rbac")
        }
        assert not wrong, f"limit missing or inside require_role: {wrong}"

    def test_login_route_is_limited(self) -> None:
        """POST /api/auth/login has no role check but must carry its own limit."""
        import adte.server as srv

        assert "limit" in _layer_kinds(srv.app.view_functions["auth_login"])
