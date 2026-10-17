"""Defensive response headers: every response carries the full set.

`add_security_headers` is the browser-side half of ADTE's hardening (CSP,
framing, referrer, cross-origin isolation, HSTS). Nothing else pins it, so a
dropped or weakened header would ship silently; these tests fail if any header
or CSP directive is removed or loosened.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from adte.store.audit_log import init_db

EXPECTED_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "X-XSS-Protection": "0",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
}

# JSON API, public probes, and a 404: the hook must cover all of them.
PATHS = ["/health", "/version", "/api/examples", "/no-such-path"]


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Flask client on a throwaway audit DB."""
    import adte.server as srv

    db = tmp_path / "headers.db"
    monkeypatch.setattr(srv, "DB_PATH", db)
    init_db(db)
    with srv.app.test_client() as c:
        yield c


def _csp(client) -> dict[str, str]:
    """Parse the CSP on /health into {directive: sources}."""
    raw = client.get("/health").headers["Content-Security-Policy"]
    directives = {}
    for part in raw.split(";"):
        tokens = part.split()
        if tokens:
            directives[tokens[0]] = " ".join(tokens[1:])
    return directives


@pytest.mark.parametrize("path", PATHS)
def test_every_response_carries_the_header_set(client, path):
    headers = client.get(path).headers
    for name, value in EXPECTED_HEADERS.items():
        assert headers.get(name) == value, f"{name} on {path}"
    assert "Content-Security-Policy" in headers, path


@pytest.mark.parametrize(
    ("directive", "sources"),
    [
        ("default-src", "'self'"),
        ("connect-src", "'self'"),
        ("object-src", "'none'"),
        ("base-uri", "'none'"),
        ("form-action", "'self'"),
        ("frame-ancestors", "'none'"),
    ],
)
def test_csp_directive(client, directive, sources):
    assert _csp(client).get(directive) == sources


def test_csp_scripts_allow_no_inline_or_eval(client):
    script_src = _csp(client)["script-src"]
    assert "'unsafe-inline'" not in script_src
    assert "'unsafe-eval'" not in script_src
