"""CORS origin trust filtering — reject placeholders and malformed values.

`ADTE_CORS_ORIGINS` feeds both flask-cors and the `_csrf_origin_check` trust
list, so an unfilled template placeholder (e.g. the Railway default
`https://YOUR-APP.up.railway.app`) left in that variable would trust a hostname
the operator does not own. `_is_trusted_cors_origin` drops such values fail-safe;
these tests pin that.
"""

from __future__ import annotations

import pytest

from adte.server import _is_trusted_cors_origin


@pytest.mark.parametrize(
    "origin",
    [
        "https://YOUR-APP.up.railway.app",  # the actual Railway placeholder
        "https://your-app.up.railway.app",  # lowercased form
        "https://your_app.example.net",
        "https://app.example.com",  # reserved documentation domain
        "https://changeme.dev",
        "https://placeholder.io",
        "https://<host>.railway.app",
        "not-a-url",
        "ftp://internal.host",  # non-http scheme
        "https://",  # no host
        "https://real.app/some/path",  # origin must have no path
        "https://real.app?q=1",  # no query
        "https://real.app#frag",  # no fragment
        "",
    ],
)
def test_rejects_placeholders_and_malformed(origin: str) -> None:
    """Placeholders, non-http schemes, hostless and path-bearing values fail."""
    assert _is_trusted_cors_origin(origin) is False


@pytest.mark.parametrize(
    "origin",
    [
        "https://adte-frontend.vercel.app",
        "http://localhost:5173",
        "http://localhost:5000",
        "https://console.acme-security.com",
        "https://app.realcompany.io:8443",
    ],
)
def test_accepts_real_origins(origin: str) -> None:
    """Concrete, well-formed http(s) origins are trusted."""
    assert _is_trusted_cors_origin(origin) is True


def test_filters_placeholder_out_of_a_mixed_list() -> None:
    """A real origin survives while a co-listed placeholder is dropped."""
    candidates = [
        "https://real-frontend.vercel.app",
        "https://YOUR-APP.up.railway.app",
    ]
    kept = [o for o in candidates if _is_trusted_cors_origin(o)]
    assert kept == ["https://real-frontend.vercel.app"]
