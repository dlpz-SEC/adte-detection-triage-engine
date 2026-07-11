"""Regression tests for SQL injection safety in the audit log module.

Verifies that all user-controlled inputs are handled via parameterized
queries (?) and cannot trigger SQL injection.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from adte.store.audit_log import (
    init_db,
    log_feedback,
    log_verdict,
    query_feedback,
    query_verdicts,
)


@pytest.fixture()
def db(tmp_path: Path) -> Path:
    """Create a fresh SQLite database for each test."""
    p = tmp_path / "injection_test.db"
    init_db(p)
    return p


def test_log_verdict_with_sql_payload_does_not_execute(db: Path) -> None:
    """A verdict dict containing SQL metacharacters stores them as data."""
    malicious_output = {
        "incident_id": "'; DROP TABLE verdicts; --",
        "verdict": "high_risk",
        "risk_score": 99.0,
        "confidence": 95,
        "recommended_action": "disable_account",
        "mitre_techniques": ["T1078"],
        "nist_phase": "Containment",
        "source": "test",
        "report": {"timestamp": "2025-01-01T00:00:00Z"},
    }
    log_verdict(malicious_output, db)
    rows = query_verdicts(db)
    assert len(rows) == 1
    assert rows[0]["incident_id"] == "'; DROP TABLE verdicts; --"


def test_log_feedback_with_sql_payload_does_not_execute(db: Path) -> None:
    """Feedback with SQL metacharacters in incident_id stores them as data."""
    log_feedback("'; DROP TABLE feedback; --", "fp", "1.2.3.4", db)
    rows = query_feedback(db)
    assert len(rows) == 1
    assert rows[0]["incident_id"] == "'; DROP TABLE feedback; --"


def test_query_verdicts_filter_with_sql_payload(db: Path) -> None:
    """Verdict filter containing SQL cannot escape the parameterized query."""
    log_verdict(
        {"incident_id": "INC-001", "verdict": "low_risk", "risk_score": 5.0},
        db,
    )
    rows = query_verdicts(db, verdict_filter="' OR '1'='1")
    assert rows == []


def test_query_feedback_filter_with_sql_payload(db: Path) -> None:
    """Feedback label filter containing SQL cannot escape the parameterized query."""
    log_feedback("INC-001", "fp", None, db)
    rows = query_feedback(db, label="' OR '1'='1")
    assert rows == []


# ---------------------------------------------------------------------------
# Request body size limit
# ---------------------------------------------------------------------------


def test_triage_rejects_oversized_body() -> None:
    """POST /api/triage with a body exceeding 1 MB returns HTTP 413."""
    import adte.server as srv

    srv.app.config["TESTING"] = True
    with srv.app.test_client() as client:
        resp = client.post(
            "/api/triage",
            data=b"x" * (1 * 1024 * 1024 + 1),
            content_type="application/json",
        )

    assert resp.status_code == 413
    assert "too large" in resp.get_json()["error"].lower()


# ---------------------------------------------------------------------------
# Health endpoint response shape
# ---------------------------------------------------------------------------


def test_health_does_not_expose_version() -> None:
    """GET /health must return status ok without a version field."""
    import adte.server as srv

    srv.app.config["TESTING"] = True
    with srv.app.test_client() as client:
        resp = client.get("/health")

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["status"] == "ok"
    assert "version" not in body


# ---------------------------------------------------------------------------
# Verdict history — since parameter validation
# ---------------------------------------------------------------------------


def test_verdicts_rejects_invalid_since_timestamp() -> None:
    """GET /api/verdicts with a malformed since value returns HTTP 400."""
    import adte.server as srv

    srv.app.config["TESTING"] = True
    with srv.app.test_client() as client:
        resp = client.get("/api/verdicts?since=not-a-date")

    assert resp.status_code == 400
    assert "ISO 8601" in resp.get_json()["error"]


def test_verdicts_accepts_valid_iso_since_timestamp() -> None:
    """GET /api/verdicts with a well-formed ISO 8601 since value returns HTTP 200."""
    import adte.server as srv

    srv.app.config["TESTING"] = True
    with srv.app.test_client() as client:
        resp = client.get("/api/verdicts?since=2025-01-01T00:00:00Z")

    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Content-Type enforcement on POST endpoints
# ---------------------------------------------------------------------------


def test_triage_rejects_missing_content_type() -> None:
    """POST /api/triage without Content-Type: application/json returns 415."""
    import adte.server as srv

    srv.app.config["TESTING"] = True
    with srv.app.test_client() as client:
        resp = client.post(
            "/api/triage",
            data=b'{"incident_id": "X"}',
            content_type="text/plain",
        )

    assert resp.status_code == 415
    assert "application/json" in resp.get_json()["error"]


def test_feedback_rejects_missing_content_type() -> None:
    """POST /api/feedback without Content-Type: application/json returns 415."""
    import adte.server as srv

    srv.app.config["TESTING"] = True
    with srv.app.test_client() as client:
        resp = client.post(
            "/api/feedback",
            data=b'{"incident_id": "X", "label": "tp"}',
            content_type="text/plain",
        )

    assert resp.status_code == 415
    assert "application/json" in resp.get_json()["error"]


# ---------------------------------------------------------------------------
# CSRF — Origin header enforcement on mutating requests
# ---------------------------------------------------------------------------


def test_csrf_rejects_cross_origin_post() -> None:
    """POST with a foreign Origin header is rejected with 403."""
    import adte.server as srv

    srv.app.config["TESTING"] = True
    with srv.app.test_client() as client:
        resp = client.post(
            "/api/triage",
            data=b"{}",
            content_type="application/json",
            headers={"Origin": "https://evil.example.com"},
        )

    assert resp.status_code == 403
    assert "cross-origin" in resp.get_json()["error"].lower()


def test_csrf_allows_same_origin_post() -> None:
    """POST with a same-origin Origin header reaches the route handler (not CSRF-blocked)."""
    import adte.server as srv

    srv.app.config["TESTING"] = True
    with srv.app.test_client() as client:
        # Same-origin: host_url is http://localhost/ in test client
        resp = client.post(
            "/api/triage",
            data=b"{}",
            content_type="application/json",
            headers={"Origin": "http://localhost"},
        )

    # Route handler returns 400/415 (bad body) not 403 (CSRF) — confirms CSRF check passed.
    assert resp.status_code != 403


def test_csrf_allows_no_origin_header() -> None:
    """POST with no Origin header (CLI/programmatic client) is not blocked by CSRF check."""
    import adte.server as srv

    srv.app.config["TESTING"] = True
    with srv.app.test_client() as client:
        resp = client.post(
            "/api/triage",
            data=b"{}",
            content_type="application/json",
        )

    # No Origin → CSRF check passes; route returns 400/415 for bad body, not 403.
    assert resp.status_code != 403


def test_csrf_allows_https_origin_behind_tls_proxy() -> None:
    """Same-origin HTTPS POST behind a TLS-terminating proxy is NOT CSRF-blocked.

    Render/Railway terminate TLS at the edge and forward plain HTTP, so without
    ProxyFix request.host_url would be ``http://<host>/`` while the browser sends
    ``Origin: https://<host>`` — the scheme mismatch wrongly tripped the 403
    "Cross-origin request rejected" on every same-origin POST (e.g. Quick Load →
    Run Triage).  ProxyFix reads X-Forwarded-Proto/Host so the origins match.
    """
    import adte.server as srv

    srv.app.config["TESTING"] = True
    host = "adte-detection-triage-engine-production.up.railway.app"
    with srv.app.test_client() as client:
        resp = client.post(
            "/api/triage",
            data=b"{}",
            content_type="application/json",
            headers={
                "Origin": f"https://{host}",
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": host,
            },
        )

    # CSRF check passes (host_url rewritten to https://<host>/); bad body → 400/415, not 403.
    assert resp.status_code != 403


def test_csrf_rejects_cross_origin_behind_tls_proxy() -> None:
    """ProxyFix must not open a CSRF hole — a foreign Origin is still rejected behind the proxy."""
    import adte.server as srv

    srv.app.config["TESTING"] = True
    host = "adte-detection-triage-engine-production.up.railway.app"
    with srv.app.test_client() as client:
        resp = client.post(
            "/api/triage",
            data=b"{}",
            content_type="application/json",
            headers={
                "Origin": "https://evil.example.com",
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": host,
            },
        )

    assert resp.status_code == 403
    assert "cross-origin" in resp.get_json()["error"].lower()
