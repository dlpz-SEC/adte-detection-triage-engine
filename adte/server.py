"""HTTP server entry point for the ADTE web interface.

Serves the static frontend and exposes triage endpoints.  The
frontend directory is resolved relative to this file so the path
is correct regardless of where the process is launched from.

NIST 800-61 Phase: Detection & Analysis — provides an operator
interface for submitting incidents and reviewing triage results.

Usage::

    python -m adte.server
    # Starts on http://localhost:5000
"""

from __future__ import annotations

import concurrent.futures
import csv
import functools
import hmac
import io
import json
import logging
import threading
import time
from datetime import datetime, timezone

from pathlib import Path
from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=True)  # always finds repo-root .env; override=True forces .env to win over existing shell vars
import os
from typing import Any

from flask import Flask, Response, jsonify, request, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pydantic import ValidationError
from werkzeug.middleware.proxy_fix import ProxyFix

from adte.engine import TriageEngine
from adte.intel.mitre_mapper import get_nist_phase, get_technique_details, get_techniques
from adte.intel.sigma_fp_registry import FPRegistry, add_fp_entry
from adte.models import NormalizedIncident, SentinelIncident
from adte.store import session_store
from adte.store.audit_log import (
    clear_feedback,
    clear_verdicts,
    init_db,
    log_feedback,
    log_verdict,
    query_feedback,
    query_verdicts,
    stats_feedback,
    stats_mitre,
    stats_verdicts,
)
from adte.store.case_store import (
    clear_cases,
    get_case,
    get_cases_by_ids,
    ingest_alert,
    list_cases,
)
from adte.store.user_history import get_user_profile


# ---------------------------------------------------------------------------
# RBAC — API key authentication with role hierarchy
# ---------------------------------------------------------------------------

# Role hierarchy — higher rank inherits all permissions of lower ranks.
#
#   readonly      (0) — read-only access: GET /api/verdicts, /api/feedback,
#                        /api/intel, /api/queue, /api/auth-check
#   analyst       (1) — adds: POST /api/triage, GET /api/cases, POST
#                        /api/feedback (TP/FP labels without IP promotion),
#                        DELETE not permitted
#   senior_analyst(2) — adds: FP registry IP promotion, GET /api/config
#   admin         (3) — adds: DELETE /api/verdicts, DELETE /api/feedback,
#                        DELETE /api/cases, POST /api/auth/login,
#                        POST /api/auth/logout
#
# Set ADTE_API_KEY_<ROLE> env vars to enable each tier (see .env.example).
ROLES: dict[str, int] = {
    "readonly": 0,
    "analyst": 1,
    "senior_analyst": 2,
    "admin": 3,
}

_ROLE_ENV_MAP: dict[str, str] = {
    "admin": "ADTE_API_KEY_ADMIN",
    "senior_analyst": "ADTE_API_KEY_SENIOR",
    "analyst": "ADTE_API_KEY_ANALYST",
    "readonly": "ADTE_API_KEY_READONLY",
}


def _any_keys_configured() -> bool:
    """Return True if at least one RBAC API key is set in the environment.

    Used to distinguish open/demo mode (no keys set) from secured mode
    (at least one key configured).  When False, all RBAC checks are
    bypassed so the web UI works without configuration.

    Returns:
        True if any ADTE_API_KEY_* env var is non-empty.
    """
    return any(os.environ.get(v, "") for v in _ROLE_ENV_MAP.values())


def _resolve_role(api_key: str) -> str | None:
    """Match an API key to its role by checking environment variables.

    Args:
        api_key: The key value from the X-ADTE-Key header.

    Returns:
        The role name if matched, or None if no match found.
    """
    for role, env_var in _ROLE_ENV_MAP.items():
        expected = os.environ.get(env_var, "")
        if expected and hmac.compare_digest(api_key, expected):
            return role
    return None


# ---------------------------------------------------------------------------
# Session store — browser clients exchange their API key for a short-lived
# session token returned as an HttpOnly cookie.  The token never touches JS.
#
# Sessions are persisted in SQLite (adte/store/session_store.py) so that all
# gunicorn worker processes share one store.  The previous in-process dict
# broke with --workers 2: a login handled by one worker was invisible to the
# other, so ~half of authenticated requests randomly failed with
# "Session expired" while /api/auth-check (hitting the right worker) still
# reported the operator as logged in.
# ---------------------------------------------------------------------------

_SESSION_TTL_HOURS: int = 8
_SESSION_COOKIE: str = "adte_session"


def _create_session(role: str) -> str:
    """Create a cryptographically random session token in the shared store.

    Args:
        role: The RBAC role to associate with this session.

    Returns:
        A 64-character hex session token.
    """
    return session_store.create_session(role, DB_PATH, _SESSION_TTL_HOURS)


def _resolve_session(token: str) -> str | None:
    """Return the role for a session token, or None if expired/unknown.

    Expired entries are removed on lookup so the store self-prunes.

    Args:
        token: Session token from the ``adte_session`` cookie.

    Returns:
        Role string, or None if the token is invalid or expired.
    """
    return session_store.resolve_session(token, DB_PATH)


# HTTP methods that are safe to serve in unauthenticated demo mode.
# Destructive methods (DELETE, POST, PUT, PATCH) are always blocked without a key.
_DEMO_SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})


def require_role(minimum_role: str):
    """Decorator that enforces a minimum RBAC role on a Flask route.

    Behaviour depends on configuration:

    - ``app.config["TESTING"] = True`` — bypasses auth entirely (test suite).
    - No ``ADTE_API_KEY_*`` env vars set — open/demo mode: GET/HEAD/OPTIONS
      pass through; DELETE/POST/PUT/PATCH return 403 regardless.
    - At least one key configured — enforces ``X-ADTE-Key`` header check.

    Args:
        minimum_role: Lowest role permitted (e.g. ``"analyst"``).
    """
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            if app.config.get("TESTING"):
                return fn(*args, **kwargs)

            if not _any_keys_configured():
                if request.method in _DEMO_SAFE_METHODS:
                    return fn(*args, **kwargs)
                return jsonify({
                    "error": "Demo mode active — set ADTE_API_KEY_ADMIN to enable write operations."
                }), 403

            # Cookie path: browser clients exchange their key for a session
            # token via /api/auth/login; the token is HttpOnly and never
            # readable by JS.
            session_token = request.cookies.get(_SESSION_COOKIE, "")
            if session_token:
                caller_role = _resolve_session(session_token)
                if caller_role is None:
                    return jsonify({"error": "Session expired — please log in again"}), 401
            else:
                # Header path: CLI / programmatic clients send X-ADTE-Key directly.
                api_key = request.headers.get("X-ADTE-Key", "")
                if not api_key:
                    return jsonify({"error": "Authentication required"}), 401
                caller_role = _resolve_role(api_key)
                if caller_role is None:
                    return jsonify({"error": "Invalid API key"}), 401

            # -1 sentinel: unknown caller role is always denied.
            # 99 sentinel: unknown minimum_role would pass — prevents a
            # misconfigured decorator from accidentally locking everyone out.
            if ROLES.get(caller_role, -1) < ROLES.get(minimum_role, 99):
                return jsonify({"error": "Insufficient permissions"}), 403

            return fn(*args, **kwargs)
        return wrapper
    return decorator


def _caller_role() -> str | None:
    """Return the authenticated role for the current request, or None.

    Used for in-body privilege checks that go beyond the minimum role set
    by the ``require_role`` decorator.  Mirrors the same cookie-first,
    header-fallback resolution order.

    In TESTING mode returns ``"admin"`` so existing unit tests are not
    affected by inline privilege checks.

    Returns:
        Role string (e.g. ``"senior_analyst"``), or None if unauthenticated.
    """
    if app.config.get("TESTING"):
        return "admin"
    if not _any_keys_configured():
        return None
    session_token = request.cookies.get(_SESSION_COOKIE, "")
    if session_token:
        return _resolve_session(session_token)
    api_key = request.headers.get("X-ADTE-Key", "")
    return _resolve_role(api_key) if api_key else None


# Resolved at import time: <repo_root>/frontend/
FRONTEND_DIR: Path = Path(__file__).parent.parent / "frontend"
EXAMPLES_DIR: Path = Path(__file__).parent.parent / "examples"

DB_PATH: Path = Path(os.getenv("ADTE_AUDIT_DB", "adte_audit.db"))
REGISTRY_PATH: Path = Path(os.getenv("ADTE_FP_REGISTRY", str(EXAMPLES_DIR / "fp_registry.yaml")))

_EXAMPLE_FILES: dict[str, str] = {
    "critical":   "incident_account_takeover_tor_exfil.json",
    "high_risk":  "incident_impossible_travel_mfa_fatigue.json",
    "low_risk":   "incident_benign_vpn_travel.json",
    "medium_risk": "incident_needs_human_ambiguous.json",
}

_log = logging.getLogger(__name__)

logging.basicConfig(level=logging.INFO)

# HTTP client libraries emit full request headers (including auth tokens)
# at DEBUG level.  Pin them to WARNING unconditionally so a LOG_LEVEL=DEBUG
# deployment does not accidentally write API keys to the log stream.
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)

if os.environ.get("LOG_LEVEL", "").upper() == "DEBUG":
    _log.warning(
        "LOG_LEVEL=DEBUG is active — debug output may include PII such as "
        "IP addresses and usernames. Do not enable in production."
    )

# Log only a count of configured intel sources, not which ones.
# Per-key presence/absence is available to operators via GET /api/config
# (masked) and must not appear in application logs where it would reveal
# intel coverage gaps to anyone with log access.
_intel_key_count = sum(
    1 for k in ("ADTE_ABUSEIPDB_KEY", "ADTE_VT_API_KEY", "ADTE_OTX_KEY")
    if os.environ.get(k)
)
_log.info("ADTE startup — %d/3 threat intel sources configured", _intel_key_count)

if not _any_keys_configured():
    _log.warning("ADTE running in DEMO MODE — write endpoints are disabled.")

app = Flask(__name__)

# --- Trust the single TLS-terminating reverse proxy (Render / Railway) ---
# These PaaS terminate HTTPS at their edge and forward plain HTTP to gunicorn,
# so without this the WSGI environ reports scheme=http and request.host_url is
# "http://<host>/".  The browser, however, sends Origin: "https://<host>".  The
# exact-string compare in _csrf_origin_check would then see a scheme mismatch
# and reject every same-origin POST (e.g. /api/triage from the Quick Load
# tiles) with 403 "Cross-origin request rejected".  ProxyFix rewrites scheme,
# host, and client IP from the X-Forwarded-* headers set by that one proxy, so
# request.host_url becomes "https://<host>/" (== Origin) and the same-origin
# check passes — no ADTE_CORS_ORIGINS entry required.  It also restores the
# real client IP for rate limiting and the access log.  Locally (no proxy) the
# X-Forwarded-* headers are absent, so this is a no-op.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# Reject request bodies larger than 1 MB before they are parsed.
# Flask enforces this at the WSGI stream level, so get_json(force=True)
# cannot read past the limit even when Content-Type is absent.
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1 MB

# --- CORS: deny all cross-origin requests unless ADTE_CORS_ORIGINS is set ---
# Default is intentionally empty (deny-all).  The self-hosted frontend is served
# from the same origin as the API (localhost:5000), so CORS is not needed for
# normal use.  Set ADTE_CORS_ORIGINS to a comma-separated list of allowed origins
# only when the frontend is hosted on a different origin.
_raw_cors: str = os.environ.get("ADTE_CORS_ORIGINS", "").strip()
_CORS_ORIGINS: list[str] = [o.strip() for o in _raw_cors.split(",") if o.strip()]
if not _CORS_ORIGINS:
    _log.info(
        "ADTE_CORS_ORIGINS is not set — all cross-origin requests are denied. "
        "Set ADTE_CORS_ORIGINS=<origin> to permit specific external origins."
    )
CORS(app, origins=_CORS_ORIGINS)

# --- Rate limiting ---
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)

init_db(DB_PATH)


@app.after_request
def add_security_headers(response: Any) -> Any:
    """Inject defensive HTTP headers on every response.

    The frontend is an esbuild-compiled bundle served from 'self', so the
    script-src CSP needs no 'unsafe-inline'/'unsafe-eval'. Scripts are limited
    to 'self' plus the cdnjs allowlist (Chart.js); styles/fonts to 'self' and
    the Google Fonts hosts. All other sources default to 'self'.
    """
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "connect-src 'self';"
    )
    # Send HSTS unconditionally so it reaches browsers even when Flask sits
    # behind a TLS-terminating reverse proxy (where request.is_secure is False).
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.after_request
def _log_api_access(response: Any) -> Any:
    """Emit one INFO line per API request for the access audit trail.

    NIST 800-61 non-repudiation: records who/what/when for every API call.
    Only /api/ paths are logged; static asset requests are excluded.
    Request bodies are never logged.

    Args:
        response: The outgoing Flask response object (passed through unchanged).

    Returns:
        The unmodified response.
    """
    if request.path.startswith("/api/"):
        role = _caller_role() or "anonymous"
        _log.info(
            "API ip=%s role=%s %s %s → %d",
            request.remote_addr, role, request.method, request.path, response.status_code,
        )
    return response


# Methods that cannot mutate server state — exempt from the CSRF Origin check.
_CSRF_SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})


@app.before_request
def _csrf_origin_check() -> Any:
    """Reject cross-origin state-mutating API requests (CSRF defence-in-depth).

    SameSite=Strict on the session cookie is the primary CSRF mitigation; this
    Origin-header check covers clients or browsers that do not enforce SameSite.
    Requests with no Origin header (CLI clients, Postman, server-to-server calls)
    are passed through — require_role enforces auth on them regardless.

    Returns:
        A 403 JSON response for cross-origin mutating requests, or None to
        allow the request to continue to the route handler.
    """
    if request.method in _CSRF_SAFE_METHODS or not request.path.startswith("/api/"):
        return None
    origin: str | None = request.headers.get("Origin")
    if origin is None:
        return None  # No Origin → not a browser cross-site request.
    # Allow same-origin requests and any explicitly configured CORS origin.
    own_origin = request.host_url.rstrip("/")
    if origin != own_origin and origin not in _CORS_ORIGINS:
        _log.warning("CSRF: rejected cross-origin request from %r to %s", origin, request.path)
        return jsonify({"error": "Cross-origin request rejected"}), 403
    return None


# ---------------------------------------------------------------------------
# Queue triage cache — keyed by incident_id, TTL 300 s.
# Eliminates redundant enrich/score/decide calls for alerts already seen in
# the current session.  TTL ensures FP registry updates propagate within 5 min.
# ---------------------------------------------------------------------------
_QUEUE_CACHE_TTL: float = 300.0
_queue_cache: dict[str, dict[str, Any]] = {}   # incident_id → {"row": ..., "ts": float}
_queue_cache_lock = threading.Lock()


@app.errorhandler(413)
def _request_too_large(e: Any) -> Any:
    """Return a JSON 413 response when the request body exceeds MAX_CONTENT_LENGTH."""
    return jsonify({"error": "Request body too large — maximum 1 MB"}), 413


@app.errorhandler(429)
def _rate_limit_exceeded(e: Any) -> Any:
    """Return a JSON 429 response when rate limit is exceeded."""
    return jsonify({"error": "Rate limit exceeded", "retry_after": e.description}), 429


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.route("/")
def index() -> Any:
    """Serve the frontend SPA.

    Returns:
        The ``index.html`` file from the frontend directory.
    """
    return send_from_directory(str(FRONTEND_DIR), "index.html")


@app.route("/<path:filename>")
def frontend_static(filename: str) -> Any:
    """Serve static frontend assets (JS, CSS, images) from the frontend directory.

    Args:
        filename: Relative path of the requested file within the frontend directory.

    Returns:
        The requested file, or 404 if it does not exist.
    """
    return send_from_directory(str(FRONTEND_DIR), filename)


@app.route("/health")
def health() -> Any:
    """Simple liveness probe.

    Returns:
        JSON ``{"status": "ok"}``.
    """
    return jsonify({"status": "ok"})


@app.route("/api/examples")
def examples() -> Any:
    """Return all four example incidents as NormalizedIncident JSON.

    The source files are in ``SentinelIncident`` format (they have
    ``alerts``, ``title``, ``raw_payload`` etc.).  This endpoint
    converts each one via ``NormalizedIncident.from_sentinel()`` so
    the frontend can load them directly into the triage POST body
    without any client-side transformation.

    Returns:
        JSON object keyed by ``critical``, ``high_risk``, ``low_risk``,
        ``medium_risk`` — each value is a ``NormalizedIncident`` dict.
    """
    result: dict[str, Any] = {}
    for key, filename in _EXAMPLE_FILES.items():
        raw = json.loads((EXAMPLES_DIR / filename).read_text(encoding="utf-8"))
        sentinel = SentinelIncident(**raw)
        normalized = NormalizedIncident.from_sentinel(sentinel)
        result[key] = normalized.model_dump(mode="json")
    return jsonify(result)


class _BatchPayloadError(ValueError):
    """Raised when a posted document wraps multiple alerts.

    ``/api/triage`` scores one incident per request — a batch document
    (``{"alerts": [...]}``, an OpenSearch search response, or a bare JSON
    array with more than one element) cannot be triaged in a single call.
    Carries the alert count so the route can say exactly what it saw.
    """

    def __init__(self, count: int) -> None:
        super().__init__(f"batch payload with {count} alerts")
        self.count = count


def _coerce_to_incident(payload: Any) -> NormalizedIncident:
    """Coerce a posted alert into a ``NormalizedIncident``, source-format aware.

    ADTE's canonical triage input is the ``NormalizedIncident`` schema (what
    ``/api/examples`` emits and Quick Load posts).  Analysts, however, routinely
    paste raw Wazuh / OpenSearch alert JSON — the most common SIEM alert-export
    shape.  This helper accepts any documented ADTE source format, so the
    triage box is not limited to the internal schema:

    1. **Batch wrappers** — ``{"alerts": [...]}`` test-suite documents, a full
       OpenSearch ``_search`` response (``{"hits": {"hits": [...]}}``), or a
       bare JSON array.  A wrapper holding exactly ONE alert is unwrapped and
       coerced (iteratively, bounded to 4 levels — deeper nesting is rejected);
       more than one raises ``_BatchPayloadError`` (the route turns it into a
       422 explaining that triage is one alert per request).
       A dict with ``alerts`` plus ``incident_id``/``title`` is NOT a batch —
       that is the raw Sentinel incident shape (see 4).
    2. **OpenSearch hit envelope** — a document with a ``_source`` object
       (typically wrapped with ``_index``/``_id``/``_score``), exactly as a
       ``wazuh-alerts-4.x-*`` search hit looks.  The ``_source`` body is
       unwrapped, the ``_id`` is carried in as the incident id, and the Wazuh
       adapter normalises it.
    3. **Bare Wazuh ``_source`` document** — a top-level ``rule`` object with no
       ADTE ``events`` array (the ``_source`` body on its own).  Normalised via
       the Wazuh adapter.
    4. **Raw Sentinel incident** — the ``SentinelIncident`` shape the bundled
       ``examples/*.json`` files use (``title`` plus ``alerts``/``raw_payload``,
       and NO top-level ``user`` — canonical payloads always carry ``user``);
       converted via ``NormalizedIncident.from_sentinel``.  Any ``severity`` in
       the raw source JSON is ignored, per the documented Sentinel contract.
    5. **NormalizedIncident** — anything else is validated against the canonical
       schema unchanged (this also preserves the top-level ``severity``
       rejection).

    The Wazuh path reuses ``WazuhAdapter.normalize_alert`` — a pure, network-free
    static transform — so no live Indexer connection is made.

    Args:
        payload: The parsed JSON request body (a dict or a list).

    Returns:
        A ``NormalizedIncident`` ready for the triage pipeline.

    Raises:
        _BatchPayloadError: If the payload wraps more than one alert.
        pydantic.ValidationError: If the payload matches none of the accepted
            shapes (surfaces as HTTP 422 at the route).
        ValueError, KeyError, TypeError: If a source-shaped payload is malformed
            (e.g. a non-ISO timestamp) — the route maps these to HTTP 422 too.
    """
    # Deferred import — mirrors /api/queue; keeps server startup light.
    from adte.adapters.wazuh import WazuhAdapter

    def _wrapper_items(p: Any) -> list[Any] | None:
        """Return the wrapped alert list when ``p`` is a batch wrapper, else None."""
        if isinstance(p, list):
            return p
        if isinstance(p, dict):
            wrapped = p.get("alerts")
            if isinstance(wrapped, list) and not (
                "incident_id" in p and "title" in p
            ):
                return wrapped
            hits = p.get("hits")
            if isinstance(hits, dict) and isinstance(hits.get("hits"), list):
                return hits["hits"]
        return None

    # (1) Batch wrappers: {"alerts": [...]}, a full _search response, or a
    # bare array. A single wrapped alert is unwrapped; multiple are rejected.
    # Unwrapping is iterative with a small depth bound — a maliciously deep
    # {"alerts":[{"alerts":[...]}]} nest must 422, not blow the stack.
    for _ in range(4):
        items = _wrapper_items(payload)
        if items is None:
            break
        if len(items) != 1:
            raise _BatchPayloadError(len(items))
        if not isinstance(items[0], (dict, list)):
            raise ValueError("wrapped alert element is not a JSON object")
        payload = items[0]
    else:
        raise ValueError("alert wrapper nesting too deep")

    if not isinstance(payload, dict):
        raise ValueError("payload is not a JSON object")

    # (2) OpenSearch hit envelope: {"_source": {...}, "_id": "..."}.
    source = payload.get("_source")
    if isinstance(source, dict):
        doc = dict(source)
        doc.setdefault("id", payload.get("_id", ""))
        return WazuhAdapter.normalize_alert(doc)

    # (3) Bare Wazuh _source document: a "rule" object, not ADTE "events".
    if isinstance(payload.get("rule"), dict) and "events" not in payload:
        return WazuhAdapter.normalize_alert(payload)

    # (4) Raw Sentinel incident (the examples/*.json shape): convert via
    # from_sentinel, exactly like /api/examples does. Detection is deliberately
    # strict — a canonical NormalizedIncident always carries a required `user`
    # (which SentinelIncident lacks), so anything with `user` stays canonical.
    if (
        "title" in payload
        and "user" not in payload
        and "events" not in payload
        and ("alerts" in payload or "raw_payload" in payload)
    ):
        return NormalizedIncident.from_sentinel(SentinelIncident.model_validate(payload))

    # (5) Canonical NormalizedIncident schema (what /api/examples emits).
    return NormalizedIncident.model_validate(payload)


def _finalize_output(output: dict[str, Any], incident: NormalizedIncident) -> dict[str, Any]:
    """Attach the MITRE technique union, technique details, and NIST phase.

    Shared by the single-alert and batch triage routes so both produce an
    identical output contract.  Union order is preserved: signal-derived IDs
    first, then native event ``technique_ids`` (e.g. Wazuh ``rule.mitre.id``),
    then IDs surfaced by the advisory rule-text enrichment.

    Args:
        output: The engine's ``to_output()`` dict; mutated in place.
        incident: The triaged incident (source of native technique IDs).

    Returns:
        The same ``output`` dict with ``mitre_techniques``, ``mitre_details``,
        and ``nist_phase`` populated.
    """
    fired = [r["signal"] for r in output.get("rationale", []) if r.get("score", 0) > 0]
    techniques = get_techniques(fired)
    sources: dict[str, str] = {tid: "signal" for tid in techniques}
    # Union in native ATT&CK IDs carried on the events (e.g. Wazuh
    # rule.mitre.id) — signal-derived IDs keep their existing order first.
    for event in incident.events:
        for tid in event.technique_ids:
            if tid and tid not in sources:
                sources[tid] = "native"
                techniques.append(tid)
    # Then any technique the advisory rule-text enrichment surfaced.
    enrichment = output.get("llm_enrichment")
    if isinstance(enrichment, dict) and enrichment.get("source") == "deterministic_mapping":
        for tid in enrichment.get("technique_ids", []):
            if tid and tid not in sources:
                sources[tid] = "rule_text"
                techniques.append(tid)
    output["mitre_techniques"] = techniques
    output["mitre_details"] = get_technique_details(techniques, sources)
    output["nist_phase"] = get_nist_phase(output["verdict"])
    return output


@app.route("/api/triage", methods=["POST"])
@require_role("analyst")
@limiter.limit("10/minute")
def triage() -> Any:
    """Run the ADTE triage pipeline on a posted incident.

    Accepts ADTE's canonical ``NormalizedIncident`` schema, a raw Wazuh /
    OpenSearch alert (auto-normalised via ``WazuhAdapter``), or a raw Sentinel
    incident; the body shape is auto-detected by ``_coerce_to_incident``.
    Batch wrappers holding exactly one alert are unwrapped; multi-alert
    batches are rejected with an explanatory 422 (one alert per request).

    NIST 800-61 Phase: Detection & Analysis — enrichment, scoring,
    and decision are all performed inside ``TriageEngine``.

    Query Parameters:
        use_llm: When ``"true"`` and ``ANTHROPIC_API_KEY`` is set, Claude
            generates the narrative summary.  Defaults to ``"false"``
            (deterministic template).  LLM output is advisory only —
            it cannot affect verdict, risk_score, or recommended_action.

    Returns:
        The full ``TriageEngine.to_output()`` dict on success (200).
        ``{"error": "<message>"}`` on bad JSON (400), schema failure
        (422), or unexpected error (500).
    """
    use_llm: bool = request.args.get("use_llm", "false").lower() == "true"

    # --- Parse request body ---
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415
    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({"error": "Request body must be valid JSON"}), 400

    # --- Validate / normalise the body ---
    # Accept ADTE's canonical NormalizedIncident schema, a raw Wazuh /
    # OpenSearch alert, or a raw Sentinel incident (auto-normalised).
    # See _coerce_to_incident for the shape-detection rules.
    if not isinstance(payload, (dict, list)):
        return jsonify({"error": "Request body must be a JSON object"}), 422
    try:
        incident = _coerce_to_incident(payload)
    except _BatchPayloadError as exc:
        return jsonify({
            "error": (
                f"Batch payload detected ({exc.count} alerts) — /api/triage "
                "triages one alert at a time. POST the batch to "
                f"/api/triage/batch (max {_BATCH_MAX_ALERTS} alerts), or a "
                "single alert object here."
            )
        }), 422
    except ValidationError:
        return jsonify({
            "error": (
                "Invalid incident schema — check required fields. Accepted formats: "
                "a NormalizedIncident object, a raw Wazuh/OpenSearch alert "
                "(a `rule` object, or an OpenSearch `_source` envelope), or a "
                "raw Sentinel incident."
            )
        }), 422
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        # AttributeError included: adapter/from_sentinel field access on
        # wrong-typed sub-documents (e.g. a string where a dict is expected)
        # must surface as a clean 422, never a 500.
        return jsonify({
            "error": (
                "Alert could not be normalised — malformed source alert "
                f"payload ({type(exc).__name__})."
            )
        }), 422

    # --- Run triage pipeline (30 s hard timeout) ---
    _TRIAGE_TIMEOUT_SECS = 30
    try:
        user_profile = get_user_profile(incident.user)
        fp_registry = FPRegistry.load()
        engine = TriageEngine(incident, user_profile, fp_registry)

        def _run() -> dict[str, Any]:
            # llm_enrich() populates the advisory llm_enrichment field only —
            # it runs after decide(), so it cannot influence the verdict.
            return engine.enrich().score().decide().llm_enrich().to_output(use_llm=use_llm)

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as _pool:
            _future = _pool.submit(_run)
            try:
                output = _future.result(timeout=_TRIAGE_TIMEOUT_SECS)
            except concurrent.futures.TimeoutError:
                return jsonify({"error": f"Triage timed out after {_TRIAGE_TIMEOUT_SECS} s"}), 504
    except Exception as exc:
        _log.error("Triage pipeline failed for incident %s (%s)", incident.incident_id, type(exc).__name__)
        return jsonify({"error": "Triage pipeline error — check server logs"}), 500

    output = _finalize_output(output, incident)
    log_verdict(output, DB_PATH)
    # Case correlation runs after the audit write and is fail-open: a broken
    # case store yields "case": null, never a failed triage.
    output["case"] = ingest_alert(output, incident, DB_PATH)
    return jsonify(output), 200


# ---------------------------------------------------------------------------
# Batch triage — accept a whole OpenSearch export (array / wrapper of alerts)
# ---------------------------------------------------------------------------

# Cap chosen against gunicorn's 60 s worker timeout: the TI TTL cache makes
# repeated/private IPs near-free, but each cold public IP costs live HTTP.
_BATCH_MAX_ALERTS: int = 25
_BATCH_DEADLINE_SECS: int = 45


def _extract_batch_items(payload: Any) -> list[Any]:
    """Return the alert elements of a batch payload (one wrapper level).

    Accepts a bare JSON array, ``{"alerts": [...]}`` (unless the dict also
    carries ``incident_id`` + ``title`` — that is a raw Sentinel incident,
    returned whole), or a full OpenSearch ``_search`` response
    (``{"hits": {"hits": [...]}}``).  Anything else is treated as a single
    alert and returned as a one-element list.  Each element is subsequently
    normalised by ``_coerce_to_incident``, which handles every single-alert
    shape — so this helper only peels the outermost wrapper.

    Args:
        payload: The parsed JSON request body (dict or list).

    Returns:
        List of alert elements to triage, in input order.
    """
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        wrapped = payload.get("alerts")
        if isinstance(wrapped, list) and not (
            "incident_id" in payload and "title" in payload
        ):
            return wrapped
        hits = payload.get("hits")
        if isinstance(hits, dict) and isinstance(hits.get("hits"), list):
            return hits["hits"]
    return [payload]


@app.route("/api/triage/batch", methods=["POST"])
@require_role("analyst")
@limiter.limit("5/minute")
def triage_batch() -> Any:
    """Triage every alert in a posted batch with per-alert error isolation.

    Accepts the shapes an analyst naturally pastes from an OpenSearch /
    Wazuh indexer export: a bare JSON array of hits, ``{"alerts": [...]}``,
    or a full ``_search`` response.  Each element goes through the same
    shape auto-detection as ``/api/triage`` (``_coerce_to_incident``), is
    scored by the engine, MITRE-finalised, and audit-logged.

    A malformed element yields an ``{"index", "ok": false, "error"}`` entry
    while the remaining alerts still triage; the response is HTTP 200 with
    per-item ``ok`` carrying the truth.  Alerts run sequentially under a
    ``_BATCH_DEADLINE_SECS`` budget — elements not started before the
    deadline are skipped with an explanatory error entry rather than
    risking the gunicorn worker timeout.

    The LLM narrative is deliberately skipped for batches (the ``use_llm``
    query parameter is ignored): N sequential Claude calls would blow the
    deadline.  ``llm_enrich()`` still runs — it is the network-free
    rule-text MITRE mapping, keeping batch entries at full MITRE parity
    with single-alert triage.

    NIST 800-61 Phase: Detection & Analysis — bulk enrichment, scoring,
    and decision over an exported alert set.

    Returns:
        ``{"count", "succeeded", "failed", "results": [...]}`` (200) with
        ``results`` in input order (``results[k]["index"] == k``; success
        entries are the full single-triage output dict).  ``{"error"}`` on
        non-JSON (415), bad JSON (400), empty/oversize batch (422), or a
        blown overall deadline (504).
    """
    # --- Parse request body (mirrors /api/triage) ---
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415
    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({"error": "Request body must be valid JSON"}), 400
    if not isinstance(payload, (dict, list)):
        return jsonify({"error": "Request body must be a JSON object or array"}), 422

    items = _extract_batch_items(payload)
    if not items:
        return jsonify({"error": "Batch contains no alerts."}), 422
    if len(items) > _BATCH_MAX_ALERTS:
        return jsonify({
            "error": (
                f"Batch too large ({len(items)} alerts, max {_BATCH_MAX_ALERTS}) — "
                "split the export or narrow the OpenSearch query."
            )
        }), 422

    def _run_batch() -> list[dict[str, Any]]:
        """Sequentially triage every element, isolating per-alert failures."""
        results: list[dict[str, Any]] = []
        deadline = time.monotonic() + _BATCH_DEADLINE_SECS
        fp_registry = FPRegistry.load()
        for i, item in enumerate(items):
            if time.monotonic() > deadline:
                results.append({
                    "index": i, "ok": False,
                    "error": "Skipped — batch deadline reached",
                })
                continue
            try:
                incident = _coerce_to_incident(item)
            except _BatchPayloadError as exc:
                results.append({
                    "index": i, "ok": False,
                    "error": f"Element is itself a batch of {exc.count} alerts",
                })
                continue
            except ValidationError:
                results.append({
                    "index": i, "ok": False,
                    "error": "Invalid incident schema — check required fields.",
                })
                continue
            except (ValueError, KeyError, TypeError, AttributeError) as exc:
                results.append({
                    "index": i, "ok": False,
                    "error": (
                        "Alert could not be normalised — malformed source "
                        f"alert payload ({type(exc).__name__})."
                    ),
                })
                continue
            try:
                user_profile = get_user_profile(incident.user)
                engine = TriageEngine(incident, user_profile, fp_registry)
                output = (
                    engine.enrich().score().decide().llm_enrich().to_output(use_llm=False)
                )
            except Exception as exc:
                _log.error(
                    "Batch triage failed for element %d (%s)", i, type(exc).__name__
                )
                results.append({
                    "index": i, "ok": False, "error": "Triage pipeline error",
                })
                continue
            output = _finalize_output(output, incident)
            log_verdict(output, DB_PATH)
            output["case"] = ingest_alert(output, incident, DB_PATH)
            results.append({"index": i, "ok": True, **output})
        return results

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as _pool:
        _future = _pool.submit(_run_batch)
        try:
            results = _future.result(timeout=_BATCH_DEADLINE_SECS + 10)
        except concurrent.futures.TimeoutError:
            return jsonify(
                {"error": f"Batch triage timed out after {_BATCH_DEADLINE_SECS} s"}
            ), 504

    succeeded = sum(1 for r in results if r.get("ok"))
    # Batch-level case summary: per-element "case" blobs show the case as of
    # that element's ingest; re-reading here reports the FINAL counts once
    # every element has landed.
    case_indices: dict[str, list[int]] = {}
    for r in results:
        if r.get("ok") and r.get("case"):
            case_indices.setdefault(r["case"]["case_id"], []).append(r["index"])
    case_summaries = get_cases_by_ids(list(case_indices), DB_PATH)
    for summary in case_summaries:
        summary["member_indices"] = case_indices[summary["case_id"]]
    return jsonify({
        "count": len(items),
        "succeeded": succeeded,
        "failed": len(results) - succeeded,
        "results": results,
        "cases": case_summaries,
    }), 200


# NOTE: /api/queue re-triages the same incidents on every poll (5-min cache),
# so it is deliberately NOT wired into case correlation — ingesting here would
# multiply case membership on every queue refresh.  Only /api/triage and
# /api/triage/batch ingest into the case store.
@app.route("/api/queue")
@require_role("analyst")
@limiter.limit("20/minute")
def queue() -> Any:
    """Return a triage-scored summary of recent alerts for the queue view.

    Accepts optional query parameters to control the Wazuh fetch window.
    Attempts to pull live alerts from the Wazuh adapter.  Falls back
    silently to the three bundled example incidents when the adapter is
    unavailable (no Wazuh credentials, adapter offline, etc.).

    Each row includes the full ``incident_json`` field so the frontend
    can pre-populate the triage input on row click without a second
    round-trip.

    NIST 800-61 Phase: Detection & Analysis — surfaces a ranked alert
    queue for analyst review.

    Query Parameters:
        hours: Look-back window in hours (default 24, range 1–168).
        limit: Maximum alerts to retrieve (default 50, range 1–500).
        min_level: Minimum Wazuh rule.level to include (default 1, range 1–15).

    Returns:
        JSON object with ``source`` (``"wazuh"`` or ``"mock"``), ``params``
        (the resolved fetch parameters), and ``rows`` — each row containing
        ``incident_id``, ``timestamp``, ``user``, ``source_ip``,
        ``verdict``, ``risk_score``, ``top_signal``, ``mitre_tactic``,
        ``status``, and ``incident_json``.
    """
    # Inner helper — not hoisted to module level because it's only needed here.
    def _clamp(val: str | None, default: int, lo: int, hi: int) -> int:
        try:
            return max(lo, min(hi, int(val)))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return default

    hours     = _clamp(request.args.get("hours"),     24,  1, 168)
    limit     = _clamp(request.args.get("limit"),     50,  1, 500)
    min_level = _clamp(request.args.get("min_level"),  1,  1,  15)

    incidents: list[NormalizedIncident] = []
    data_source = "mock"
    try:
        # Deferred import: keeps server startup clean when the adapter's
        # env vars (ADTE_WAZUH_HOST etc.) are absent.
        from adte.adapters.wazuh import WazuhAdapter
        incidents = WazuhAdapter.from_env().fetch_incidents(hours=hours, limit=limit, min_level=min_level)
        data_source = "wazuh"
    except Exception:
        for filename in _EXAMPLE_FILES.values():
            raw = json.loads((EXAMPLES_DIR / filename).read_text(encoding="utf-8"))
            incidents.append(NormalizedIncident.from_sentinel(SentinelIncident(**raw)))

    now = time.monotonic()
    rows: list[dict[str, Any]] = []
    for incident in incidents:
        iid = incident.incident_id

        # Cache hit: return stored row if still within TTL.
        with _queue_cache_lock:
            cached = _queue_cache.get(iid)
            if cached and (now - cached["ts"]) < _QUEUE_CACHE_TTL:
                rows.append(cached["row"])
                continue

        # Cache miss: run the full triage pipeline.
        try:
            user_profile = get_user_profile(incident.user)
            fp_registry = FPRegistry.load()
            engine = TriageEngine(incident, user_profile, fp_registry)
            output = engine.enrich().score().decide().to_output()
        except Exception as exc:
            _log.error("Queue triage failed for incident %s (%s)", iid, type(exc).__name__)
            continue

        source_ip = (
            incident.events[0].ip_address or ""
            if incident.events
            else ""
        )
        rationale = output.get("rationale", [])
        top_signal = (
            max(rationale, key=lambda r: r.get("score", 0), default={}).get("signal", "")
            if rationale else ""
        )
        # mitre_tactics may be absent or empty; `or [""]` ensures [0] is safe.
        mitre_tactic = (output.get("report", {}).get("mitre_tactics") or [""])[0]

        row: dict[str, Any] = {
            "incident_id":      iid,
            "timestamp":        incident.created_time.isoformat() if incident.created_time else "",
            "user":             incident.user,
            "source_ip":        source_ip,
            "verdict":          output["verdict"],
            "risk_score":       output["risk_score"],
            "top_signal":       top_signal,
            "mitre_tactic":     mitre_tactic,
            "mitre_techniques": get_techniques(
                [r["signal"] for r in rationale if r.get("score", 0) > 0]
            ),
            "nist_phase":       get_nist_phase(output["verdict"]),
            "status":           "open",
            "incident_json":    incident.model_dump(mode="json"),
        }

        with _queue_cache_lock:
            _queue_cache[iid] = {"row": row, "ts": now}

        rows.append(row)

    return jsonify({
        "source": data_source,
        "params": {"hours": hours, "limit": limit, "min_level": min_level},
        "rows": rows,
    }), 200


@app.route("/api/verdicts")
@require_role("analyst")
@limiter.limit("60/minute")
def verdicts() -> Any:
    """Return audit log entries for past triage verdicts, newest first.

    NIST 800-61 Phase: Detection & Analysis — audit trail access for
    post-incident review and trending.

    Query Parameters:
        verdict: Optional filter string (e.g. ``"high_risk"``).
        limit:   Maximum rows to return (default 100, capped at 500).

    Returns:
        JSON object with ``verdicts`` (list of row dicts) and ``count`` (int).
    """
    verdict_filter: str | None = request.args.get("verdict") or None
    since: str | None = request.args.get("since") or None
    if since is not None:
        try:
            datetime.fromisoformat(since)
        except ValueError:
            return jsonify({
                "error": "since must be a valid ISO 8601 timestamp (e.g. 2025-01-01T00:00:00Z)"
            }), 400
    try:
        limit = max(1, min(500, int(request.args.get("limit", 100))))
    except (TypeError, ValueError):
        limit = 100
    rows = query_verdicts(DB_PATH, verdict_filter=verdict_filter, limit=limit, since=since)
    return jsonify({"verdicts": rows, "count": len(rows)}), 200


# Column order for the CSV export — explicit so the file layout is stable
# regardless of SQLite's column ordering or the presence of soft-delete fields.
_EXPORT_COLUMNS: list[str] = [
    "id",
    "incident_id",
    "verdict",
    "risk_score",
    "confidence",
    "recommended_action",
    "mitre_techniques",
    "nist_phase",
    "source",
    "timestamp",
    "logged_at",
]


@app.route("/api/verdicts/export")
@require_role("analyst")
@limiter.limit("10/minute")
def export_verdicts() -> Any:
    """Export audit-log verdict rows as a downloadable CSV or JSON file.

    Mirrors the filters of ``GET /api/verdicts`` but streams the result
    as an attachment so analysts can pull the audit trail into a
    spreadsheet or downstream tooling.

    NIST 800-61 Phase: Post-Incident Activity — supports retrospective
    review and reporting by exporting the persistent decision trail.

    Query Parameters:
        format:  ``"csv"`` (default) or ``"json"``.
        verdict: Optional exact-match filter (e.g. ``"high_risk"``).
        since:   Optional ISO 8601 lower bound on ``logged_at``.
        limit:   Maximum rows (default 1000, capped at 10000).

    Returns:
        A ``text/csv`` or ``application/json`` attachment (200), or
        ``{"error": "..."}`` on an invalid ``format`` or ``since`` (400).
    """
    fmt: str = (request.args.get("format") or "csv").lower()
    if fmt not in ("csv", "json"):
        return jsonify({"error": "format must be 'csv' or 'json'"}), 400

    verdict_filter: str | None = request.args.get("verdict") or None
    since: str | None = request.args.get("since") or None
    if since is not None:
        try:
            datetime.fromisoformat(since)
        except ValueError:
            return jsonify({
                "error": "since must be a valid ISO 8601 timestamp (e.g. 2025-01-01T00:00:00Z)"
            }), 400
    try:
        limit = max(1, min(10000, int(request.args.get("limit", 1000))))
    except (TypeError, ValueError):
        limit = 1000

    rows = query_verdicts(DB_PATH, verdict_filter=verdict_filter, limit=limit, since=since)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    if fmt == "json":
        body = json.dumps({"verdicts": rows, "count": len(rows)}, indent=2)
        return Response(
            body,
            mimetype="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="adte_verdicts_{stamp}.json"'
            },
        )

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_EXPORT_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({col: row.get(col, "") for col in _EXPORT_COLUMNS})
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="adte_verdicts_{stamp}.csv"'
        },
    )


def _parse_since_param() -> tuple[str | None, Any | None]:
    """Validate the optional ``since`` query parameter.

    Returns:
        ``(since, None)`` when absent or valid ISO-8601;
        ``(None, <error response>)`` when malformed.
    """
    since: str | None = request.args.get("since") or None
    if since is not None:
        try:
            datetime.fromisoformat(since)
        except ValueError:
            return None, (
                jsonify({
                    "error": "since must be a valid ISO 8601 timestamp (e.g. 2025-01-01T00:00:00Z)"
                }),
                400,
            )
    return since, None


@app.route("/api/stats/verdicts")
@require_role("analyst")
@limiter.limit("10/minute")
def stats_verdicts_route() -> Any:
    """Return the verdict distribution over the audit log (P13 aggregation).

    NIST 800-61 Phase: Post-Incident Activity — trend metrics for SOC review.

    Query Parameters:
        since: Optional ISO-8601 timestamp lower bound on ``logged_at``.

    Returns:
        JSON ``{"counts": {<verdict>: n}, "total": N, "since": <str|null>}``.
    """
    since, error = _parse_since_param()
    if error is not None:
        return error
    result = stats_verdicts(DB_PATH, since=since)
    result["since"] = since
    return jsonify(result), 200


@app.route("/api/stats/mitre")
@require_role("analyst")
@limiter.limit("10/minute")
def stats_mitre_route() -> Any:
    """Return MITRE ATT&CK technique frequency across logged verdicts.

    NIST 800-61 Phase: Post-Incident Activity — technique-level coverage
    and recurrence metrics for detection-engineering review.

    Query Parameters:
        since: Optional ISO-8601 timestamp lower bound on ``logged_at``.

    Returns:
        JSON ``{"techniques": [{"technique_id", "count"}], "total_rows": N,
        "since": <str|null>}`` sorted by count descending.
    """
    since, error = _parse_since_param()
    if error is not None:
        return error
    result = stats_mitre(DB_PATH, since=since)
    result["since"] = since
    return jsonify(result), 200


@app.route("/api/stats/feedback")
@require_role("analyst")
@limiter.limit("10/minute")
def stats_feedback_route() -> Any:
    """Return the analyst feedback FP/TP split and ratio.

    NIST 800-61 Phase: Post-Incident Activity — detection quality metrics.

    Query Parameters:
        since: Optional ISO-8601 timestamp lower bound on ``submitted_at``.

    Returns:
        JSON ``{"fp": n, "tp": n, "total": N, "fp_ratio": r,
        "since": <str|null>}``.
    """
    since, error = _parse_since_param()
    if error is not None:
        return error
    result = stats_feedback(DB_PATH, since=since)
    result["since"] = since
    return jsonify(result), 200


@app.route("/api/feedback", methods=["GET"])
@require_role("analyst")
@limiter.limit("60/minute")
def get_feedback() -> Any:
    """Return analyst feedback rows, newest first.

    NIST 800-61 Phase: Post-Incident Activity — surfaces the analyst
    feedback trail for review and tuning audits.

    Query Parameters:
        label: Optional filter — ``"fp"`` or ``"tp"``.  Omit for all rows.

    Returns:
        JSON object with ``feedback`` (list of row dicts) and ``count`` (int).
    """
    label: str | None = request.args.get("label") or None
    try:
        rows = query_feedback(DB_PATH, label=label)
        return jsonify({"feedback": rows, "count": len(rows)}), 200
    except Exception as exc:
        _log.error("GET /api/feedback failed (%s)", type(exc).__name__)
        return jsonify({"error": "Failed to retrieve feedback"}), 500


@app.route("/api/feedback", methods=["POST"])
@require_role("analyst")
@limiter.limit("30/minute")
def feedback() -> Any:
    """Record analyst FP/TP feedback and optionally promote FP IPs to the registry.

    Accepts a JSON body with ``incident_id``, ``label`` (``"fp"`` or ``"tp"``),
    and an optional ``ip``.  When ``label`` is ``"fp"`` and ``ip`` is present
    the IP is appended to the FP registry YAML so future triage runs suppress it.
    Promoting an IP to the registry requires the ``senior_analyst`` role; a plain
    analyst can still submit TP labels or FP labels without an IP.

    NIST 800-61 Phase: Post-Incident Activity — analyst feedback closes the
    detection tuning loop by promoting confirmed false positives into the
    known-benign registry.

    Request body:
        ``{"incident_id": "...", "label": "fp"|"tp", "ip": "..."}``
        (``ip`` is optional).

    Returns:
        ``{"status": "ok", "label": label, "incident_id": incident_id,
        "registry_updated": bool}`` on success (200).
        ``{"error": "..."}`` on bad label (400) or unexpected error (500).
    """
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415
    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({"error": "Request body must be valid JSON"}), 400

    incident_id: str = payload.get("incident_id") or ""
    label: str = payload.get("label") or ""
    ip: str | None = payload.get("ip") or None

    if label not in ("fp", "tp"):
        return jsonify({"error": "label must be 'fp' or 'tp'"}), 400

    try:
        log_feedback(incident_id, label, ip, DB_PATH)

        registry_updated = False
        if label == "fp" and ip:
            caller = _caller_role()
            if ROLES.get(caller, -1) < ROLES["senior_analyst"]:
                return jsonify({
                    "error": "Promoting IPs to the FP registry requires senior_analyst role"
                }), 403
            registry_updated = add_fp_entry(
                ip, "Auto-added by ADTE feedback loop", REGISTRY_PATH
            )

        return jsonify({
            "status": "ok",
            "label": label,
            "incident_id": incident_id,
            "registry_updated": registry_updated,
        }), 200
    except Exception as exc:
        _log.error("Feedback endpoint failed for incident %s (%s)", incident_id, type(exc).__name__)
        return jsonify({"error": "Failed to record feedback"}), 500


@app.route("/api/verdicts", methods=["DELETE"])
@require_role("admin")
@limiter.limit("5/minute")
def delete_verdicts() -> Any:
    """Soft-delete all active verdict rows from the audit table.

    Rows are stamped with ``deleted_at`` and hidden from normal queries;
    they are never physically removed, preserving the forensic audit trail
    required by NIST 800-61 non-repudiation requirements.

    NIST 800-61 Phase: Post-Incident Activity.

    Returns:
        ``{"status": "ok"}`` on success (200), or ``{"error": "..."}`` on failure (500).
    """
    ok = clear_verdicts(DB_PATH)
    if ok:
        return jsonify({"status": "ok"}), 200
    return jsonify({"error": "Failed to clear verdicts"}), 500


@app.route("/api/feedback", methods=["DELETE"])
@require_role("admin")
@limiter.limit("5/minute")
def delete_feedback() -> Any:
    """Soft-delete all active feedback rows from the audit table.

    Rows are stamped with ``deleted_at`` and hidden from normal queries;
    they are never physically removed, preserving the forensic audit trail.

    NIST 800-61 Phase: Post-Incident Activity.

    Returns:
        ``{"status": "ok"}`` on success (200), or ``{"error": "..."}`` on failure (500).
    """
    ok = clear_feedback(DB_PATH)
    if ok:
        return jsonify({"status": "ok"}), 200
    return jsonify({"error": "Failed to clear feedback"}), 500


# ---------------------------------------------------------------------------
# Case correlation — grouped alerts with kill-chain escalation
# ---------------------------------------------------------------------------


@app.route("/api/cases")
@require_role("analyst")
@limiter.limit("60/minute")
def cases() -> Any:
    """Return correlation case summaries, newest activity first.

    A case groups triaged alerts that share a source IP or user within the
    rolling correlation window (see ``adte/case_policy.py``).  Case status is
    computed on read: ``open`` while the last activity is inside the window,
    ``closed`` afterwards.

    NIST 800-61 Phase: Detection & Analysis — correlation of related events.

    Query Parameters:
        status: Optional filter — ``open``, ``closed``, or ``all`` (default).
        limit:  Maximum rows to return (default 50, capped at 200).

    Returns:
        JSON object with ``cases`` (list of summary dicts) and ``count``.
    """
    status = request.args.get("status", "all")
    if status not in ("open", "closed", "all"):
        return jsonify({"error": "status must be one of: open, closed, all"}), 400
    try:
        limit = max(1, min(200, int(request.args.get("limit", 50))))
    except (TypeError, ValueError):
        limit = 50
    rows = list_cases(DB_PATH, status=status, limit=limit)
    return jsonify({"cases": rows, "count": len(rows)}), 200


@app.route("/api/cases/<case_id>")
@require_role("analyst")
@limiter.limit("60/minute")
def case_detail(case_id: str) -> Any:
    """Return one case with its escalation rationale and member alerts.

    NIST 800-61 Phase: Detection & Analysis — drill-down into a correlated
    alert cluster for investigation.

    Args:
        case_id: Case identifier (``CASE-YYYYMMDD-xxxxxx``).

    Returns:
        Case detail JSON (summary + ``escalation_rationale`` + ``members``),
        or a 404 when the case is unknown or has been cleared.
    """
    detail = get_case(case_id, DB_PATH)
    if detail is None:
        return jsonify({"error": "Case not found"}), 404
    return jsonify(detail), 200


@app.route("/api/cases", methods=["DELETE"])
@require_role("admin")
@limiter.limit("5/minute")
def delete_cases() -> Any:
    """Soft-delete all active correlation cases.

    Cases are derived data — the verdict audit trail is untouched.  Rows are
    stamped ``deleted_at`` and hidden from queries, mirroring
    ``DELETE /api/verdicts``.

    NIST 800-61 Phase: Post-Incident Activity.

    Returns:
        ``{"status": "ok"}`` on success (200), or ``{"error": "..."}`` on
        failure (500).
    """
    ok = clear_cases(DB_PATH)
    if ok:
        return jsonify({"status": "ok"}), 200
    return jsonify({"error": "Failed to clear cases"}), 500


@app.route("/api/intel")
@require_role("analyst")
@limiter.limit("30/minute")
def intel() -> Any:
    """Enrich a single IP address against configured threat intelligence sources.

    Delegates to ``check_threat_intel`` which queries live API sources
    when keys are configured (``ADTE_ABUSEIPDB_KEY``, ``ADTE_VT_API_KEY``,
    ``ADTE_OTX_KEY``) and falls back to a deterministic mock otherwise.

    NIST 800-61 Phase: Detection & Analysis — observable enrichment.

    Query Parameters:
        ip: IPv4 address to look up.

    Returns:
        JSON object with ``ip``, ``is_malicious``, ``confidence``,
        ``source``, ``tags``, ``queried_at`` on success (200).
        ``{"error": "..."}`` on bad input (400) or failure (500).
    """
    ip = request.args.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "ip parameter required"}), 400
    try:
        from adte.intel.threat_intel import check_threat_intel
        r = check_threat_intel(ip)
        return jsonify({
            "ip":          r.ip,
            "is_malicious": r.is_malicious,
            "confidence":  r.confidence,
            "source":      r.source,
            "tags":        r.tags,
            "queried_at":  r.queried_at.isoformat() if r.queried_at else None,
        }), 200
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        _log.error("Intel lookup failed for IP %s (%s)", ip, type(exc).__name__)
        return jsonify({"error": "Intel lookup failed"}), 500


@app.route("/api/auth-check")
@require_role("readonly")
def auth_check() -> Any:
    """Verify the caller's API key and return their resolved role.

    Requires at minimum the ``readonly`` role.  In open/demo mode
    (no ``ADTE_API_KEY_*`` vars set) always returns ``{"authenticated":
    true, "role": "open"}``.

    NIST 800-61 Phase: Detection & Analysis — lets the frontend
    confirm a stored key is valid before the first triage call.

    Returns:
        ``{"authenticated": true, "role": "<role>"}`` on success (200).
    """
    session_token = request.cookies.get(_SESSION_COOKIE, "")
    if session_token:
        role = _resolve_session(session_token) or "open"
    else:
        api_key = request.headers.get("X-ADTE-Key", "")
        role = _resolve_role(api_key) if api_key else "open"
    return jsonify({"authenticated": True, "role": role}), 200


@app.route("/api/auth/login", methods=["POST"])
def auth_login() -> Any:
    """Exchange an API key for an HttpOnly session cookie.

    Accepts a JSON body ``{"api_key": "<key>"}`` and, if the key is valid,
    sets an ``adte_session`` cookie that is HttpOnly (not readable by JS)
    and SameSite=Strict.  The raw API key is never stored in the browser.

    NIST 800-61 Phase: Detection & Analysis — credential exchange for
    browser-based operator sessions.

    Returns:
        ``{"authenticated": true, "role": "<role>"}`` on success (200),
        or an error dict on failure (400/401).
    """
    body = request.get_json(silent=True) or {}
    api_key = str(body.get("api_key", "")).strip()
    if not api_key:
        return jsonify({"error": "api_key is required"}), 400

    role = _resolve_role(api_key)
    if role is None:
        return jsonify({"error": "Invalid API key"}), 401

    token = _create_session(role)
    resp = jsonify({"authenticated": True, "role": role})
    resp.set_cookie(
        _SESSION_COOKIE,
        token,
        httponly=True,
        secure=request.is_secure,   # Secure flag only over HTTPS (safe on localhost HTTP)
        samesite="Strict",
        path="/",
        max_age=_SESSION_TTL_HOURS * 3600,
    )
    return resp, 200


@app.route("/api/auth/logout", methods=["POST"])
def auth_logout() -> Any:
    """Invalidate the current browser session.

    Removes the session token from the server-side store and instructs
    the browser to delete the ``adte_session`` cookie.

    NIST 800-61 Phase: Detection & Analysis — explicit session termination.

    Returns:
        ``{"status": "logged_out"}`` (200) always.
    """
    token = request.cookies.get(_SESSION_COOKIE, "")
    if token:
        session_store.delete_session(token, DB_PATH)
    resp = jsonify({"status": "logged_out"})
    resp.delete_cookie(_SESSION_COOKIE, path="/")
    return resp, 200


@app.route("/api/config")
@require_role("senior_analyst")
@limiter.limit("10/minute")
def config() -> Any:
    """Return sanitised safety-gate configuration from environment variables.

    Reads the six ADTE safety gate env vars and returns their current
    values without exposing any secret or credential material.  Boolean
    vars are coerced to Python bools; allowlist vars are returned as
    lists of strings.

    NIST 800-61 Phase: Detection & Analysis — surfaces the reserved
    safety-gate env vars (read-only; reserved for a future execution layer,
    they gate nothing today) for analyst visibility.

    Returns:
        JSON object with ``kill_switch``, ``dry_run``,
        ``execution_enabled``, ``tenant_allowlist``,
        ``user_allowlist``, ``action_allowlist``.
    """
    # _b, _l, _mask_key are defined locally and read the safety-config env
    # vars directly. These vars are surfaced read-only here for analyst
    # visibility; they are reserved for a future execution layer and do not
    # gate anything today (ADTE performs no automated actions).
    def _b(key: str, default: str = "false") -> bool:
        return os.environ.get(key, default).lower() == "true"

    def _l(key: str, default: str = "") -> list[str]:
        val = os.environ.get(key, default)
        return [x.strip() for x in val.split(",") if x.strip()]

    def _mask_key(env_var: str) -> str:
        # Show first-4/last-4 for keys longer than 8 chars so analysts can
        # confirm which key is active without exposing the full secret.
        val = os.environ.get(env_var, "")
        if not val:
            return ""
        if len(val) <= 8:
            return "****"
        return val[:4] + "****" + val[-4:]

    return jsonify({
        "kill_switch":       _b("ADTE_KILL_SWITCH"),
        "dry_run":           _b("ADTE_DRY_RUN", "true"),
        "execution_enabled": _b("ADTE_EXECUTION_ENABLED"),
        "tenant_allowlist":  _l("ADTE_TENANT_ALLOWLIST"),
        "user_allowlist":    _l("ADTE_USER_ALLOWLIST"),
        "action_allowlist":  _l("ADTE_ACTION_ALLOWLIST", "CLOSE_INCIDENT,POST_COMMENT"),
        "api_keys": {
            "admin": _mask_key("ADTE_API_KEY_ADMIN"),
            "senior_analyst": _mask_key("ADTE_API_KEY_SENIOR"),
            "analyst": _mask_key("ADTE_API_KEY_ANALYST"),
            "readonly": _mask_key("ADTE_API_KEY_READONLY"),
        },
        "intel_keys": {
            "abuseipdb": _mask_key("ADTE_ABUSEIPDB_KEY"),
            "virustotal": _mask_key("ADTE_VT_API_KEY"),
            "otx": _mask_key("ADTE_OTX_KEY"),
        },
        "llm_available": bool(os.environ.get("ANTHROPIC_API_KEY", "").strip()),
    }), 200


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.run(host="0.0.0.0", port=5000, debug=False)
