"""ADTE ticket client — creates Linear or Trello tickets for triage verdicts.

Provides a single ``create_ticket()`` dispatcher that tries Linear first
(when ``ADTE_LINEAR_API_KEY`` is set) then falls back to Trello (when
``ADTE_TRELLO_API_KEY`` is set).  If neither provider is configured the
function returns ``None`` silently — no errors on unconfigured installs.

All failures are logged at WARNING level and swallowed.  Ticket creation
can never raise or interrupt the caller's control flow.

NIST 800-61 Phase: Detection & Analysis — automated evidence trail for
incidents requiring analyst follow-up.

Environment variables:
    ADTE_LINEAR_API_KEY:   Linear personal API key.
    ADTE_LINEAR_TEAM_ID:   Linear team ID to create issues in.
    ADTE_TRELLO_API_KEY:   Trello Power-Up API key.
    ADTE_TRELLO_TOKEN:     Trello user OAuth token.
    ADTE_TRELLO_LIST_ID:   ID of the Trello list to add cards to.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

import requests

_log = logging.getLogger(__name__)

_LINEAR_URL: str = "https://api.linear.app/graphql"
_TRELLO_URL: str = "https://api.trello.com/1/cards"

_LINEAR_MUTATION: str = """
mutation IssueCreate($teamId: String!, $title: String!, $description: String!) {
  issueCreate(input: { teamId: $teamId, title: $title, description: $description }) {
    success
    issue {
      url
    }
  }
}
"""


def _build_title(verdict: dict[str, Any]) -> str:
    """Build a ticket title from a triage verdict or queue row.

    Args:
        verdict: Full triage output dict or queue row dict.

    Returns:
        Title string in the format ``[VERDICT_UPPER] incident_id — description``.
    """
    raw_verdict = verdict.get("verdict", "unknown")
    verdict_upper = raw_verdict.upper().replace("-", "_")

    incident_id = (
        verdict.get("incident_id")
        or (verdict.get("evidence") or {}).get("incident_id")
        or (verdict.get("report") or {}).get("incident_id")
        or "unknown"
    )

    description = (
        verdict.get("rule_description")
        or (verdict.get("report") or {}).get("rule_description")
        or verdict.get("user")
        or (verdict.get("evidence") or {}).get("user")
        or (verdict.get("report") or {}).get("user")
        or "unknown"
    )

    return f"[{verdict_upper}] {incident_id} — {description}"


def _build_body(verdict: dict[str, Any]) -> str:
    """Build ticket body text from a triage verdict or queue row.

    Includes verdict, risk score, confidence, recommended action, top signal
    rationale (if present), and timestamp.

    Args:
        verdict: Full triage output dict or queue row dict.

    Returns:
        Multi-line plain-text body string.
    """
    raw_verdict = verdict.get("verdict", "unknown")
    risk_score = verdict.get("risk_score", "N/A")
    confidence = verdict.get("confidence", "N/A")
    recommended_action = verdict.get("recommended_action", "N/A")

    timestamp = (
        (verdict.get("report") or {}).get("timestamp")
        or verdict.get("timestamp")
        or datetime.now(timezone.utc).isoformat()
    )

    lines: list[str] = [
        f"Verdict: {raw_verdict.upper()}",
        f"Risk Score: {risk_score}/100",
        f"Confidence: {confidence}%",
        f"Recommended Action: {recommended_action}",
    ]

    rationale: list[dict[str, Any]] = verdict.get("rationale") or []
    if rationale:
        best = max(rationale, key=lambda r: r.get("score", 0))
        signal = best.get("signal", "")
        detail = best.get("detail", "")
        if signal:
            lines.append(f"Top Signal: {signal} — {detail}")
    elif verdict.get("top_signal"):
        lines.append(f"Top Signal: {verdict['top_signal']}")

    mitre_techniques: list[str] = verdict.get("mitre_techniques") or []
    if mitre_techniques:
        lines.append(f"MITRE ATT&CK: {', '.join(mitre_techniques)}")
    nist_phase: str | None = verdict.get("nist_phase")
    if nist_phase:
        lines.append(f"NIST 800-61: {nist_phase}")

    lines.append(f"Timestamp: {timestamp}")

    return "\n".join(lines)


def create_linear_ticket(verdict: dict[str, Any]) -> str | None:
    """Create a Linear issue for the given triage verdict.

    Reads ``ADTE_LINEAR_API_KEY`` and ``ADTE_LINEAR_TEAM_ID`` from the
    environment.  Returns ``None`` without making any network call if either
    variable is unset.

    Args:
        verdict: Full triage output dict or queue row dict.

    Returns:
        The Linear issue URL on success, or ``None`` on failure or missing keys.
    """
    api_key = os.environ.get("ADTE_LINEAR_API_KEY")
    team_id = os.environ.get("ADTE_LINEAR_TEAM_ID")

    if not api_key or not team_id:
        return None

    title = _build_title(verdict)
    body = _build_body(verdict)

    try:
        resp = requests.post(
            _LINEAR_URL,
            json={
                "query": _LINEAR_MUTATION,
                "variables": {
                    "teamId": team_id,
                    "title": title,
                    "description": body,
                },
            },
            headers={
                "Authorization": api_key,
                "Content-Type": "application/json",
            },
            timeout=10,
        )
        if resp.status_code != 200:
            _log.warning("Linear API returned HTTP %s", resp.status_code)
            return None
        data = resp.json()
        url: str | None = (
            (data.get("data") or {})
            .get("issueCreate", {})
            .get("issue", {})
            .get("url")
        )
        if not url:
            _log.warning("Linear response missing issue URL: %s", data)
            return None
        return url
    except requests.RequestException as exc:
        _log.warning("Linear ticket creation failed: %s", exc)
        return None


def create_trello_card(verdict: dict[str, Any]) -> str | None:
    """Create a Trello card for the given triage verdict.

    Reads ``ADTE_TRELLO_API_KEY``, ``ADTE_TRELLO_TOKEN``, and
    ``ADTE_TRELLO_LIST_ID`` from the environment.  Returns ``None`` without
    making any network call if any variable is unset.

    Args:
        verdict: Full triage output dict or queue row dict.

    Returns:
        The Trello card URL on success, or ``None`` on failure or missing keys.
    """
    api_key = os.environ.get("ADTE_TRELLO_API_KEY")
    token = os.environ.get("ADTE_TRELLO_TOKEN")
    list_id = os.environ.get("ADTE_TRELLO_LIST_ID")

    if not api_key or not token or not list_id:
        return None

    title = _build_title(verdict)
    body = _build_body(verdict)

    try:
        resp = requests.post(
            _TRELLO_URL,
            params={
                "key": api_key,
                "token": token,
                "idList": list_id,
                "name": title,
                "desc": body,
            },
            timeout=10,
        )
        if resp.status_code not in (200, 201):
            _log.warning("Trello API returned HTTP %s", resp.status_code)
            return None
        data = resp.json()
        url = data.get("url") or data.get("shortUrl")
        if not url:
            _log.warning("Trello response missing card URL: %s", data)
            return None
        return url
    except requests.RequestException as exc:
        _log.warning("Trello card creation failed: %s", exc)
        return None


def create_ticket(verdict: dict[str, Any]) -> str | None:
    """Dispatch to Linear or Trello and return the first successful ticket URL.

    Tries Linear first when ``ADTE_LINEAR_API_KEY`` is set, then Trello when
    ``ADTE_TRELLO_API_KEY`` is set.  Returns ``None`` silently when neither
    provider is configured or both fail.  Never raises.

    Args:
        verdict: Full triage output dict or queue row dict.

    Returns:
        Ticket URL from the first successful provider, or ``None``.
    """
    if os.environ.get("ADTE_LINEAR_API_KEY"):
        url = create_linear_ticket(verdict)
        if url is not None:
            return url

    if os.environ.get("ADTE_TRELLO_API_KEY"):
        url = create_trello_card(verdict)
        if url is not None:
            return url

    return None
