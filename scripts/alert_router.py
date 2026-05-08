"""ADTE alert router — polls /api/queue and routes verdicts to Slack and tickets.

Runs as a standalone script.  Polls the ADTE queue endpoint on a fixed interval,
deduplicates already-seen incidents, enriches each new high-risk hit with a
secondary triage call to obtain ``confidence`` and ``recommended_action``, and
delivers a plain-text notification to a Slack incoming webhook or stdout fallback.

After routing a ``high_risk`` alert, attempts to open a ticket via
``scripts.ticket_client.create_ticket``.  ``medium_risk`` verdicts also trigger
ticket creation directly from the queue row (no second triage fetch).

NIST 800-61 Phase: Detection & Analysis — automated escalation of high-risk
and medium-risk triage verdicts to on-call operators.

Usage::

    python scripts/alert_router.py [--url URL] [--interval N]

Environment variables:
    ADTE_SLACK_WEBHOOK: Slack incoming webhook URL.  When unset, alerts are
        printed to stdout instead.
    ADTE_LINEAR_API_KEY / ADTE_TRELLO_API_KEY: See scripts/ticket_client.py.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from typing import Any

import requests

from scripts.ticket_client import create_ticket

_log = logging.getLogger(__name__)

_QUEUE_PARAMS: dict[str, int] = {
    "hours": 1,
    "limit": 100,
    "min_level": 1,
}

MAX_QUEUE_SIZE: int = 1000


def fetch_queue(base_url: str) -> list[dict[str, Any]]:
    """Fetch the current triage queue from the ADTE server.

    Args:
        base_url: ADTE server base URL (e.g. ``"http://localhost:5000"``).

    Returns:
        List of row dicts from ``/api/queue``, or an empty list on any error.
    """
    try:
        resp = requests.get(
            f"{base_url}/api/queue",
            params=_QUEUE_PARAMS,
            timeout=10,
        )
        if resp.status_code != 200:
            _log.warning("Queue poll returned HTTP %s", resp.status_code)
            return []
        return resp.json().get("rows", [])
    except requests.RequestException as exc:
        _log.warning("Failed to reach ADTE server: %s", exc)
        return []


def fetch_triage(base_url: str, incident_json: dict[str, Any]) -> dict[str, Any] | None:
    """POST an incident to /api/triage and return the full result.

    Used to retrieve ``confidence``, ``recommended_action``, and ``rationale``
    fields not included in the queue row.

    Args:
        base_url: ADTE server base URL.
        incident_json: Serialised ``NormalizedIncident`` dict from the queue row.

    Returns:
        Full triage output dict, or ``None`` on any error.
    """
    try:
        resp = requests.post(
            f"{base_url}/api/triage",
            json=incident_json,
            timeout=15,
        )
        if resp.status_code != 200:
            _log.warning("Triage enrichment returned HTTP %s", resp.status_code)
            return None
        return resp.json()
    except requests.RequestException as exc:
        _log.warning("Triage enrichment request failed: %s", exc)
        return None


def _build_message(row: dict[str, Any], detail: dict[str, Any] | None) -> str:
    """Format a plain-text alert message for Slack or stdout.

    Args:
        row: Queue row dict containing base incident fields.
        detail: Full triage result from ``/api/triage``, or ``None`` if the
            enrichment call failed.

    Returns:
        Formatted plain-text alert string (no emojis).
    """
    incident_id = row.get("incident_id", "unknown")
    user = row.get("user", "unknown")
    source_ip = row.get("source_ip", "unknown")
    risk_score = row.get("risk_score", "N/A")

    if detail is not None:
        confidence_raw = detail.get("confidence")
        confidence = f"{confidence_raw}%" if confidence_raw is not None else "N/A"
        recommended_action = detail.get("recommended_action", "N/A")
        rationale: list[dict[str, Any]] = detail.get("rationale") or []
        if rationale:
            best = max(rationale, key=lambda r: r.get("score", 0))
            top_signal = best.get("signal", row.get("top_signal", "N/A"))
        else:
            top_signal = row.get("top_signal", "N/A")
    else:
        confidence = "N/A"
        recommended_action = "N/A"
        top_signal = row.get("top_signal", "N/A")

    return (
        "HIGH RISK ALERT\n"
        f"Incident:         {incident_id}\n"
        f"User:             {user}\n"
        f"Source IP:        {source_ip}\n"
        f"Risk Score:       {risk_score}/100\n"
        f"Confidence:       {confidence}\n"
        f"Top Signal:       {top_signal}\n"
        f"Recommended:      {recommended_action}"
    )


def route_alert(
    row: dict[str, Any],
    detail: dict[str, Any] | None,
    webhook_url: str | None,
) -> None:
    """Route a high-risk alert to Slack or stdout.

    If ``webhook_url`` is set, POSTs the message as ``{"text": ...}`` to the
    Slack incoming webhook.  On webhook error, logs a warning and continues.
    If ``webhook_url`` is ``None``, prints the message to stdout.

    Args:
        row: Queue row dict for the high-risk incident.
        detail: Full triage result, or ``None`` if enrichment failed.
        webhook_url: Slack incoming webhook URL, or ``None`` for stdout fallback.
    """
    message = _build_message(row, detail)

    if webhook_url:
        try:
            resp = requests.post(
                webhook_url,
                json={"text": message},
                timeout=5,
            )
            if resp.status_code != 200:
                _log.warning(
                    "Slack webhook returned HTTP %s for incident %s",
                    resp.status_code,
                    row.get("incident_id"),
                )
        except requests.RequestException as exc:
            _log.warning("Slack webhook request failed: %s", exc)
    else:
        print(message)
        print()


def run_loop(base_url: str, interval: int, webhook_url: str | None) -> None:
    """Run the alert routing polling loop until interrupted.

    Maintains an in-memory set of seen incident IDs to prevent duplicate
    notifications across both ``high_risk`` (Slack + ticket) and
    ``medium_risk`` (ticket only) verdicts.  The set resets on process restart.

    Args:
        base_url: ADTE server base URL.
        interval: Seconds to sleep between queue polls.
        webhook_url: Slack incoming webhook URL, or ``None`` for stdout fallback.
    """
    seen_ids: set[str] = set()

    try:
        while True:
            if len(seen_ids) >= MAX_QUEUE_SIZE:
                _log.warning(
                    "seen_ids set reached MAX_QUEUE_SIZE (%d) — evicting oldest entries",
                    MAX_QUEUE_SIZE,
                )
                to_keep = len(seen_ids) // 2
                seen_ids = set(list(seen_ids)[-to_keep:])

            rows = fetch_queue(base_url)
            new_high_risk = 0
            for row in rows:
                verdict = row.get("verdict")
                if verdict not in ("high_risk", "medium_risk"):
                    continue
                incident_id = row.get("incident_id", "")
                if incident_id in seen_ids:
                    continue
                seen_ids.add(incident_id)

                if verdict == "high_risk":
                    new_high_risk += 1
                    detail = fetch_triage(base_url, row.get("incident_json", {}))
                    route_alert(row, detail, webhook_url)
                    ticket_url = create_ticket(detail if detail is not None else row)
                else:
                    ticket_url = create_ticket(row)

                if ticket_url:
                    _log.info("Ticket created for %s: %s", incident_id, ticket_url)
                else:
                    _log.warning("Ticket creation skipped or failed for %s", incident_id)

            _log.info(
                "Polled queue: %d rows, %d new high-risk", len(rows), new_high_risk
            )
            time.sleep(interval)
    except KeyboardInterrupt:
        _log.info("Alert router stopped by user.")
        sys.exit(0)


def _parse_args() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        Parsed argument namespace with ``url`` and ``interval`` attributes.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Poll the ADTE triage queue and route HIGH RISK verdicts to Slack."
        ),
    )
    parser.add_argument(
        "--url",
        default="http://localhost:5000",
        metavar="URL",
        help="ADTE server base URL (default: http://localhost:5000)",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=60,
        metavar="N",
        help="Poll interval in seconds (default: 60)",
    )
    return parser.parse_args()


def main() -> None:
    """Entry point for the ADTE alert router.

    Reads ``ADTE_SLACK_WEBHOOK`` from the environment, prints a startup
    banner, then enters the polling loop.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    args = _parse_args()
    base_url: str = args.url.rstrip("/")
    interval: int = args.interval
    webhook_url: str | None = os.environ.get("ADTE_SLACK_WEBHOOK") or None

    slack_status = (
        "configured"
        if webhook_url
        else "stdout fallback (ADTE_SLACK_WEBHOOK not set)"
    )
    print(
        "ADTE Alert Router\n"
        f"  ADTE URL:      {base_url}\n"
        f"  Poll interval: {interval}s\n"
        f"  Slack:         {slack_status}"
    )

    run_loop(base_url, interval, webhook_url)


if __name__ == "__main__":
    main()
