"""Microsoft Sentinel adapter for incident management actions.

Provides mock implementations of Sentinel API operations (posting
comments, closing incidents) that respect the ADTE safety gate
framework.  In production these would call the Azure REST API via
``azure-mgmt-securityinsight``.

NIST 800-61 Phase: Containment, Eradication & Recovery — executes
the containment and resolution actions decided by the triage engine.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from adte.config import SafetyConfig


class SentinelAdapter:
    """Safety-gated adapter for Microsoft Sentinel incident operations.

    Every mutating method checks ``SafetyConfig.can_execute()`` before
    taking action.  Blocked actions are logged via
    ``SafetyConfig.log_blocked_action()`` and return a response dict
    with ``"status": "blocked"``.

    Typical usage::

        adapter = SentinelAdapter(tenant_id, safety_config)
        result = adapter.post_incident_comment(incident_id, comment)
    """

    def __init__(self, tenant_id: str, safety_config: SafetyConfig) -> None:
        """Initialise the Sentinel adapter.

        Args:
            tenant_id: Azure tenant ID for the Sentinel workspace.
            safety_config: Safety gate configuration that governs
                which actions are permitted.
        """
        self._tenant_id = tenant_id
        self._safety = safety_config

    def post_incident_comment(
        self,
        incident_id: str,
        comment: str,
        *,
        user_upn: str = "",
        severity: str = "Medium",
    ) -> dict[str, Any]:
        """Post an analyst comment to a Sentinel incident.

        Args:
            incident_id: Sentinel incident ID to comment on.
            comment: Comment text (Markdown supported by Sentinel).
            user_upn: UPN of the incident subject (for gate checks).
            severity: Incident severity (for gate checks).

        Returns:
            A dict with ``status`` (``"executed"`` or ``"blocked"``),
            ``action``, ``incident_id``, and either the mock API
            response or the block ``reasons``.
        """
        action_type = "POST_COMMENT"
        context = {
            "incident_id": incident_id,
            "user_upn": user_upn,
            "severity": severity,
            "comment_length": len(comment),
        }

        allowed, reasons = self._safety.can_execute(
            action_type=action_type,
            tenant_id=self._tenant_id,
            user_upn=user_upn,
            severity=severity,
        )

        if not allowed:
            self._safety.log_blocked_action(action_type, reasons, context)
            return {
                "status": "blocked",
                "action": action_type,
                "incident_id": incident_id,
                "reasons": reasons,
            }

        # Mock execution — in production this calls the Sentinel REST API.
        now = datetime.now(timezone.utc).isoformat()
        return {
            "status": "executed",
            "action": action_type,
            "incident_id": incident_id,
            "response": {
                "id": f"{incident_id}/comments/mock-{now}",
                "name": f"mock-comment-{now}",
                "properties": {
                    "message": comment,
                    "createdTimeUtc": now,
                    "author": {
                        "name": "ADTE Triage Engine",
                        "objectId": "00000000-0000-0000-0000-000000000000",
                    },
                },
            },
        }

    def close_incident(
        self,
        incident_id: str,
        classification: str,
        reason: str,
        *,
        user_upn: str = "",
        severity: str = "Medium",
    ) -> dict[str, Any]:
        """Close a Sentinel incident with a classification and reason.

        Args:
            incident_id: Sentinel incident ID to close.
            classification: Closing classification (e.g.
                ``"BenignPositive"``, ``"TruePositive"``,
                ``"FalsePositive"``, ``"Undetermined"``).
            reason: Free-text reason for the classification.
            user_upn: UPN of the incident subject (for gate checks).
            severity: Incident severity (for gate checks).

        Returns:
            A dict with ``status``, ``action``, ``incident_id``, and
            either the mock API response or the block ``reasons``.
        """
        action_type = "CLOSE_INCIDENT"
        context = {
            "incident_id": incident_id,
            "user_upn": user_upn,
            "severity": severity,
            "classification": classification,
            "reason": reason,
        }

        allowed, reasons = self._safety.can_execute(
            action_type=action_type,
            tenant_id=self._tenant_id,
            user_upn=user_upn,
            severity=severity,
        )

        if not allowed:
            self._safety.log_blocked_action(action_type, reasons, context)
            return {
                "status": "blocked",
                "action": action_type,
                "incident_id": incident_id,
                "reasons": reasons,
            }

        # Mock execution.
        now = datetime.now(timezone.utc).isoformat()
        return {
            "status": "executed",
            "action": action_type,
            "incident_id": incident_id,
            "response": {
                "id": incident_id,
                "properties": {
                    "status": "Closed",
                    "classification": classification,
                    "classificationReason": reason,
                    "closedTimeUtc": now,
                    "owner": {
                        "assignedTo": "ADTE Triage Engine",
                        "objectId": "00000000-0000-0000-0000-000000000000",
                    },
                },
            },
        }
