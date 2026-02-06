"""Microsoft Entra ID (Azure AD) adapter for identity response actions.

Provides mock implementations of Entra ID user-management operations
(token revocation, password reset, account disable) that respect the
ADTE safety gate framework.  In production these would call the
Microsoft Graph API.

NIST 800-61 Phase: Containment, Eradication & Recovery — executes
identity-level containment to limit attacker persistence after a
confirmed or high-confidence compromise.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from adte.config import SafetyConfig


class EntraIDAdapter:
    """Safety-gated adapter for Microsoft Entra ID user operations.

    Every mutating method checks ``SafetyConfig.can_execute()`` before
    taking action.  High-impact operations like ``disable_user`` use
    a distinct action type (``DISABLE_ACCOUNT``) that is *not* in the
    default action allowlist, so they are blocked unless explicitly
    permitted.

    Typical usage::

        adapter = EntraIDAdapter(tenant_id, safety_config)
        result = adapter.revoke_refresh_tokens("alice@contoso.com", "High")
    """

    def __init__(self, tenant_id: str, safety_config: SafetyConfig) -> None:
        """Initialise the Entra ID adapter.

        Args:
            tenant_id: Azure tenant ID for the Entra ID directory.
            safety_config: Safety gate configuration that governs
                which actions are permitted.
        """
        self._tenant_id = tenant_id
        self._safety = safety_config

    def revoke_refresh_tokens(
        self,
        user_upn: str,
        severity: str,
    ) -> dict[str, Any]:
        """Revoke all refresh tokens for a user, forcing re-authentication.

        This is a moderate-impact action: the user must sign in again
        but does not lose account access.

        Args:
            user_upn: User principal name whose tokens to revoke.
            severity: Incident severity (for gate checks).

        Returns:
            A dict with ``status`` (``"executed"`` or ``"blocked"``),
            ``action``, ``user_upn``, and either the mock Graph API
            response or the block ``reasons``.
        """
        action_type = "REVOKE_SESSIONS"
        context = {
            "user_upn": user_upn,
            "severity": severity,
            "tenant_id": self._tenant_id,
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
                "user_upn": user_upn,
                "reasons": reasons,
            }

        # Mock execution — Graph API: POST /users/{id}/revokeSignInSessions
        now = datetime.now(timezone.utc).isoformat()
        return {
            "status": "executed",
            "action": action_type,
            "user_upn": user_upn,
            "response": {
                "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#Edm.Boolean",
                "value": True,
                "timestamp": now,
            },
        }

    def force_password_reset(
        self,
        user_upn: str,
        severity: str,
    ) -> dict[str, Any]:
        """Force a password reset on next sign-in for a user.

        This is a high-impact action: the user will be unable to access
        resources until they complete the password reset flow.

        Args:
            user_upn: User principal name whose password to reset.
            severity: Incident severity (for gate checks).

        Returns:
            A dict with ``status``, ``action``, ``user_upn``, and
            either the mock response or block ``reasons``.
        """
        action_type = "FORCE_PASSWORD_RESET"
        context = {
            "user_upn": user_upn,
            "severity": severity,
            "tenant_id": self._tenant_id,
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
                "user_upn": user_upn,
                "reasons": reasons,
            }

        # Mock execution — Graph API: PATCH /users/{id}
        now = datetime.now(timezone.utc).isoformat()
        return {
            "status": "executed",
            "action": action_type,
            "user_upn": user_upn,
            "response": {
                "id": f"mock-user-id-{user_upn}",
                "userPrincipalName": user_upn,
                "passwordProfile": {
                    "forceChangePasswordNextSignIn": True,
                    "forceChangePasswordNextSignInWithMfa": True,
                },
                "timestamp": now,
            },
        }

    def disable_user(
        self,
        user_upn: str,
        severity: str,
    ) -> dict[str, Any]:
        """Disable a user account, blocking all sign-in attempts.

        This is the highest-impact identity action: the user is
        completely locked out.  The action type ``DISABLE_ACCOUNT`` is
        **not** in the default action allowlist and must be explicitly
        added to ``ADTE_ACTION_ALLOWLIST`` before it will execute.

        Args:
            user_upn: User principal name to disable.
            severity: Incident severity (for gate checks).

        Returns:
            A dict with ``status``, ``action``, ``user_upn``, and
            either the mock response or block ``reasons``.
        """
        action_type = "DISABLE_ACCOUNT"
        context = {
            "user_upn": user_upn,
            "severity": severity,
            "tenant_id": self._tenant_id,
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
                "user_upn": user_upn,
                "reasons": reasons,
            }

        # Mock execution — Graph API: PATCH /users/{id} accountEnabled=false
        now = datetime.now(timezone.utc).isoformat()
        return {
            "status": "executed",
            "action": action_type,
            "user_upn": user_upn,
            "response": {
                "id": f"mock-user-id-{user_upn}",
                "userPrincipalName": user_upn,
                "accountEnabled": False,
                "timestamp": now,
            },
        }
