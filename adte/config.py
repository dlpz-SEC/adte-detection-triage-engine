"""Safety configuration and execution gate controls.

Implements a defence-in-depth safety model with multiple independent
gates that must all pass before any automated action is executed.
This ensures that misconfiguration of a single variable cannot lead
to unintended automated response.

NIST 800-61 Phase: Containment, Eradication & Recovery — governs
which automated containment actions the engine is permitted to take
and provides an auditable record of blocked actions.

Gate evaluation order (short-circuits on first failure):

1. **Kill switch** — emergency halt of all automated actions.
2. **Dry-run mode** — global read-only mode (default: enabled).
3. **Execution enabled** — explicit opt-in for write operations.
4. **Tenant allowlist** — restricts actions to approved tenants.
5. **User / severity gate** — user must be on allowlist OR severity
   must be High/Critical (ensures high-sev incidents are never
   blocked by an incomplete allowlist).
6. **Action allowlist** — restricts which action types are permitted.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from typing import Any

from pydantic import Field
from pydantic_settings import BaseSettings


class SafetyConfig(BaseSettings):
    """Environment-driven safety configuration for the ADTE engine.

    All fields default to the most restrictive setting so that a
    fresh deployment with no env vars configured will refuse to
    execute any automated actions.

    Attributes:
        dry_run: When ``True`` (default), the engine will evaluate
            and score incidents but never execute write/mutate actions.
        execution_enabled: Must be explicitly set to ``True`` to allow
            any automated actions.  Acts as a second confirmation
            gate beyond ``dry_run``.
        kill_switch: Emergency halt.  When ``True``, **all** automated
            actions are blocked regardless of other settings.
        tenant_allowlist: Comma-separated list of Azure tenant IDs
            permitted for automated actions.  Empty list means all
            tenants are allowed (open gate).
        user_allowlist: Comma-separated list of UPNs whose incidents
            may be automatically actioned.  If the user is not on this
            list, the severity gate is checked instead.
        action_allowlist: Comma-separated list of action type strings
            the engine is permitted to execute (e.g. ``CLOSE_INCIDENT``,
            ``POST_COMMENT``).
    """

    dry_run: bool = True
    execution_enabled: bool = False
    kill_switch: bool = False
    tenant_allowlist: list[str] = Field(default_factory=list)
    user_allowlist: list[str] = Field(default_factory=list)
    action_allowlist: list[str] = Field(
        default_factory=lambda: ["CLOSE_INCIDENT", "POST_COMMENT"],
    )

    model_config = {
        "env_prefix": "ADTE_",
        "env_file": ".env",
        "env_file_encoding": "utf-8",
    }

    # ------------------------------------------------------------------
    # Execution gate
    # ------------------------------------------------------------------

    def can_execute(
        self,
        action_type: str,
        tenant_id: str,
        user_upn: str,
        severity: str,
    ) -> tuple[bool, list[str]]:
        """Evaluate whether an automated action is permitted.

        Checks every safety gate in order and collects all reasons for
        denial so that the caller (and audit log) can see exactly which
        gates blocked the action.

        Args:
            action_type: The action to execute (e.g. ``"CLOSE_INCIDENT"``).
            tenant_id: Azure tenant ID of the target environment.
            user_upn: User principal name of the incident subject.
            severity: Incident severity (``"Low"``, ``"Medium"``,
                ``"High"``, ``"Critical"``).

        Returns:
            A tuple of ``(allowed, reasons)``.  ``allowed`` is ``True``
            only if every gate passes.  ``reasons`` lists human-readable
            strings for each gate that blocked the action.
        """
        reasons: list[str] = []

        # Gate 1: Kill switch (highest priority).
        if self.kill_switch:
            reasons.append(
                "KILL_SWITCH is active — all automated actions halted"
            )

        # Gate 2: Dry-run mode.
        if self.dry_run:
            reasons.append(
                "DRY_RUN is enabled — write/mutate operations blocked"
            )

        # Gate 3: Execution not explicitly enabled.
        if not self.execution_enabled:
            reasons.append(
                "EXECUTION_ENABLED is false — automated actions require explicit opt-in"
            )

        # Gate 4: Tenant allowlist.
        if self.tenant_allowlist and tenant_id not in self.tenant_allowlist:
            reasons.append(
                f"Tenant {tenant_id!r} not in TENANT_ALLOWLIST "
                f"({', '.join(self.tenant_allowlist)})"
            )

        # Gate 5: User allowlist OR high severity.
        high_sev = severity in ("High", "Critical")
        user_allowed = not self.user_allowlist or user_upn in self.user_allowlist
        if not user_allowed and not high_sev:
            reasons.append(
                f"User {user_upn!r} not in USER_ALLOWLIST and severity "
                f"{severity!r} is not High/Critical"
            )

        # Gate 6: Action allowlist.
        if self.action_allowlist and action_type not in self.action_allowlist:
            reasons.append(
                f"Action {action_type!r} not in ACTION_ALLOWLIST "
                f"({', '.join(self.action_allowlist)})"
            )

        allowed = len(reasons) == 0
        return allowed, reasons

    # ------------------------------------------------------------------
    # Audit logging
    # ------------------------------------------------------------------

    def log_blocked_action(
        self,
        action_type: str,
        reasons: list[str],
        context: dict[str, Any],
    ) -> None:
        """Write a structured JSON log entry to stderr for a blocked action.

        NIST 800-61 requires an audit trail for all automated decisions,
        including actions that were *not* taken and why.

        Args:
            action_type: The action that was blocked.
            reasons: Human-readable list of gate failures.
            context: Arbitrary key-value context about the incident
                (incident_id, user, severity, etc.).
        """
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "action_blocked",
            "action_type": action_type,
            "reasons": reasons,
            "context": context,
        }
        print(json.dumps(entry, default=str), file=sys.stderr)
