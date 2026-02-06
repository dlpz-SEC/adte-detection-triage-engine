"""Tests for adte.config — SafetyConfig execution gates."""

from __future__ import annotations

import json

from adte.config import SafetyConfig


class TestDefaultConfig:
    """Test that default configuration is maximally restrictive."""

    def test_default_config_blocks_all(self) -> None:
        """Default SafetyConfig blocks all actions (dry_run + execution_enabled)."""
        cfg = SafetyConfig()
        allowed, reasons = cfg.can_execute(
            "CLOSE_INCIDENT", "tenant-1", "alice@contoso.com", "Low",
        )
        assert allowed is False
        assert len(reasons) == 2
        assert any("DRY_RUN" in r for r in reasons)
        assert any("EXECUTION_ENABLED" in r for r in reasons)

    def test_default_values(self) -> None:
        """Default field values are the most restrictive."""
        cfg = SafetyConfig()
        assert cfg.dry_run is True
        assert cfg.execution_enabled is False
        assert cfg.kill_switch is False
        assert cfg.tenant_allowlist == []
        assert cfg.user_allowlist == []
        assert cfg.action_allowlist == ["CLOSE_INCIDENT", "POST_COMMENT"]


class TestKillSwitch:
    """Test the kill switch gate."""

    def test_kill_switch_blocks_everything(self) -> None:
        """Kill switch blocks even when all other gates are open."""
        cfg = SafetyConfig(
            kill_switch=True, dry_run=False, execution_enabled=True,
        )
        allowed, reasons = cfg.can_execute(
            "CLOSE_INCIDENT", "tenant-1", "alice@contoso.com", "Critical",
        )
        assert allowed is False
        assert any("KILL_SWITCH" in r for r in reasons)


class TestDryRun:
    """Test the dry-run gate."""

    def test_dry_run_blocks_execution(self) -> None:
        """Dry-run mode blocks write operations."""
        cfg = SafetyConfig(dry_run=True, execution_enabled=True)
        allowed, reasons = cfg.can_execute(
            "CLOSE_INCIDENT", "tenant-1", "alice@contoso.com", "Low",
        )
        assert allowed is False
        assert any("DRY_RUN" in r for r in reasons)


class TestExecutionEnabled:
    """Test the execution-enabled gate."""

    def test_execution_enabled_required(self) -> None:
        """Execution must be explicitly enabled."""
        cfg = SafetyConfig(dry_run=False, execution_enabled=False)
        allowed, reasons = cfg.can_execute(
            "CLOSE_INCIDENT", "tenant-1", "alice@contoso.com", "Low",
        )
        assert allowed is False
        assert any("EXECUTION_ENABLED" in r for r in reasons)


class TestTenantAllowlist:
    """Test the tenant allowlist gate."""

    def test_tenant_allowlist_blocks_wrong_tenant(self) -> None:
        """Actions for unlisted tenants are blocked."""
        cfg = SafetyConfig(
            dry_run=False, execution_enabled=True,
            tenant_allowlist=["tenant-a"],
        )
        allowed, reasons = cfg.can_execute(
            "CLOSE_INCIDENT", "tenant-b", "alice@contoso.com", "Low",
        )
        assert allowed is False
        assert any("TENANT_ALLOWLIST" in r for r in reasons)

    def test_tenant_allowlist_allows_listed_tenant(self) -> None:
        """Actions for listed tenants pass this gate."""
        cfg = SafetyConfig(
            dry_run=False, execution_enabled=True,
            tenant_allowlist=["tenant-a"],
        )
        allowed, reasons = cfg.can_execute(
            "CLOSE_INCIDENT", "tenant-a", "alice@contoso.com", "Low",
        )
        assert allowed is True

    def test_tenant_allowlist_empty_allows_all(self) -> None:
        """Empty allowlist means all tenants are permitted."""
        cfg = SafetyConfig(
            dry_run=False, execution_enabled=True,
            tenant_allowlist=[],
        )
        allowed, reasons = cfg.can_execute(
            "CLOSE_INCIDENT", "any-tenant", "alice@contoso.com", "Low",
        )
        assert allowed is True


class TestUserAllowlist:
    """Test the user allowlist / severity gate."""

    def test_user_allowlist_bypassed_by_high_severity(self) -> None:
        """High severity bypasses the user allowlist."""
        cfg = SafetyConfig(
            dry_run=False, execution_enabled=True,
            user_allowlist=["bob@contoso.com"],
        )
        # alice is NOT in allowlist, but severity is High
        allowed, reasons = cfg.can_execute(
            "CLOSE_INCIDENT", "tenant-1", "alice@contoso.com", "High",
        )
        assert allowed is True

    def test_user_allowlist_bypassed_by_critical_severity(self) -> None:
        """Critical severity also bypasses the user allowlist."""
        cfg = SafetyConfig(
            dry_run=False, execution_enabled=True,
            user_allowlist=["bob@contoso.com"],
        )
        allowed, reasons = cfg.can_execute(
            "CLOSE_INCIDENT", "tenant-1", "alice@contoso.com", "Critical",
        )
        assert allowed is True

    def test_user_allowlist_blocks_at_low_severity(self) -> None:
        """Unlisted user at Low severity is blocked."""
        cfg = SafetyConfig(
            dry_run=False, execution_enabled=True,
            user_allowlist=["bob@contoso.com"],
        )
        allowed, reasons = cfg.can_execute(
            "CLOSE_INCIDENT", "tenant-1", "alice@contoso.com", "Low",
        )
        assert allowed is False
        assert any("USER_ALLOWLIST" in r for r in reasons)


class TestActionAllowlist:
    """Test the action allowlist gate."""

    def test_action_allowlist_blocks_unlisted_action(self) -> None:
        """Actions not in the allowlist are blocked."""
        cfg = SafetyConfig(
            dry_run=False, execution_enabled=True,
            action_allowlist=["CLOSE_INCIDENT", "POST_COMMENT"],
        )
        allowed, reasons = cfg.can_execute(
            "DISABLE_ACCOUNT", "tenant-1", "alice@contoso.com", "High",
        )
        assert allowed is False
        assert any("ACTION_ALLOWLIST" in r for r in reasons)

    def test_action_allowlist_allows_listed_action(self) -> None:
        """Actions in the allowlist pass this gate."""
        cfg = SafetyConfig(
            dry_run=False, execution_enabled=True,
            action_allowlist=["DISABLE_ACCOUNT"],
        )
        allowed, reasons = cfg.can_execute(
            "DISABLE_ACCOUNT", "tenant-1", "alice@contoso.com", "High",
        )
        assert allowed is True


class TestAllGatesPass:
    """Test that all gates passing allows execution."""

    def test_all_gates_pass_allows_execution(self) -> None:
        """When every gate passes, the action is allowed."""
        cfg = SafetyConfig(
            dry_run=False,
            execution_enabled=True,
            kill_switch=False,
            tenant_allowlist=[],
            user_allowlist=[],
            action_allowlist=["CLOSE_INCIDENT"],
        )
        allowed, reasons = cfg.can_execute(
            "CLOSE_INCIDENT", "tenant-1", "alice@contoso.com", "Low",
        )
        assert allowed is True
        assert reasons == []

    def test_all_gates_fail_accumulates_reasons(self) -> None:
        """When every gate fails, all reasons are collected."""
        cfg = SafetyConfig(
            kill_switch=True,
            dry_run=True,
            execution_enabled=False,
            tenant_allowlist=["other-tenant"],
            user_allowlist=["other@contoso.com"],
            action_allowlist=["POST_COMMENT"],
        )
        allowed, reasons = cfg.can_execute(
            "DISABLE_ACCOUNT", "bad-tenant", "alice@contoso.com", "Low",
        )
        assert allowed is False
        assert len(reasons) == 6


class TestLogBlockedAction:
    """Test the audit logging method."""

    def test_log_blocked_action_format(self, capsys: object) -> None:
        """Blocked action log is valid JSON written to stderr."""
        import io
        import sys

        cfg = SafetyConfig()
        stderr_capture = io.StringIO()
        old_stderr = sys.stderr
        sys.stderr = stderr_capture
        try:
            cfg.log_blocked_action(
                "TEST_ACTION",
                ["reason1", "reason2"],
                {"incident_id": "INC-TEST"},
            )
        finally:
            sys.stderr = old_stderr

        line = stderr_capture.getvalue().strip()
        parsed = json.loads(line)
        assert parsed["event"] == "action_blocked"
        assert parsed["action_type"] == "TEST_ACTION"
        assert len(parsed["reasons"]) == 2
        assert parsed["context"]["incident_id"] == "INC-TEST"
        assert "timestamp" in parsed
