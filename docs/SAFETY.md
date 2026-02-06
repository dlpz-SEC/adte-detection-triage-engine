# Safety Controls

ADTE implements a **defence-in-depth safety model** with six independent gates that must all pass before any automated action executes. This ensures that misconfiguration of a single variable cannot lead to unintended automated response.

## Design Philosophy

1. **Default deny** — A fresh deployment with no environment variables configured will refuse to execute any automated actions
2. **Non-short-circuiting evaluation** — All six gates are always evaluated so the audit log captures every reason for denial, not just the first
3. **Audit everything** — Blocked actions are logged as structured JSON to stderr, satisfying NIST 800-61 audit trail requirements
4. **Emergency halt** — The kill switch provides a single-variable mechanism to halt all automated actions instantly

## Gate Evaluation Order

Gates are evaluated in the following order. All must pass for an action to execute:

```
Request: "CLOSE_INCIDENT for tenant-a, alice@contoso.com, severity=High"
    │
    ▼
┌──────────────────────────────────────────────────────────────┐
│ Gate 1: KILL SWITCH                                          │
│   ADTE_KILL_SWITCH=true → BLOCK (all actions halted)         │
│   ADTE_KILL_SWITCH=false → pass                              │
├──────────────────────────────────────────────────────────────┤
│ Gate 2: DRY RUN                                              │
│   ADTE_DRY_RUN=true (default) → BLOCK (read-only mode)      │
│   ADTE_DRY_RUN=false → pass                                 │
├──────────────────────────────────────────────────────────────┤
│ Gate 3: EXECUTION ENABLED                                    │
│   ADTE_EXECUTION_ENABLED=false (default) → BLOCK            │
│   ADTE_EXECUTION_ENABLED=true → pass                         │
├──────────────────────────────────────────────────────────────┤
│ Gate 4: TENANT ALLOWLIST                                     │
│   ADTE_TENANT_ALLOWLIST="" (empty, default) → pass (all)     │
│   ADTE_TENANT_ALLOWLIST="tenant-a" → pass if tenant matches  │
│   ADTE_TENANT_ALLOWLIST="tenant-b" → BLOCK (wrong tenant)    │
├──────────────────────────────────────────────────────────────┤
│ Gate 5: USER / SEVERITY                                      │
│   User in ADTE_USER_ALLOWLIST → pass                         │
│   Severity is High or Critical → pass (bypass allowlist)     │
│   Otherwise → BLOCK                                          │
├──────────────────────────────────────────────────────────────┤
│ Gate 6: ACTION ALLOWLIST                                     │
│   Action in ADTE_ACTION_ALLOWLIST → pass                     │
│   Default: ["CLOSE_INCIDENT", "POST_COMMENT"]                │
│   DISABLE_ACCOUNT is NOT in default list → BLOCK             │
└──────────────────────────────────────────────────────────────┘
    │
    ▼
 All gates passed → EXECUTE action
```

## Gate Details

### Gate 1: Kill Switch (`ADTE_KILL_SWITCH`)

| Setting | Behavior |
|---------|----------|
| `false` (default) | Normal operation |
| `true` | **All automated actions immediately blocked**, regardless of all other settings |

**When to use:** Activate during an active incident response where you need to halt ADTE's automated actions while preserving its triage/scoring capability. The engine will continue to produce verdicts and reports, but no containment actions will execute.

```bash
# Emergency halt
export ADTE_KILL_SWITCH=true

# Resume normal operation
export ADTE_KILL_SWITCH=false
```

### Gate 2: Dry Run (`ADTE_DRY_RUN`)

| Setting | Behavior |
|---------|----------|
| `true` (default) | Read-only mode — engine scores and reports but never writes |
| `false` | Write operations permitted (subject to remaining gates) |

**Purpose:** The default-on dry run ensures that first-time deployments never accidentally execute actions. Operators must explicitly disable it.

### Gate 3: Execution Enabled (`ADTE_EXECUTION_ENABLED`)

| Setting | Behavior |
|---------|----------|
| `false` (default) | Automated actions require explicit opt-in |
| `true` | Actions permitted (subject to remaining gates) |

**Purpose:** A second confirmation gate beyond dry run. To execute any action, operators must both disable dry run AND enable execution — a deliberate two-step process that prevents accidental activation.

### Gate 4: Tenant Allowlist (`ADTE_TENANT_ALLOWLIST`)

| Setting | Behavior |
|---------|----------|
| `""` (empty, default) | All tenants permitted (open gate) |
| `"tenant-a,tenant-b"` | Only listed tenants permitted |

**Purpose:** In multi-tenant environments, restricts which Azure tenants ADTE is allowed to take actions in. Prevents a misconfigured deployment from modifying incidents in the wrong tenant.

### Gate 5: User / Severity (`ADTE_USER_ALLOWLIST`)

| Setting | Behavior |
|---------|----------|
| `""` (empty, default) | All users permitted (open gate) |
| `"alice@contoso.com,bob@contoso.com"` | Only listed users' incidents can be actioned, UNLESS severity is High or Critical |

**Severity bypass:** High and Critical severity incidents always pass this gate, even if the user is not on the allowlist. This ensures that confirmed high-severity compromises are never blocked by an incomplete allowlist.

### Gate 6: Action Allowlist (`ADTE_ACTION_ALLOWLIST`)

| Setting | Behavior |
|---------|----------|
| Default: `"CLOSE_INCIDENT,POST_COMMENT"` | Only low-impact actions permitted |
| `"CLOSE_INCIDENT,POST_COMMENT,REVOKE_SESSIONS"` | Add moderate-impact actions |
| `"CLOSE_INCIDENT,POST_COMMENT,REVOKE_SESSIONS,FORCE_PASSWORD_RESET,DISABLE_ACCOUNT"` | All actions permitted |

**Available action types:**

| Action Type | Impact | Default Allowed | Adapter |
|-------------|--------|-----------------|---------|
| `POST_COMMENT` | Low | Yes | SentinelAdapter |
| `CLOSE_INCIDENT` | Low | Yes | SentinelAdapter |
| `REVOKE_SESSIONS` | Moderate | No | EntraIDAdapter |
| `FORCE_PASSWORD_RESET` | High | No | EntraIDAdapter |
| `DISABLE_ACCOUNT` | Critical | No | EntraIDAdapter |

## Example Scenarios

### Scenario 1: Fresh deployment (all defaults)

```
ADTE_KILL_SWITCH=false
ADTE_DRY_RUN=true          ← blocks
ADTE_EXECUTION_ENABLED=false ← blocks
```

**Result:** All actions blocked. Two reasons logged:
1. `DRY_RUN is enabled — write/mutate operations blocked`
2. `EXECUTION_ENABLED is false — automated actions require explicit opt-in`

### Scenario 2: Read-only scoring with execution disabled

```
ADTE_DRY_RUN=true
ADTE_EXECUTION_ENABLED=false
```

**Result:** Engine produces verdicts and reports. All actions blocked. This is the recommended mode for initial testing and validation.

### Scenario 3: Production — low-impact actions only

```
ADTE_DRY_RUN=false
ADTE_EXECUTION_ENABLED=true
ADTE_TENANT_ALLOWLIST="your-tenant-id"
ADTE_ACTION_ALLOWLIST="CLOSE_INCIDENT,POST_COMMENT"
```

**Result:** Engine can auto-close benign incidents and post analyst comments, but cannot revoke sessions, reset passwords, or disable accounts. Only works in the specified tenant.

### Scenario 4: Production — full containment for specific users

```
ADTE_DRY_RUN=false
ADTE_EXECUTION_ENABLED=true
ADTE_TENANT_ALLOWLIST="your-tenant-id"
ADTE_USER_ALLOWLIST="alice@contoso.com,bob@contoso.com"
ADTE_ACTION_ALLOWLIST="CLOSE_INCIDENT,POST_COMMENT,REVOKE_SESSIONS,FORCE_PASSWORD_RESET"
```

**Result:** Full containment actions (except account disable) for alice and bob. High/Critical severity incidents for ANY user also pass the user gate.

### Scenario 5: Emergency — kill switch activated

```
ADTE_KILL_SWITCH=true
ADTE_DRY_RUN=false
ADTE_EXECUTION_ENABLED=true
```

**Result:** All actions blocked despite execution being enabled. Kill switch overrides everything.

### Scenario 6: Attempt to disable account (not in default allowlist)

```
ADTE_DRY_RUN=false
ADTE_EXECUTION_ENABLED=true
# ADTE_ACTION_ALLOWLIST not set (defaults to CLOSE_INCIDENT, POST_COMMENT)
```

Action: `DISABLE_ACCOUNT`

**Result:** Blocked. Reason: `Action 'DISABLE_ACCOUNT' not in ACTION_ALLOWLIST (CLOSE_INCIDENT, POST_COMMENT)`

## Audit Logging

Every blocked action is logged as structured JSON to **stderr**:

```json
{
  "timestamp": "2025-01-15T10:30:00.000000+00:00",
  "event": "action_blocked",
  "action_type": "DISABLE_ACCOUNT",
  "reasons": [
    "Action 'DISABLE_ACCOUNT' not in ACTION_ALLOWLIST (CLOSE_INCIDENT, POST_COMMENT)"
  ],
  "context": {
    "user_upn": "alice@contoso.com",
    "severity": "High",
    "tenant_id": "tenant-1"
  }
}
```

**Fields:**
- `timestamp` — ISO 8601 UTC timestamp
- `event` — Always `"action_blocked"` for blocked actions
- `action_type` — The action that was attempted
- `reasons` — List of all gate failures (non-short-circuiting)
- `context` — Incident-specific metadata for audit correlation

In production, pipe stderr to your SIEM or log aggregation platform:

```bash
python -m adte triage -i incident.json 2>> /var/log/adte/blocked_actions.jsonl
```

## Configuration Reference

All settings are configured via environment variables with the `ADTE_` prefix, or via a `.env` file.

```bash
# Gate 1: Emergency halt
ADTE_KILL_SWITCH=false

# Gate 2: Read-only mode (default: true — blocks all writes)
ADTE_DRY_RUN=true

# Gate 3: Explicit execution opt-in (default: false)
ADTE_EXECUTION_ENABLED=false

# Gate 4: Comma-separated tenant IDs (empty = all tenants)
ADTE_TENANT_ALLOWLIST=

# Gate 5: Comma-separated UPNs (empty = all users; High/Critical bypass)
ADTE_USER_ALLOWLIST=

# Gate 6: Comma-separated action types
ADTE_ACTION_ALLOWLIST=CLOSE_INCIDENT,POST_COMMENT
```
