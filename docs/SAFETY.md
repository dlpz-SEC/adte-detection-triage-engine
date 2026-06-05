# Safety Model

ADTE is a **triage engine, not an actuator**. Its primary safety guarantee is
architectural: the engine has no code path that mutates any external system. It
ingests alerts, scores them, and returns a verdict with a *recommended* action —
acting on that recommendation (disabling an account, revoking sessions, closing
an incident) is always performed by a human analyst or a downstream
SOAR/ticketing workflow, never by ADTE itself.

## Design Philosophy

1. **Recommend, never act** — There is no execution path. The strongest possible
   guarantee against an unintended automated response is the absence of any code
   that can perform one.
2. **Human-in-the-loop by default** — Every `medium_risk` and `high_risk` verdict
   sets `human_review_required: true` in the output. Low-risk verdicts are the
   only ones cleared for unattended auto-close by a downstream system.
3. **Determinism** — The same input always produces the same verdict. The LLM
   narrative layer is advisory only and can never change the verdict, risk score,
   confidence, or recommended action.
4. **Auditability** — Every verdict is persisted to the SQLite audit log
   (`adte/store/audit_log.py`) with timestamps, signal scores, and NIST 800-61
   phase alignment, so each decision is reviewable after the fact.

## Output safety fields

Each triage result carries a `safety` block (`engine._build_safety`) derived
purely from the verdict:

| Field | Meaning |
|-------|---------|
| `human_review_required` | `true` for any verdict above `low_risk` |
| `automated_actions_permitted` | `true` only for `high_risk` — a recommendation flag for downstream tooling, not an instruction ADTE executes |

These are advisory signals for whatever consumes the verdict; ADTE takes no
action on them.

## Reserved: execution-layer configuration (not currently enforced)

The following environment variables and the **Safety Gates** UI panel document
the *intended* gating model for a future automated-containment layer (see the
roadmap in `docs/PROJECT_PROGRESS.md`). **They are surfaced read-only and do not
gate anything today**, because ADTE performs no automated actions:

| Variable | Default | Reserved purpose |
|----------|---------|------------------|
| `ADTE_KILL_SWITCH` | `false` | Emergency halt for a future execution layer |
| `ADTE_DRY_RUN` | `true` | Global read-only mode for a future execution layer |
| `ADTE_EXECUTION_ENABLED` | `false` | Explicit opt-in for a future execution layer |
| `ADTE_TENANT_ALLOWLIST` | `""` | Reserved tenant scoping |
| `ADTE_USER_ALLOWLIST` | `""` | Reserved user scoping |
| `ADTE_ACTION_ALLOWLIST` | `CLOSE_INCIDENT,POST_COMMENT` | Reserved action allowlist |

If and when an execution layer is built, this is the configuration contract it is
expected to honour. Until then, treat these as documentation of intent, not
active controls.
