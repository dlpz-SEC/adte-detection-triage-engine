# CLAUDE.md — ADTE Project Conventions

## Project Overview
Automated Detection Triage Engine (ADTE) for Microsoft Sentinel.
Ingests Sentinel incidents, enriches with context, and applies triage decisions.

## Standards
- **NIST 800-61**: All incident handling logic and documentation must follow
  NIST SP 800-61 Rev. 2 (Computer Security Incident Handling Guide).
  - Triage decisions must reference the phase they belong to:
    Preparation, Detection & Analysis, Containment/Eradication/Recovery, Post-Incident Activity.
  - Audit trails must capture who/what/when/why for every automated action.

## Code Conventions
- **Type hints required** on all function signatures and return types.
- **All functions must have docstrings** (Google-style).
- Python 3.11+ required.
- Use `pydantic` models for all data structures crossing module boundaries.
- Keep modules focused: one responsibility per file.

## Safety
- `ADTE_KILL_SWITCH=true` must immediately halt all automated actions.
- `ADTE_DRY_RUN=true` (default) prevents any write/mutate operations.
- `ADTE_EXECUTION_ENABLED` must be explicitly set to `true` to allow actions.

## Testing
- Run tests: `pytest`
- All new code must have corresponding tests in `tests/`.
