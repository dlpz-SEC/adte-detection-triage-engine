"""Shared pytest fixtures for ADTE tests."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from adte.config import SafetyConfig
from adte.intel.sigma_fp_registry import FPRegistry
from adte.models import NormalizedIncident, SentinelIncident
from adte.store.user_history import get_user_profile

# Ensure safety-related env vars don't leak between tests.
_SAFETY_ENV_VARS = [
    "ADTE_DRY_RUN",
    "ADTE_EXECUTION_ENABLED",
    "ADTE_KILL_SWITCH",
    "ADTE_TENANT_ALLOWLIST",
    "ADTE_USER_ALLOWLIST",
    "ADTE_ACTION_ALLOWLIST",
]


@pytest.fixture(autouse=True)
def _clean_safety_env() -> None:
    """Remove ADTE env vars before each test to ensure isolation."""
    for var in _SAFETY_ENV_VARS:
        os.environ.pop(var, None)


EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"


def _load_raw(filename: str) -> dict[str, Any]:
    """Load a raw JSON dict from the examples directory."""
    return json.loads((EXAMPLES_DIR / filename).read_text(encoding="utf-8"))


@pytest.fixture()
def raw_true_positive() -> dict[str, Any]:
    """Raw JSON for the impossible-travel + MFA-fatigue incident."""
    return _load_raw("incident_impossible_travel_mfa_fatigue.json")


@pytest.fixture()
def raw_false_positive() -> dict[str, Any]:
    """Raw JSON for the benign VPN-travel incident."""
    return _load_raw("incident_benign_vpn_travel.json")


@pytest.fixture()
def raw_ambiguous() -> dict[str, Any]:
    """Raw JSON for the ambiguous needs-human incident."""
    return _load_raw("incident_needs_human_ambiguous.json")


@pytest.fixture()
def incident_true_positive(raw_true_positive: dict[str, Any]) -> NormalizedIncident:
    """Normalised incident for the true-positive scenario."""
    return NormalizedIncident.from_sentinel(SentinelIncident(**raw_true_positive))


@pytest.fixture()
def incident_false_positive(raw_false_positive: dict[str, Any]) -> NormalizedIncident:
    """Normalised incident for the false-positive scenario."""
    return NormalizedIncident.from_sentinel(SentinelIncident(**raw_false_positive))


@pytest.fixture()
def incident_ambiguous(raw_ambiguous: dict[str, Any]) -> NormalizedIncident:
    """Normalised incident for the ambiguous scenario."""
    return NormalizedIncident.from_sentinel(SentinelIncident(**raw_ambiguous))


@pytest.fixture()
def fp_registry() -> FPRegistry:
    """Load the default false-positive registry."""
    return FPRegistry.load()
