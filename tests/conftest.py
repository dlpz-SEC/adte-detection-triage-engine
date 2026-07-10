"""Shared pytest fixtures for ADTE tests."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from adte.intel import threat_intel
from adte.intel.aggregator import ThreatIntelAggregator
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
    # Threat intel API keys — cleared between tests to keep mock fallback active.
    "ADTE_ABUSEIPDB_KEY",
    "ADTE_VT_API_KEY",
    "ADTE_OTX_KEY",
]


@pytest.fixture(autouse=True)
def _clean_safety_env() -> None:
    """Remove ADTE env vars and pin threat intel to mock before each test.

    Popping the env keys alone is not enough: any test that imports
    ``adte.server`` mid-suite re-runs ``load_dotenv`` (repopulating real keys
    from a local ``.env``), and the module-level threat-intel singleton keeps
    whatever mode it was first created in.  Resetting the singleton to a
    keyless (pure-mock) aggregator makes every test deterministic and
    network-free regardless of test ordering.
    """
    for var in _SAFETY_ENV_VARS:
        os.environ.pop(var, None)
    threat_intel._aggregator = ThreatIntelAggregator()
    # Clear the LLM response cache: tests reuse identical decision outputs
    # with different mocked API responses, so a warm cache would leak
    # summaries across tests.
    from adte.llm import assist

    assist._llm_cache.clear()
    # Disable per-route rate limits in tests: the limiter's in-memory counters
    # span the whole pytest process, so cumulative /api/triage POSTs across
    # test files would otherwise start returning 429 mid-suite.
    import sys

    server_module = sys.modules.get("adte.server")
    if server_module is not None:
        server_module.limiter.enabled = False


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
