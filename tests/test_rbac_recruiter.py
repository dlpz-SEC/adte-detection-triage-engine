"""RBAC alias-key resolution — the recruiter demo passkey.

The recruiter key is a public demo credential that grants analyst privileges
under its own env var (ADTE_API_KEY_RECRUITER), so it can be rotated or revoked
without touching the real per-tier analyst key. These tests pin that contract.
"""

from __future__ import annotations

import pytest

from adte import server as srv


def test_recruiter_key_resolves_to_analyst(monkeypatch: pytest.MonkeyPatch) -> None:
    """A key set in ADTE_API_KEY_RECRUITER resolves to the analyst role."""
    monkeypatch.delenv("ADTE_API_KEY_ANALYST", raising=False)
    monkeypatch.setenv("ADTE_API_KEY_RECRUITER", "recruiter-demo-key")
    assert srv._resolve_role("recruiter-demo-key") == "analyst"


def test_recruiter_key_is_distinct_from_analyst_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Recruiter and analyst keys are separate credentials, both -> analyst.

    Rotating one must not affect the other; here they coexist with different
    values and each independently resolves to the analyst role.
    """
    monkeypatch.setenv("ADTE_API_KEY_ANALYST", "real-analyst-key")
    monkeypatch.setenv("ADTE_API_KEY_RECRUITER", "public-recruiter-key")
    assert srv._resolve_role("real-analyst-key") == "analyst"
    assert srv._resolve_role("public-recruiter-key") == "analyst"


def test_recruiter_key_cannot_reach_higher_roles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The alias grants analyst only — never senior_analyst or admin."""
    monkeypatch.setenv("ADTE_API_KEY_ADMIN", "the-admin-key")
    monkeypatch.setenv("ADTE_API_KEY_RECRUITER", "the-recruiter-key")
    # The recruiter value resolves to analyst, not admin.
    assert srv._resolve_role("the-recruiter-key") == "analyst"
    # And it is not accepted as the admin key.
    assert srv._resolve_role("the-recruiter-key") != "admin"


def test_recruiter_key_alone_enables_secured_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Setting only the recruiter key still counts as configured (not demo)."""
    for env in (
        "ADTE_API_KEY_ADMIN",
        "ADTE_API_KEY_SENIOR",
        "ADTE_API_KEY_ANALYST",
        "ADTE_API_KEY_READONLY",
    ):
        monkeypatch.delenv(env, raising=False)
    monkeypatch.setenv("ADTE_API_KEY_RECRUITER", "only-the-recruiter-key")
    assert srv._any_keys_configured() is True


def test_unknown_key_still_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unmatched key resolves to None even with the recruiter alias set."""
    monkeypatch.setenv("ADTE_API_KEY_RECRUITER", "the-recruiter-key")
    assert srv._resolve_role("some-other-value") is None
