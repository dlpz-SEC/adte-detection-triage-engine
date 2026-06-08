"""Tests for the OCSF-inspired incident input schema migration.

Covers the new input contract:
- top-level ``severity`` is rejected (it is engine-assigned)
- per-event ``type`` is required
- ``auth_status`` / ``event_risk`` / ``source`` use the new vendor-neutral enums
- ``from_sentinel`` maps to the new field names and drops severity
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from adte.models import NormalizedIncident, SentinelIncident, SignInMetadata


def _valid_event(**overrides: Any) -> dict[str, Any]:
    """Return kwargs for a minimal valid ``SignInMetadata``."""
    base: dict[str, Any] = {
        "user_principal_name": "alice@contoso.com",
        "ip_address": "203.0.113.10",
        "type": "authentication",
        "timestamp": datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
    }
    base.update(overrides)
    return base


class TestSeverityRejection:
    """Severity is engine-assigned and must never be accepted on input."""

    def test_model_validate_rejects_severity(self) -> None:
        """A payload containing a top-level severity fails validation (→ 422)."""
        with pytest.raises(ValidationError, match="engine-assigned"):
            NormalizedIncident.model_validate({
                "incident_id": "INC-1",
                "user": "alice@contoso.com",
                "severity": "High",
            })

    def test_constructor_rejects_severity(self) -> None:
        """Direct construction with severity is rejected too."""
        with pytest.raises(ValidationError, match="engine-assigned"):
            NormalizedIncident(  # type: ignore[call-arg]
                incident_id="INC-1", user="alice@contoso.com", severity="High",
            )

    def test_severity_is_not_a_model_field(self) -> None:
        """NormalizedIncident no longer declares a severity field."""
        assert "severity" not in NormalizedIncident.model_fields


class TestEventTypeRequired:
    """Each event must carry an OCSF ``type``."""

    def test_missing_type_rejected(self) -> None:
        """Omitting the required type field fails validation."""
        kwargs = _valid_event()
        kwargs.pop("type")
        with pytest.raises(ValidationError):
            SignInMetadata(**kwargs)

    def test_invalid_type_rejected(self) -> None:
        """An out-of-enum type value is rejected."""
        with pytest.raises(ValidationError):
            SignInMetadata(**_valid_event(type="login"))

    @pytest.mark.parametrize("etype", ["authentication", "network", "process", "file"])
    def test_valid_types_accepted(self, etype: str) -> None:
        """All four OCSF event types are accepted."""
        ev = SignInMetadata(**_valid_event(type=etype))
        assert ev.type == etype


class TestAuthStatus:
    """auth_status uses the vendor-neutral enum and is optional."""

    def test_defaults_to_none(self) -> None:
        """Omitting auth_status yields None (no MFA outcome)."""
        ev = SignInMetadata(**_valid_event())
        assert ev.auth_status is None

    def test_old_vendor_value_rejected(self) -> None:
        """The old AAD value 'Denied' is no longer valid."""
        with pytest.raises(ValidationError):
            SignInMetadata(**_valid_event(auth_status="Denied"))

    @pytest.mark.parametrize("status", ["success", "failure", "challenge"])
    def test_valid_values_accepted(self, status: str) -> None:
        """The new auth_status enum values are accepted."""
        ev = SignInMetadata(**_valid_event(auth_status=status))
        assert ev.auth_status == status


class TestEventRisk:
    """event_risk replaces the AAD risk_state strings."""

    def test_defaults_to_none(self) -> None:
        """event_risk defaults to 'none'."""
        ev = SignInMetadata(**_valid_event())
        assert ev.event_risk == "none"

    def test_old_vendor_value_rejected(self) -> None:
        """The old AAD value 'atRisk' is no longer valid."""
        with pytest.raises(ValidationError):
            SignInMetadata(**_valid_event(event_risk="atRisk"))

    @pytest.mark.parametrize("risk", ["none", "suspicious", "high", "confirmed"])
    def test_valid_values_accepted(self, risk: str) -> None:
        """The new event_risk enum values are accepted."""
        ev = SignInMetadata(**_valid_event(event_risk=risk))
        assert ev.event_risk == risk


class TestSourceField:
    """Top-level source identifies the originating platform."""

    @pytest.mark.parametrize("src", ["azure_ad", "wazuh", "okta", "generic"])
    def test_valid_sources_accepted(self, src: str) -> None:
        """All four source enum values are accepted."""
        inc = NormalizedIncident(incident_id="INC-1", user="alice@contoso.com", source=src)
        assert inc.source == src

    def test_invalid_source_rejected(self) -> None:
        """An unknown source value is rejected."""
        with pytest.raises(ValidationError):
            NormalizedIncident(incident_id="INC-1", user="alice@contoso.com", source="aws")

    def test_source_defaults_to_generic(self) -> None:
        """Omitting source defaults to 'generic'."""
        inc = NormalizedIncident(incident_id="INC-1", user="alice@contoso.com")
        assert inc.source == "generic"


class TestEventsField:
    """The events collection replaces sign_in_events."""

    def test_events_field_present_and_legacy_absent(self) -> None:
        """NormalizedIncident exposes 'events' and no longer 'sign_in_events'."""
        ev = SignInMetadata(**_valid_event())
        inc = NormalizedIncident(
            incident_id="INC-1", user="alice@contoso.com", events=[ev],
        )
        assert len(inc.events) == 1
        assert "sign_in_events" not in NormalizedIncident.model_fields


class TestFromSentinel:
    """from_sentinel emits the new schema and drops severity."""

    def _raw(self) -> dict[str, Any]:
        return {
            "incident_id": "INC-SENT-1",
            "title": "Test incident",
            "source": "azure_ad",
            "created_time": "2025-01-01T12:00:00Z",
            "entities": [
                {"entity_type": "Account", "identifier": "alice@contoso.com", "metadata": {}}
            ],
            "alerts": [
                {
                    "alert_id": "A1",
                    "events": [
                        {
                            "user_principal_name": "alice@contoso.com",
                            "ip_address": "203.0.113.10",
                            "auth_status": "failure",
                            "event_risk": "suspicious",
                            "timestamp": "2025-01-01T12:00:00Z",
                        }
                    ],
                }
            ],
        }

    def test_maps_new_fields(self) -> None:
        """source carries through; type defaults; auth_status/event_risk map; no severity."""
        inc = NormalizedIncident.from_sentinel(SentinelIncident(**self._raw()))
        assert inc.source == "azure_ad"
        assert len(inc.events) == 1
        event = inc.events[0]
        assert event.type == "authentication"   # defaulted by from_sentinel
        assert event.auth_status == "failure"
        assert event.event_risk == "suspicious"
        assert "severity" not in NormalizedIncident.model_fields

    def test_sentinel_ignores_legacy_severity(self) -> None:
        """A raw Sentinel payload carrying severity is accepted (severity ignored)."""
        raw = self._raw()
        raw["severity"] = "High"  # real Sentinel data may still carry this
        inc = NormalizedIncident.from_sentinel(SentinelIncident(**raw))
        assert inc.source == "azure_ad"

    def test_legacy_sign_in_events_key_still_parsed(self) -> None:
        """from_sentinel falls back to the legacy 'sign_in_events' alert key."""
        raw = self._raw()
        raw["alerts"][0]["sign_in_events"] = raw["alerts"][0].pop("events")
        inc = NormalizedIncident.from_sentinel(SentinelIncident(**raw))
        assert len(inc.events) == 1
