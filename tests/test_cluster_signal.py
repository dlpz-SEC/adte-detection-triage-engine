"""Engine-level tests for the additive cluster_context signal (Phase 31).

Constructs TriageEngine directly with a ClusterContext value object — no
database involved.  Covers: solo byte-parity, the integer points curve,
confidence ramp, rationale contents, output shape, additive uplift + cap,
and monotonicity (context is an aggravator, never a mitigator).
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from adte.decision_policy import ClusterContext
from adte.engine import TriageEngine
from adte.intel.sigma_fp_registry import FPRegistry
from adte.models import GeoLocation, NormalizedIncident, SignInMetadata
from adte.store.user_history import get_user_profile


def _make_sign_in(
    *,
    ip: str,
    device_id: str = "",
    auth_status: str | None = None,
    location: GeoLocation | None = None,
    ts: str = "2024-06-15T12:00:00+00:00",
) -> SignInMetadata:
    """Helper: build a minimal SignInMetadata."""
    return SignInMetadata(
        user_principal_name="wazuh-host@test.local",
        ip_address=ip,
        type="authentication",
        location=location,
        device_id=device_id,
        device_name="test-device",
        auth_status=auth_status,  # type: ignore[arg-type]
        timestamp=datetime.fromisoformat(ts),
    )


def _make_incident(sign_ins: list[SignInMetadata]) -> NormalizedIncident:
    """Helper: wrap events into a NormalizedIncident."""
    return NormalizedIncident(
        incident_id="TEST-CLUSTER-001",
        user="wazuh-host@test.local",
        events=sign_ins,
        created_time=datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc),
    )


def _make_context(
    siblings: int = 1,
    *,
    tactics: int = 0,
    kill_chain: bool = False,
    max_risk: float = 60.0,
) -> ClusterContext:
    """Helper: build a ClusterContext snapshot."""
    return ClusterContext(
        case_id="CASE-20260711-abc123",
        sibling_count=siblings,
        distinct_sibling_tactics=tactics,
        kill_chain_detected=kill_chain,
        max_sibling_risk_score=max_risk,
        window_minutes=60,
    )


def _wazuh_skip_incident() -> NormalizedIncident:
    """The test_engine ==78 scenario: no geo, no MFA, C2 IP, unknown device."""
    return _make_incident([
        _make_sign_in(
            ip="198.51.100.23",  # malicious C2 IP in the mock TI feed
            device_id="unknown-wazuh-device-xyz",
            auth_status=None,
            location=None,
        )
    ])


def _run(
    incident: NormalizedIncident,
    fp_registry: FPRegistry,
    context: ClusterContext | None = None,
) -> tuple[TriageEngine, dict]:
    """Run the enrich→score→decide pipeline and return (engine, output)."""
    profile = get_user_profile(incident.user)
    engine = TriageEngine(
        incident, profile, fp_registry, cluster_context=context
    )
    output = engine.enrich().score().decide().to_output()
    return engine, output


class TestSoloParity:
    def test_no_context_output_identical_to_default_construction(
        self, fp_registry: FPRegistry
    ) -> None:
        """cluster_context=None must be a byte-level no-op on the output."""
        incident = _wazuh_skip_incident()
        profile = get_user_profile(incident.user)

        explicit = TriageEngine(incident, profile, fp_registry, cluster_context=None)
        default = TriageEngine(incident, profile, fp_registry)
        out_explicit = explicit.enrich().score().decide().to_output()
        out_default = default.enrich().score().decide().to_output()

        for body in (out_explicit, out_default):
            body["report"]["timestamp"] = "<normalized>"
        assert out_explicit == out_default

    def test_solo_output_has_no_cluster_entry(self, fp_registry: FPRegistry) -> None:
        """N/A semantics: without context the signal never enters the output."""
        _, output = _run(_wazuh_skip_incident(), fp_registry)
        assert len(output["rationale"]) == 5
        assert all(r["signal"] != "cluster_context" for r in output["rationale"])
        assert "cluster_context" not in output["report"]["signal_summary"]

    def test_solo_wazuh_78_unchanged(self, fp_registry: FPRegistry) -> None:
        """Belt-and-braces duplicate of the Phase-31 parity claim."""
        _, output = _run(_wazuh_skip_incident(), fp_registry)
        assert output["risk_score"] == 78
        assert output["verdict"] == "high_risk"


class TestPointsCurve:
    @pytest.mark.parametrize(
        ("siblings", "kill_chain", "expected"),
        [
            (1, False, 5.0),
            (2, False, 8.0),
            (3, False, 10.0),
            (7, False, 10.0),   # volume ramp caps at 10
            (1, True, 10.0),
            (2, True, 13.0),
            (3, True, 15.0),    # weight cap
            (9, True, 15.0),
        ],
    )
    def test_curve_points(
        self,
        fp_registry: FPRegistry,
        siblings: int,
        kill_chain: bool,
        expected: float,
    ) -> None:
        engine, _ = _run(
            _wazuh_skip_incident(),
            fp_registry,
            _make_context(siblings, kill_chain=kill_chain),
        )
        assert engine._signals["cluster_context"][0] == expected

    @pytest.mark.parametrize(
        ("siblings", "kill_chain", "expected"),
        [
            (1, False, 0.6),
            (2, False, 0.7),
            (4, False, 0.9),
            (6, False, 0.9),    # confidence ramp caps at 0.9
            (1, True, 0.7),
            (5, True, 1.0),     # 0.9 + 0.1 caps at 1.0
        ],
    )
    def test_confidence_ramp(
        self,
        fp_registry: FPRegistry,
        siblings: int,
        kill_chain: bool,
        expected: float,
    ) -> None:
        engine, _ = _run(
            _wazuh_skip_incident(),
            fp_registry,
            _make_context(siblings, kill_chain=kill_chain),
        )
        assert engine._signals["cluster_context"][2] == pytest.approx(expected)


class TestAdditiveUplift:
    def test_one_sibling_boosts_78_to_83(self, fp_registry: FPRegistry) -> None:
        """The core score is computed exactly as solo, then +5 on top."""
        _, output = _run(_wazuh_skip_incident(), fp_registry, _make_context(1))
        assert output["risk_score"] == 83
        assert output["verdict"] == "high_risk"

    def test_kill_chain_boosts_78_to_88(self, fp_registry: FPRegistry) -> None:
        _, output = _run(
            _wazuh_skip_incident(), fp_registry, _make_context(1, kill_chain=True)
        )
        assert output["risk_score"] == 88

    def test_uplift_capped_at_100(
        self, incident_true_positive: NormalizedIncident, fp_registry: FPRegistry
    ) -> None:
        """A near-max core score + max context never exceeds 100."""
        _, solo = _run(incident_true_positive, fp_registry)
        _, boosted = _run(
            incident_true_positive, fp_registry, _make_context(5, kill_chain=True)
        )
        assert solo["risk_score"] > 85  # sanity: the true-positive example is hot
        assert boosted["risk_score"] == 100
        assert boosted["risk_score"] == min(100, solo["risk_score"] + 15)

    @pytest.mark.parametrize("kill_chain", [False, True])
    @pytest.mark.parametrize("siblings", [1, 2, 3])
    def test_correlated_never_below_solo(
        self, fp_registry: FPRegistry, siblings: int, kill_chain: bool
    ) -> None:
        """Monotonicity doctrine: context is an aggravator, never a mitigator."""
        for incident in (
            _wazuh_skip_incident(),      # skip-heavy: the old 78→67 anomaly case
            _make_incident([_make_sign_in(ip="10.0.0.1", auth_status="success")]),
        ):
            _, solo = _run(incident, fp_registry)
            _, boosted = _run(
                incident,
                fp_registry,
                _make_context(siblings, kill_chain=kill_chain),
            )
            assert boosted["risk_score"] > solo["risk_score"]
            assert boosted["risk_score"] <= 100


class TestOutputShape:
    def test_context_adds_sixth_rationale_and_summary_entry(
        self, fp_registry: FPRegistry
    ) -> None:
        _, output = _run(_wazuh_skip_incident(), fp_registry, _make_context(2))
        assert len(output["rationale"]) == 6
        entry = next(
            r for r in output["rationale"] if r["signal"] == "cluster_context"
        )
        assert entry["score"] == 8.0
        summary = output["report"]["signal_summary"]["cluster_context"]
        assert summary["max_possible"] == 15
        assert summary["score"] == 8.0

    def test_rationale_names_case_count_window(
        self, fp_registry: FPRegistry
    ) -> None:
        engine, _ = _run(
            _wazuh_skip_incident(),
            fp_registry,
            _make_context(2, tactics=3, kill_chain=True, max_risk=78.0),
        )
        detail = engine._signals["cluster_context"][1]
        assert "CASE-20260711-abc123" in detail
        assert "2 related alert(s)" in detail
        assert "60 min" in detail
        assert "3 distinct ATT&CK tactics" in detail
        assert "kill-chain progression detected" in detail
        assert "max sibling risk 78" in detail

    def test_rationale_omits_conditional_clauses(
        self, fp_registry: FPRegistry
    ) -> None:
        """Tactics clause needs >1 tactic; kill-chain clause needs detection."""
        engine, _ = _run(
            _wazuh_skip_incident(),
            fp_registry,
            _make_context(1, tactics=1, kill_chain=False),
        )
        detail = engine._signals["cluster_context"][1]
        assert "distinct ATT&CK tactics" not in detail
        assert "kill-chain" not in detail

    def test_context_counts_toward_confidence_coverage(
        self, fp_registry: FPRegistry
    ) -> None:
        """Correlated coverage is present/total over 6 applicable signals."""
        incident = _wazuh_skip_incident()
        solo_engine, solo = _run(incident, fp_registry)
        boosted_engine, boosted = _run(incident, fp_registry, _make_context(1))
        assert len(solo_engine._signals) == 5
        assert len(boosted_engine._signals) == 6
        # Both runs: travel + mfa skipped. Solo coverage 3/5; boosted 4/6 — the
        # cluster signal enters the coverage denominator, so the correlated
        # verdict is measurably more confident. Exact values pinned so a
        # regression in signals_total/avg_confidence on the boosted path fails.
        assert solo["confidence"] == 48
        assert boosted["confidence"] == 49
        assert boosted["confidence"] > solo["confidence"]
