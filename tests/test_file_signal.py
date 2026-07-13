"""Engine-level tests for the additive file_reputation signal (Phase 32).

Constructs TriageEngine directly with file-bearing incidents.  Covers:
non-file byte-parity, the evidence-tier points curve (embedded VT verdict,
ADTE hash lookup, unverified-confirmed), additive uplift + cap, monotonicity
(malware is an aggravator, never a mitigator), the both-additives stack,
recommended-action extension, conditional evidence keys, and the enrich()
embedded-verdict-wins / lookup-bound / malformed-hash behaviour.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

import adte.engine as eng
from adte.decision_policy import ClusterContext
from adte.engine import TriageEngine
from adte.intel.sigma_fp_registry import FPRegistry
from adte.models import FileArtifact, NormalizedIncident, SignInMetadata
from adte.store.user_history import get_user_profile

_EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
_SUSPICIOUS_SHA256 = (  # sha256("test") — the mock "suspicious" (0.45) entry
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
)
_CLEAN_SHA256 = "a" * 64  # not in the mock table → clean lookup


def _file_event(
    *,
    path: str = "/tmp/malware/sample",
    sha256: str = "",
    vt_positives: int | None = None,
    vt_total: int | None = None,
    vt_malicious: bool | None = None,
    event_risk: str = "none",
    ip: str = "192.168.1.77",
    device_id: str = "novel-device-xyz",
    ts: str = "2024-06-15T12:00:00+00:00",
) -> SignInMetadata:
    """Build a file-type event with an attached FileArtifact."""
    return SignInMetadata(
        user_principal_name="wazuh-host@test.local",
        ip_address=ip,
        type="file",
        location=None,
        device_id=device_id,
        device_name="ubuntu-agent",
        auth_status=None,
        event_risk=event_risk,  # type: ignore[arg-type]
        file=FileArtifact(
            path=path,
            sha256=sha256,
            fim_action="added",
            vt_positives=vt_positives,
            vt_total=vt_total,
            vt_malicious=vt_malicious,
        ),
        timestamp=datetime.fromisoformat(ts),
    )


def _auth_event(*, ip: str = "198.51.100.23") -> SignInMetadata:
    """A non-file auth event (malicious mock C2 IP, no geo, no MFA)."""
    return SignInMetadata(
        user_principal_name="wazuh-host@test.local",
        ip_address=ip,
        type="authentication",
        location=None,
        device_id="unknown-wazuh-device-xyz",
        auth_status=None,
        timestamp=datetime.fromisoformat("2024-06-15T12:00:00+00:00"),
    )


def _incident(events: list[SignInMetadata], iid: str = "TEST-FILE-001") -> NormalizedIncident:
    """Wrap events into a NormalizedIncident."""
    return NormalizedIncident(
        incident_id=iid,
        user="wazuh-host@test.local",
        source="wazuh",
        events=events,
        created_time=datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc),
    )


def _run(
    incident: NormalizedIncident,
    fp_registry: FPRegistry,
    context: ClusterContext | None = None,
) -> dict:
    """Run enrich→score→decide→to_output and return the output dict."""
    profile = get_user_profile(incident.user)
    engine = TriageEngine(incident, profile, fp_registry, cluster_context=context)
    return engine.enrich().score().decide().to_output()


def _entry(output: dict, signal: str) -> dict | None:
    """Return the rationale entry for a signal, or None."""
    return next((r for r in output["rationale"] if r["signal"] == signal), None)


class TestNonFileParity:
    def test_non_file_alert_has_no_file_signal(self, fp_registry: FPRegistry) -> None:
        """N/A semantics: without file evidence the signal never registers."""
        output = _run(_incident([_auth_event()]), fp_registry)
        assert _entry(output, "file_reputation") is None
        assert len(output["rationale"]) == 5
        assert "file_reputation" not in output["report"]["signal_summary"]

    def test_non_file_alert_has_no_file_evidence_keys(
        self, fp_registry: FPRegistry
    ) -> None:
        """Evidence must not gain file keys on a non-file alert (parity trap)."""
        output = _run(_incident([_auth_event()]), fp_registry)
        assert "files" not in output["evidence"]
        assert "file_reputation" not in output["evidence"]

    def test_non_file_actions_unextended(self, fp_registry: FPRegistry) -> None:
        """Malware actions never appear without file evidence."""
        output = _run(_incident([_auth_event()]), fp_registry)
        assert "quarantine_file" not in output["actions"]


class TestPointsCurve:
    @pytest.mark.parametrize(
        ("kwargs", "expected_points"),
        [
            (dict(vt_positives=58, vt_total=72), 40.0),          # ratio 0.8 ≥ .5
            (dict(vt_positives=1, vt_total=72, vt_malicious=True), 40.0),  # flag wins
            (dict(vt_positives=10, vt_total=72), 20.0),          # 0 < ratio < .5
            (dict(vt_positives=0, vt_total=72), 0.0),            # clean, registered
            (dict(sha256=_EICAR_SHA256), 40.0),                  # lookup malicious
            (dict(sha256=_SUSPICIOUS_SHA256), 20.0),             # lookup 0.45
            (dict(sha256=_CLEAN_SHA256), 0.0),                   # lookup clean
            (dict(event_risk="confirmed"), 15.0),                # confirmed, no hash
        ],
    )
    def test_tier_points(
        self, fp_registry: FPRegistry, kwargs: dict, expected_points: float
    ) -> None:
        """Each evidence tier awards the documented points and registers."""
        output = _run(_incident([_file_event(**kwargs)]), fp_registry)
        entry = _entry(output, "file_reputation")
        assert entry is not None, "signal must register for any file evidence"
        assert entry["score"] == expected_points

    def test_best_evidence_across_events(self, fp_registry: FPRegistry) -> None:
        """The strongest file event drives the score (best-of)."""
        events = [
            _file_event(path="/a", vt_positives=10, vt_total=72),   # 20
            _file_event(path="/b", vt_positives=58, vt_total=72),   # 40
        ]
        output = _run(_incident(events), fp_registry)
        assert _entry(output, "file_reputation")["score"] == 40.0

    def test_points_capped_at_weight(self, fp_registry: FPRegistry) -> None:
        """A 100% ratio never exceeds the 40-point weight."""
        output = _run(
            _incident([_file_event(vt_positives=72, vt_total=72)]), fp_registry
        )
        assert _entry(output, "file_reputation")["score"] == 40.0


class TestAdditiveUplift:
    def test_confirmed_malware_reaches_high_risk(self, fp_registry: FPRegistry) -> None:
        """Canonical 87105 case: core 33 (in-hours) + 40 = 73 → high_risk."""
        output = _run(
            _incident([_file_event(vt_positives=58, vt_total=72)]), fp_registry
        )
        assert output["risk_score"] == 73
        assert output["verdict"] == "high_risk"

    def test_out_of_hours_core_plus_forty(self, fp_registry: FPRegistry) -> None:
        """Out-of-hours core 56 + 40 = 96."""
        output = _run(
            _incident(
                [
                    _file_event(
                        vt_positives=58,
                        vt_total=72,
                        ts="2024-06-15T03:00:00+00:00",
                    )
                ]
            ),
            fp_registry,
        )
        assert output["risk_score"] == 96

    def test_score_capped_at_100(self, fp_registry: FPRegistry) -> None:
        """A malicious C2 IP + novel device + malware exceeds 100 → capped."""
        event = _file_event(vt_positives=58, vt_total=72, ip="198.51.100.23")
        output = _run(_incident([event]), fp_registry)
        assert output["risk_score"] == 100

    def test_clean_file_does_not_lower_score(self, fp_registry: FPRegistry) -> None:
        """Monotonicity: a clean scan registers 0 points, never a reduction."""
        with_clean = _run(
            _incident([_file_event(sha256=_CLEAN_SHA256)]), fp_registry
        )
        # The core-only score for the same skip profile is 33 (device 15/45).
        assert with_clean["risk_score"] == 33
        entry = _entry(with_clean, "file_reputation")
        assert entry is not None and entry["score"] == 0.0


class TestBothAdditives:
    def test_file_and_cluster_stack_under_cap(self, fp_registry: FPRegistry) -> None:
        """Cluster (+5) then file (+40) both apply: 33 → 38 → 78."""
        ctx = ClusterContext(
            case_id="CASE-20260712-abc123",
            sibling_count=1,
            distinct_sibling_tactics=0,
            kill_chain_detected=False,
            max_sibling_risk_score=60.0,
            window_minutes=60,
        )
        output = _run(
            _incident([_file_event(vt_positives=58, vt_total=72)]), fp_registry, ctx
        )
        assert output["risk_score"] == 78
        assert _entry(output, "cluster_context") is not None
        assert _entry(output, "file_reputation") is not None
        assert len(output["rationale"]) == 7  # 5 core + cluster + file


class TestActions:
    def test_high_risk_malware_actions(self, fp_registry: FPRegistry) -> None:
        """High-risk malware appends all four recommendations incl. isolate."""
        output = _run(
            _incident([_file_event(vt_positives=58, vt_total=72)]), fp_registry
        )
        for action in (
            "quarantine_file",
            "preserve_forensic_copy",
            "hash_sweep_fleet",
            "isolate_host",
        ):
            assert action in output["actions"]

    def test_non_high_malware_omits_isolate_host(self, fp_registry: FPRegistry) -> None:
        """A 20-point suspicious file that stays below high_risk: no isolate."""
        output = _run(
            _incident([_file_event(vt_positives=10, vt_total=72)]), fp_registry
        )
        assert output["verdict"] != "high_risk"
        assert "quarantine_file" in output["actions"]
        assert "isolate_host" not in output["actions"]

    def test_clean_file_no_action_extension(self, fp_registry: FPRegistry) -> None:
        """A clean scan (0 points) does not add malware recommendations."""
        output = _run(_incident([_file_event(sha256=_CLEAN_SHA256)]), fp_registry)
        assert "quarantine_file" not in output["actions"]

    def test_base_actions_preserved(self, fp_registry: FPRegistry) -> None:
        """The verdict-keyed base action list is unchanged, then extended."""
        output = _run(
            _incident([_file_event(vt_positives=58, vt_total=72)]), fp_registry
        )
        # high_risk base list still leads.
        assert output["actions"][:4] == [
            "disable_account",
            "revoke_sessions",
            "notify_soc_tier2",
            "create_ticket_p1",
        ]


class TestEvidence:
    def test_files_key_present_with_file_evidence(
        self, fp_registry: FPRegistry
    ) -> None:
        """A file incident emits evidence.files with path + hashes."""
        output = _run(
            _incident([_file_event(vt_positives=58, vt_total=72, path="/tmp/x")]),
            fp_registry,
        )
        assert "files" in output["evidence"]
        assert output["evidence"]["files"][0]["path"] == "/tmp/x"
        assert output["evidence"]["files"][0]["vt_positives"] == 58

    def test_file_reputation_key_only_when_looked_up(
        self, fp_registry: FPRegistry
    ) -> None:
        """evidence.file_reputation appears only when a lookup ran."""
        embedded = _run(
            _incident([_file_event(vt_positives=58, vt_total=72)]), fp_registry
        )
        assert "file_reputation" not in embedded["evidence"]  # embedded → no lookup

        looked_up = _run(_incident([_file_event(sha256=_EICAR_SHA256)]), fp_registry)
        assert "file_reputation" in looked_up["evidence"]
        assert _EICAR_SHA256 in looked_up["evidence"]["file_reputation"]


class TestEnrichHashLookup:
    def test_embedded_verdict_skips_lookup(
        self, fp_registry: FPRegistry, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An embedded VT verdict costs zero check_file_hash calls."""
        calls: list[str] = []
        real = eng.check_file_hash
        monkeypatch.setattr(
            eng, "check_file_hash", lambda h: calls.append(h) or real(h)
        )
        _run(
            _incident([_file_event(sha256=_EICAR_SHA256, vt_positives=58, vt_total=72)]),
            fp_registry,
        )
        assert calls == []

    def test_missing_verdict_triggers_one_lookup(
        self, fp_registry: FPRegistry, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No embedded verdict → exactly one lookup for the hash."""
        calls: list[str] = []
        real = eng.check_file_hash
        monkeypatch.setattr(
            eng, "check_file_hash", lambda h: calls.append(h) or real(h)
        )
        _run(_incident([_file_event(sha256=_EICAR_SHA256)]), fp_registry)
        assert calls == [_EICAR_SHA256]

    def test_lookup_bound_enforced(
        self, fp_registry: FPRegistry, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """More than _MAX_HASH_LOOKUPS distinct hashes → capped lookups."""
        calls: list[str] = []
        real = eng.check_file_hash
        monkeypatch.setattr(
            eng, "check_file_hash", lambda h: calls.append(h) or real(h)
        )
        events = [
            _file_event(path=f"/f{i}", sha256=f"{i:064x}")
            for i in range(eng._MAX_HASH_LOOKUPS + 1)
        ]
        _run(_incident(events), fp_registry)
        assert len(calls) == eng._MAX_HASH_LOOKUPS

    def test_malformed_hash_skipped_silently(
        self, fp_registry: FPRegistry, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A non-hex/short hash is never looked up and never raises."""
        calls: list[str] = []
        real = eng.check_file_hash
        monkeypatch.setattr(
            eng, "check_file_hash", lambda h: calls.append(h) or real(h)
        )
        output = _run(_incident([_file_event(sha256="xyz123")]), fp_registry)
        assert calls == []
        # No hash, no embedded verdict, not confirmed → signal not applicable.
        assert _entry(output, "file_reputation") is None
