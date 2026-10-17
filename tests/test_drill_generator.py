"""Incident Drill generator: determinism, the generation rules, kill-chain pins.

The kill-chain tests run every generated alert through the real per-alert
triage path (``server._triage_incident``) into a temporary case store, so the
tactics they pin are the ones the case layer actually computes (including the
tactics ADTE's own signals add), not the ones the generator intended.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

SCENARIO_IDS = ["password-spray", "identity-exfil", "malware-spread"]
SEEDS = [1, 7, 42, 1234, 2**31 - 1]

_ALLOWED_NETWORKS = [
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
    ipaddress.IPv4Network("100.64.0.0/10"),
    ipaddress.IPv4Network("10.20.0.0/24"),
]
_INTERNAL = ipaddress.IPv4Network("10.20.0.0/24")
_MOCK_PROXY_16 = ipaddress.IPv4Network("100.64.0.0/16")

# The tactics the case layer reports for each scenario's attack case.
EXPECTED_CHAINS = {
    "password-spray": ["Initial Access", "Credential Access", "Discovery", "Collection"],
    "identity-exfil": [
        "Initial Access",
        "Persistence",
        "Collection",
        "Command and Control",
        "Exfiltration",
    ],
    "malware-spread": ["Initial Access", "Execution", "Lateral Movement", "Command and Control"],
}


def _all_ips(run: Any) -> list[str]:
    return [e.ip_address for inc in run.incidents for e in inc.events if e.ip_address]


class TestDeterminism:
    @pytest.mark.parametrize("scenario", SCENARIO_IDS)
    @pytest.mark.parametrize("noise", ["low", "medium", "high"])
    def test_same_seed_same_run(self, scenario: str, noise: str) -> None:
        """A seed replays byte-identically (no wall clock, no hash randomisation)."""
        from adte.simulation.generator import generate

        a, b = generate(scenario, 42, noise), generate(scenario, 42, noise)
        assert a.model_dump_json() == b.model_dump_json()

    @pytest.mark.parametrize("scenario", SCENARIO_IDS)
    def test_different_seeds_differ(self, scenario: str) -> None:
        """Different seeds give different runs."""
        from adte.simulation.generator import generate

        dumps = {generate(scenario, s).model_dump_json() for s in SEEDS}
        assert len(dumps) == len(SEEDS)

    @pytest.mark.parametrize("scenario", SCENARIO_IDS)
    def test_noise_level_never_changes_the_attack(self, scenario: str) -> None:
        """The attack draws from its own stream: noise only adds benign alerts."""
        from adte.simulation.generator import generate

        def attack(noise: str) -> list[str]:
            run = generate(scenario, 7, noise)
            return [
                inc.model_dump_json(exclude={"incident_id"})
                for inc, st in zip(run.incidents, run.truth)
                if st.label == "malicious"
            ]

        assert attack("low") == attack("medium") == attack("high")


class TestGenerationRules:
    @pytest.mark.parametrize("scenario", SCENARIO_IDS)
    @pytest.mark.parametrize("seed", SEEDS)
    def test_ids_are_drill_prefixed_and_unique(self, scenario: str, seed: int) -> None:
        from adte.simulation.generator import generate
        from adte.store.audit_log import DRILL_ID_PREFIX

        ids = [inc.incident_id for inc in generate(scenario, seed, "high").incidents]
        assert all(i.startswith(DRILL_ID_PREFIX) for i in ids)
        assert len(set(ids)) == len(ids)

    @pytest.mark.parametrize("scenario", SCENARIO_IDS)
    @pytest.mark.parametrize("seed", SEEDS)
    def test_at_most_25_alerts(self, scenario: str, seed: int) -> None:
        from adte.simulation.generator import generate

        run = generate(scenario, seed, "high")
        assert len(run.incidents) <= 25
        assert len(run.truth) == len(run.incidents)

    @pytest.mark.parametrize("scenario", SCENARIO_IDS)
    @pytest.mark.parametrize("seed", SEEDS)
    def test_every_ip_is_reserved_and_never_an_example_or_fp_entry(
        self, scenario: str, seed: int
    ) -> None:
        """Drill IPs never reach a live provider and never hit the FP registry."""
        from adte.intel.sigma_fp_registry import FPRegistry
        from adte.simulation.generator import generate

        registry = FPRegistry.load()
        for ip in _all_ips(generate(scenario, seed, "high")):
            addr = ipaddress.IPv4Address(ip)
            assert any(addr in net for net in _ALLOWED_NETWORKS), ip
            assert addr not in _MOCK_PROXY_16, ip  # benign noise must be mock-unknown
            assert ip not in {"198.51.100.23", "203.0.113.5"}, ip
            if addr not in _INTERNAL:  # internal hosts are corporate on purpose
                assert registry.is_known_benign_any(ip)[0] is False, ip

    @pytest.mark.parametrize("scenario", SCENARIO_IDS)
    def test_times_are_seed_anchored_and_ordered(self, scenario: str) -> None:
        """Times sit in the fixed drill window, events and queue are ascending."""
        from adte.simulation.generator import generate

        start = datetime(2026, 3, 2, tzinfo=timezone.utc)
        for seed in SEEDS:
            run = generate(scenario, seed, "high")
            firsts = [inc.events[0].timestamp for inc in run.incidents]
            assert firsts == sorted(firsts)
            for inc in run.incidents:
                times = [e.timestamp for e in inc.events]
                assert times == sorted(times)
                assert all(t.tzinfo is not None for t in times)
                assert start <= times[0] < start + timedelta(days=121)
                assert inc.created_time == times[0]

    @pytest.mark.parametrize("scenario", SCENARIO_IDS)
    def test_file_events_never_need_a_live_hash_lookup(self, scenario: str) -> None:
        """Every file artifact carries an embedded verdict; no EICAR hash."""
        from adte.intel import _mock
        from adte.simulation.generator import generate

        known = {
            h
            for name, table in vars(_mock).items()
            if name.endswith("_HASHES") and isinstance(table, dict)
            for h in table
        }
        assert known  # the mock's hash tables (EICAR and friends) were found
        for seed in SEEDS:
            for inc in generate(scenario, seed, "high").incidents:
                for e in inc.events:
                    if e.file is None:
                        continue
                    assert e.file.vt_positives is not None and e.file.vt_total
                    assert e.file.sha256 not in known

    @pytest.mark.parametrize("scenario", SCENARIO_IDS)
    def test_native_techniques_exist_in_the_attack_map(self, scenario: str) -> None:
        """Case tactics come from the YAML map, so every ID must be in it."""
        from adte.intel.mitre_mapper import get_technique_details
        from adte.simulation.generator import generate
        from adte.simulation.scenarios import SCENARIOS

        ids = set(SCENARIOS[scenario].techniques)
        for seed in SEEDS:
            for inc in generate(scenario, seed, "high").incidents:
                ids.update(t for e in inc.events for t in e.technique_ids)
        for tid in ids:
            assert get_technique_details([tid])[0]["tactic"], tid

    def test_catalogue_chains_use_real_tactic_names(self) -> None:
        from adte.case_policy import KILL_CHAIN_ORDER
        from adte.simulation.scenarios import SCENARIOS

        for s in SCENARIOS.values():
            assert set(s.chain) <= set(KILL_CHAIN_ORDER), s.id

    @pytest.mark.parametrize("scenario", ["password-spray", "identity-exfil"])
    def test_noise_never_uses_the_compromised_account(self, scenario: str) -> None:
        """Noise shares no user with the attack, so it cannot join its case by user."""
        from adte.simulation.generator import generate

        for seed in SEEDS:
            run = generate(scenario, seed, "high")
            attack = {
                inc.user for inc, st in zip(run.incidents, run.truth) if st.label == "malicious"
            }
            noise = {inc.user for inc, st in zip(run.incidents, run.truth) if st.label == "benign"}
            assert not attack & noise

    def test_bad_arguments(self) -> None:
        from adte.simulation.generator import generate

        with pytest.raises(KeyError):
            generate("no-such-scenario", 1)
        with pytest.raises(ValueError):
            generate("password-spray", 1, "extreme")  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            generate("password-spray", -1)

    def test_personas_have_baselines(self) -> None:
        """Noise needs a home location, a device and an old last-seen time."""
        from adte.store.user_history import DRILL_PERSONA_UPNS, get_user_profile

        assert len(DRILL_PERSONA_UPNS) == 4
        for upn in DRILL_PERSONA_UPNS:
            p = get_user_profile(upn)
            assert upn == upn.lower() and upn.endswith("@corp.example")
            assert p.known_devices and p.last_seen_location is not None
            assert p.last_seen_at is not None and p.last_seen_at < datetime(2026, 3, 2)


def _triage_run(run: Any, tmp_path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Triage a run's incidents in order through the real per-alert path."""
    import adte.server as srv
    from adte.intel.sigma_fp_registry import FPRegistry

    case_db = tmp_path / "cases.db"
    fp = FPRegistry.load()
    results = [
        {"index": i, "ok": True, **srv._triage_incident(inc, fp, case_db=case_db, log=False)}
        for i, inc in enumerate(run.incidents)
    ]
    return results, srv._case_summaries(results, case_db)


class TestKillChains:
    @pytest.mark.parametrize("scenario", SCENARIO_IDS)
    @pytest.mark.parametrize("seed", [1, 7, 42])
    def test_attack_forms_one_case_with_the_pinned_chain(
        self, scenario: str, seed: int, tmp_path: Path
    ) -> None:
        """All attack alerts land in one case, no noise joins it, the chain fires."""
        from adte.simulation.generator import generate

        run = generate(scenario, seed, "high")
        _, cases = _triage_run(run, tmp_path)
        attack = {i for i, st in enumerate(run.truth) if st.label == "malicious"}
        attack_cases = [c for c in cases if attack & set(c["member_indices"])]
        assert len(attack_cases) == 1
        case = attack_cases[0]
        assert set(case["member_indices"]) == attack
        assert case["kill_chain"]["detected"] is True
        assert case["kill_chain"]["tactics_in_order"] == EXPECTED_CHAINS[scenario]

    @pytest.mark.parametrize("scenario", SCENARIO_IDS)
    @pytest.mark.parametrize("seed", SEEDS)
    def test_noise_alone_never_forms_a_kill_chain(
        self, scenario: str, seed: int, tmp_path: Path
    ) -> None:
        """Control: the benign alerts by themselves cannot fire the detector."""
        from adte.simulation.generator import generate
        from adte.simulation.schema import DrillRun

        run = generate(scenario, seed, "high")
        noise = [(inc, st) for inc, st in zip(run.incidents, run.truth) if st.label == "benign"]
        control = DrillRun(
            scenario=scenario,
            seed=seed,
            noise="high",
            incidents=[n[0] for n in noise],
            truth=[n[1] for n in noise],
        )
        _, cases = _triage_run(control, tmp_path)
        assert noise and cases
        assert not any(c["kill_chain"]["detected"] for c in cases)
