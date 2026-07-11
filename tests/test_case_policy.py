"""Tests for adte/case_policy.py — constants and case scoring."""

from __future__ import annotations

from adte.case_policy import (
    KILL_CHAIN_BONUS,
    KILL_CHAIN_ORDER,
    KILL_CHAIN_RANK,
    MULTI_ALERT_BONUS,
    MULTI_ALERT_BONUS_CAP,
    TACTIC_BREADTH_BONUS,
    TACTIC_BREADTH_BONUS_CAP,
    score_case,
)
from adte.decision_policy import classify_verdict

_NO_CHAIN = {"detected": False, "tactics_in_order": []}
_CHAIN = {
    "detected": True,
    "tactics_in_order": ["Credential Access", "Lateral Movement", "Exfiltration"],
}


class TestKillChainConstants:
    def test_order_has_all_14_enterprise_tactics(self) -> None:
        assert len(KILL_CHAIN_ORDER) == 14
        assert len(set(KILL_CHAIN_ORDER)) == 14

    def test_order_is_canonical(self) -> None:
        assert KILL_CHAIN_ORDER[0] == "Reconnaissance"
        assert KILL_CHAIN_ORDER[-1] == "Impact"
        # The demo-story trio must ascend.
        assert (
            KILL_CHAIN_RANK["Credential Access"]
            < KILL_CHAIN_RANK["Lateral Movement"]
            < KILL_CHAIN_RANK["Exfiltration"]
        )

    def test_rank_map_matches_order(self) -> None:
        assert KILL_CHAIN_RANK == {t: i for i, t in enumerate(KILL_CHAIN_ORDER)}

    def test_min_members_pinned_to_dp_capability(self) -> None:
        """Tripwire: the detection DP tracks a BINARY crossed-members
        property, so only values 1 and 2 behave as documented.  If this
        fails, you raised the constant — extend the DP to count distinct
        members first (see detect_kill_chain docstring)."""
        from adte.case_policy import KILL_CHAIN_MIN_MEMBERS

        assert KILL_CHAIN_MIN_MEMBERS in (1, 2)

    def test_yaml_tactics_all_rankable(self) -> None:
        """Every tactic name in the technique map must exist in the ordering."""
        import yaml
        from pathlib import Path

        map_path = (
            Path(__file__).resolve().parent.parent
            / "adte"
            / "data"
            / "mitre_technique_map.yaml"
        )
        mappings = yaml.safe_load(map_path.read_text(encoding="utf-8"))["mappings"]
        tactics = {m["mitre_tactic"] for m in mappings}
        assert tactics <= set(KILL_CHAIN_ORDER)


class TestScoreCase:
    def test_base_only_single_member(self) -> None:
        score, verdict, escalated, rationale = score_case(
            [55.0], 1, _NO_CHAIN, "INC-1"
        )
        assert score == 55
        assert verdict == "medium_risk"
        assert escalated is False
        assert [r["factor"] for r in rationale] == ["base_max_member"]
        assert "INC-1" in rationale[0]["detail"]

    def test_multi_alert_bonus(self) -> None:
        score, _, _, rationale = score_case([55.0, 40.0], 1, _NO_CHAIN, "INC-1")
        assert score == 55 + MULTI_ALERT_BONUS
        assert any(r["factor"] == "multi_alert" for r in rationale)

    def test_multi_alert_bonus_capped(self) -> None:
        score, _, _, _ = score_case([10.0] * 6, 1, _NO_CHAIN, "INC-1")
        assert score == 10 + MULTI_ALERT_BONUS_CAP  # (6-1)*5 = 25 -> cap 15

    def test_tactic_breadth_bonus(self) -> None:
        score, _, _, rationale = score_case([40.0], 3, _NO_CHAIN, "INC-1")
        assert score == 40 + 2 * TACTIC_BREADTH_BONUS
        assert any(r["factor"] == "tactic_breadth" for r in rationale)

    def test_tactic_breadth_bonus_capped(self) -> None:
        score, _, _, _ = score_case([40.0], 6, _NO_CHAIN, "INC-1")
        assert score == 40 + TACTIC_BREADTH_BONUS_CAP

    def test_kill_chain_bonus(self) -> None:
        score, _, _, rationale = score_case([40.0], 1, _CHAIN, "INC-1")
        assert score == 40 + KILL_CHAIN_BONUS
        chain_entries = [r for r in rationale if r["factor"] == "kill_chain"]
        assert len(chain_entries) == 1
        assert "Credential Access → Lateral Movement" in chain_entries[0]["detail"]

    def test_demo_story_three_medium_alerts_escalate_to_high(self) -> None:
        """Three medium alerts, one IP, cred-access→lateral→exfil = 95 high."""
        score, verdict, escalated, _ = score_case(
            [55.0, 48.0, 51.0], 3, _CHAIN, "INC-104"
        )
        assert score == 55 + 10 + 10 + 20 == 95
        assert verdict == "high_risk"
        assert escalated is True

    def test_cap_at_100_with_negative_cap_entry(self) -> None:
        score, _, _, rationale = score_case([90.0] * 4, 4, _CHAIN, "INC-1")
        # raw = 90 + 15 + 15 + 20 = 140
        assert score == 100
        cap_entries = [r for r in rationale if r["factor"] == "cap"]
        assert len(cap_entries) == 1
        assert cap_entries[0]["points"] == -40

    def test_rationale_points_always_sum_to_score(self) -> None:
        for members, tactics, chain in [
            ([12.0], 0, _NO_CHAIN),
            ([55.0, 40.0, 30.0], 3, _CHAIN),
            ([90.0] * 5, 6, _CHAIN),
            ([100.0], 1, _NO_CHAIN),
        ]:
            score, _, _, rationale = score_case(members, tactics, chain, "INC-X")
            assert sum(r["points"] for r in rationale) == score

    def test_verdict_uses_classify_verdict(self) -> None:
        for members, tactics, chain in [
            ([10.0], 1, _NO_CHAIN),
            ([55.0], 1, _NO_CHAIN),
            ([70.0, 60.0], 2, _NO_CHAIN),
            ([90.0] * 3, 4, _CHAIN),
        ]:
            score, verdict, _, _ = score_case(members, tactics, chain, "INC-X")
            assert verdict == classify_verdict(score)

    def test_escalated_false_when_class_unchanged(self) -> None:
        # Base already high_risk; bonuses keep it high_risk -> not escalated.
        _, verdict, escalated, _ = score_case([80.0, 75.0], 1, _NO_CHAIN, "INC-1")
        assert verdict == "high_risk"
        assert escalated is False

    def test_escalated_true_on_class_change(self) -> None:
        # 65 (medium) + 5 (multi) = 70 is still medium; add breadth to cross 70.
        _, verdict, escalated, _ = score_case([65.0, 60.0], 2, _NO_CHAIN, "INC-1")
        assert verdict == "high_risk"  # 65 + 5 + 5 = 75
        assert escalated is True

    def test_empty_members_returns_zero(self) -> None:
        score, verdict, escalated, rationale = score_case([], 0, _NO_CHAIN, "")
        assert (score, verdict, escalated, rationale) == (0, "low_risk", False, [])

    def test_base_clamped_to_valid_range(self) -> None:
        score, _, _, _ = score_case([150.0], 0, _NO_CHAIN, "INC-1")
        assert score == 100
