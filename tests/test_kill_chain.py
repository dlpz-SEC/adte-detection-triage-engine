"""Tests for adte/case_policy.py detect_kill_chain — progression detection."""

from __future__ import annotations

from adte.case_policy import detect_kill_chain


class TestKillChainDetection:
    def test_ascending_three_tactics_three_members_detected(self) -> None:
        result = detect_kill_chain(
            [
                (1, ["Credential Access"]),
                (2, ["Lateral Movement"]),
                (3, ["Exfiltration"]),
            ]
        )
        assert result["detected"] is True
        assert result["tactics_in_order"] == [
            "Credential Access",
            "Lateral Movement",
            "Exfiltration",
        ]

    def test_descending_not_detected(self) -> None:
        result = detect_kill_chain(
            [
                (1, ["Exfiltration"]),
                (2, ["Lateral Movement"]),
                (3, ["Credential Access"]),
            ]
        )
        assert result["detected"] is False
        assert result["tactics_in_order"] == []

    def test_gaps_allowed(self) -> None:
        # Initial Access -> Credential Access -> Impact skips many stages.
        result = detect_kill_chain(
            [
                (1, ["Initial Access"]),
                (2, ["Credential Access"]),
                (3, ["Impact"]),
            ]
        )
        assert result["detected"] is True

    def test_single_member_three_tactics_not_detected(self) -> None:
        """One alert with three techniques is breadth, not progression."""
        result = detect_kill_chain(
            [(1, ["Credential Access", "Lateral Movement", "Exfiltration"])]
        )
        assert result["detected"] is False

    def test_two_members_three_tactics_detected(self) -> None:
        result = detect_kill_chain(
            [
                (1, ["Credential Access"]),
                (2, ["Lateral Movement", "Exfiltration"]),
            ]
        )
        assert result["detected"] is True
        assert result["tactics_in_order"] == [
            "Credential Access",
            "Lateral Movement",
            "Exfiltration",
        ]

    def test_out_of_order_arrival_still_found(self) -> None:
        """LIS beats greedy: an early Exfiltration alert must not mask the
        chain formed by later members."""
        result = detect_kill_chain(
            [
                (1, ["Exfiltration"]),
                (2, ["Credential Access"]),
                (3, ["Lateral Movement", "Impact"]),
            ]
        )
        assert result["detected"] is True
        assert result["tactics_in_order"] == [
            "Credential Access",
            "Lateral Movement",
            "Impact",
        ]

    def test_unknown_tactics_ignored(self) -> None:
        result = detect_kill_chain(
            [
                (1, ["Credential Access", "Made Up Tactic"]),
                (2, ["Lateral Movement"]),
                (3, ["Not A Tactic"]),
            ]
        )
        # Only 2 known tactics remain -> below the 3-tactic minimum.
        assert result["detected"] is False

    def test_two_distinct_tactics_not_enough(self) -> None:
        result = detect_kill_chain(
            [
                (1, ["Credential Access"]),
                (2, ["Exfiltration"]),
            ]
        )
        assert result["detected"] is False

    def test_repeated_tactic_does_not_chain(self) -> None:
        """Strictly increasing: the same tactic from three alerts is volume,
        not progression."""
        result = detect_kill_chain(
            [
                (1, ["Credential Access"]),
                (2, ["Credential Access"]),
                (3, ["Credential Access"]),
            ]
        )
        assert result["detected"] is False

    def test_empty_input(self) -> None:
        result = detect_kill_chain([])
        assert result == {"detected": False, "tactics_in_order": []}

    def test_duplicate_tactics_within_member_deduplicated(self) -> None:
        result = detect_kill_chain(
            [
                (1, ["Credential Access", "Credential Access"]),
                (2, ["Lateral Movement"]),
                (3, ["Exfiltration"]),
            ]
        )
        assert result["detected"] is True
        assert result["tactics_in_order"] == [
            "Credential Access",
            "Lateral Movement",
            "Exfiltration",
        ]
