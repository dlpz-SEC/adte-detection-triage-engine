"""Tests for detections/sigma/wazuh_indexer_auth_unexpected_source.yml.

ADTE carries no pySigma dependency (and a supply-chain postmortem is a poor
place to add one), so this file evaluates the rule with a deliberately tiny
matcher.  It supports exactly what the rule uses (plain field equality, the
``|cidr`` modifier, and a ``a and not b`` condition) and FAILS on anything
else, so a future edit to the rule cannot pass here by being ignored.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

_REPO_ROOT = Path(__file__).resolve().parents[1]
RULE_PATH = _REPO_ROOT / "detections" / "sigma" / "wazuh_indexer_auth_unexpected_source.yml"
EVENTS_PATH = Path(__file__).resolve().parent / "fixtures" / "indexer_audit_events.json"

_CONDITION = re.compile(r"^(\w+)(?:\s+and\s+not\s+(\w+))?$")


class UnsupportedSigma(Exception):
    """The rule uses a construct this matcher does not implement."""


def _field_matches(event: dict[str, Any], key: str, expected: Any) -> bool:
    """Return True if one ``field[|modifier]: value(s)`` item matches *event*."""
    field, _, modifier = key.partition("|")
    values = expected if isinstance(expected, list) else [expected]
    actual = event.get(field)
    if actual is None:
        return False
    if modifier == "":
        return any(str(actual) == str(v) for v in values)
    if modifier == "cidr":
        try:
            addr = ipaddress.ip_address(str(actual))
        except ValueError:
            return False
        return any(addr in ipaddress.ip_network(str(v), strict=False) for v in values)
    raise UnsupportedSigma(f"modifier {modifier!r}")


def _selection_matches(event: dict[str, Any], selection: Any) -> bool:
    """AND every field item of a map selection."""
    if not isinstance(selection, dict):
        raise UnsupportedSigma(f"selection type {type(selection).__name__}")
    return all(_field_matches(event, k, v) for k, v in selection.items())


def rule_matches(rule: dict[str, Any], event: dict[str, Any]) -> bool:
    """Evaluate the rule's detection block against one event."""
    detection = dict(rule["detection"])
    condition = detection.pop("condition")
    m = _CONDITION.match(str(condition).strip())
    if m is None:
        raise UnsupportedSigma(f"condition {condition!r}")
    include, exclude = m.group(1), m.group(2)
    hit = _selection_matches(event, detection[include])
    if exclude is not None:
        hit = hit and not _selection_matches(event, detection[exclude])
    return hit


@pytest.fixture(scope="module")
def rule() -> dict[str, Any]:
    """The rule under test, parsed."""
    return yaml.safe_load(RULE_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def events() -> dict[str, list[dict[str, Any]]]:
    """Positive and negative sample audit-log documents."""
    return json.loads(EVENTS_PATH.read_text(encoding="utf-8"))


class TestRuleFires:
    """Behaviour against the sample audit-log events."""

    def test_positive_sample_fires(self, rule: dict[str, Any], events: dict[str, Any]) -> None:
        """REST login from outside the allowlist matches."""
        assert events["positive"]
        for event in events["positive"]:
            assert rule_matches(rule, event), event

    @pytest.mark.parametrize("index", range(4))
    def test_negative_sample_does_not_fire(
        self, rule: dict[str, Any], events: dict[str, Any], index: int
    ) -> None:
        """Allowlisted, loopback, failed and transport events do not match."""
        event = events["negative"][index]
        assert not rule_matches(rule, event), event["_why"]

    def test_every_negative_is_covered(self, events: dict[str, Any]) -> None:
        """The parametrized range above spans every negative sample."""
        assert len(events["negative"]) == 4

    def test_matcher_rejects_unknown_modifier(self, rule: dict[str, Any]) -> None:
        """A construct the matcher lacks raises instead of silently not matching."""
        broken = copy.deepcopy(rule)
        broken["detection"]["selection"] = {"audit_category|contains": "AUTH"}
        with pytest.raises(UnsupportedSigma):
            rule_matches(broken, {"audit_category": "AUTHENTICATED"})


class TestRuleMetadata:
    """House conventions from the dlpz-SEC Sigma standard."""

    def test_title_format(self, rule: dict[str, Any]) -> None:
        """Title follows '[Platform] - [Threat Behavior]'."""
        assert rule["title"] == "Wazuh - Indexer Authentication From Unexpected Source"

    def test_attack_tags(self, rule: dict[str, Any]) -> None:
        """Tagged Valid Accounts and Unsecured Credentials."""
        assert {"attack.t1078", "attack.t1552"} <= set(rule["tags"])

    def test_status_experimental(self, rule: dict[str, Any]) -> None:
        """Not yet validated in a pipeline, so experimental."""
        assert rule["status"] == "experimental"

    def test_falsepositives_present(self, rule: dict[str, Any]) -> None:
        """The falsepositives field exists and is non-empty."""
        assert rule["falsepositives"]

    def test_allowlist_parses_as_networks(self, rule: dict[str, Any]) -> None:
        """Every allowlist entry is a valid CIDR (a typo would silently widen the alert)."""
        for cidr in rule["detection"]["filter_allowlist"]["audit_request_remote_address|cidr"]:
            ipaddress.ip_network(cidr, strict=False)
