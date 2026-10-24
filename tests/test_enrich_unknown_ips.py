"""Tests for scripts.enrich_unknown_ips — the incident-hunt IP enrichment helper.

The dry-run default must never reach a provider, even with live keys in the
environment; the hunt runs it before the keys are rotated.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import responses

from scripts.enrich_unknown_ips import classify, enrich, main, read_ips


@pytest.fixture()
def fake_live_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    """Put placeholder provider keys in the env so a live path WOULD be chosen."""
    monkeypatch.setenv("ADTE_ABUSEIPDB_KEY", "test-abuse-key")
    monkeypatch.setenv("ADTE_VT_API_KEY", "test-vt-key")
    monkeypatch.setenv("ADTE_OTX_KEY", "test-otx-key")


@pytest.mark.parametrize(
    ("ip", "category"),
    [
        ("10.0.0.5", "private"),
        ("127.0.0.1", "private"),
        ("192.0.2.1", "documentation"),
        ("100.64.1.1", "shared-address"),
        ("8.8.8.8", "public"),
    ],
)
def test_classify_matches_aggregator_ranges(ip: str, category: str) -> None:
    """Each address lands in the aggregator's own category."""
    assert classify(ip) == category


@responses.activate
def test_dry_run_makes_no_network_call_with_live_keys(fake_live_keys: None) -> None:
    """With keys set and no URL registered, any provider call would raise; none happens."""
    report = enrich(["8.8.8.8", "10.0.0.5", "192.0.2.1"], live=False)
    assert len(responses.calls) == 0
    assert report["mode"] == "dry-run"
    assert report["providers_configured"] == 3
    by_ip = {r["ip"]: r for r in report["results"]}
    assert by_ip["8.8.8.8"]["would_query_live"] is True
    assert by_ip["10.0.0.5"]["would_query_live"] is False
    assert by_ip["192.0.2.1"]["would_query_live"] is False
    assert all(r["result_origin"] == "mock (dry run)" for r in report["results"])


def test_invalid_address_is_reported_not_raised() -> None:
    """IPv6 and junk are skipped with an error entry."""
    report = enrich(["2001:db8::1", "not-an-ip"], live=False)
    assert [r["error"] for r in report["results"]] == ["not an IPv4 address; skipped"] * 2


def test_output_never_contains_key_values(
    fake_live_keys: None, capsys: pytest.CaptureFixture[str]
) -> None:
    """The printed JSON reports a provider count, never a key."""
    assert main(["198.51.100.7"]) == 0
    out = capsys.readouterr().out
    json.loads(out)
    for value in ("test-abuse-key", "test-vt-key", "test-otx-key"):
        assert value not in out


def test_read_ips_merges_args_and_file(tmp_path: Path) -> None:
    """File comments and blanks are dropped; duplicates collapse in order."""
    f = tmp_path / "ips.txt"
    f.write_text("# hunt output\n203.0.113.9\n\n8.8.8.8  # resolver\n", encoding="utf-8")
    assert read_ips(["8.8.8.8"], f) == ["8.8.8.8", "203.0.113.9"]


def test_no_ips_exits_2() -> None:
    """Running with nothing to enrich is a usage error."""
    assert main([]) == 2
