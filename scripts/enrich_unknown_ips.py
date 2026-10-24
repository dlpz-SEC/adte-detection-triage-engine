"""Run unknown IPs from an incident hunt through ADTE's threat-intel wrappers.

Built for the 2026-10-21 Railway env-var exposure hunt
(docs/incidents/2026-10-21-railway-env-var-exposure.md): any source IP the
indexer audit-log queries turn up outside the allowlist goes in here.

Two modes:

* ``--dry-run`` (the default) never calls a provider.  It classifies each
  address the way the aggregator does (private, documentation, shared
  address space, or public), says whether a live run WOULD query a provider
  given the keys present in the environment, and attaches the deterministic
  mock result from a key-less aggregator.  Safe to run anywhere.
* ``--live`` calls ``check_threat_intel`` (AbuseIPDB / VirusTotal / OTX,
  whichever keys are set) inside ``lookup_budget``, so at most 25 live
  lookups are spent per run.  It spends real provider quota: run it only
  after the keys have been rotated, with the new keys.

Output is JSON on stdout.  No key value is ever printed; only the number of
configured providers.

Usage:
    .venv/Scripts/python.exe scripts/enrich_unknown_ips.py 203.0.113.7 198.51.100.2
    .venv/Scripts/python.exe scripts/enrich_unknown_ips.py --file unknown_ips.txt
    .venv/Scripts/python.exe scripts/enrich_unknown_ips.py --live --file unknown_ips.txt
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from adte.intel import threat_intel
from adte.intel.aggregator import (
    ThreatIntelAggregator,
    _is_documentation,
    _is_private,
    _is_shared_address,
    env_key,
)

_PROVIDER_KEYS: tuple[str, ...] = ("ADTE_ABUSEIPDB_KEY", "ADTE_VT_API_KEY", "ADTE_OTX_KEY")


def classify(ip: str) -> str:
    """Return the aggregator's address category for a valid IPv4 string.

    Args:
        ip: A pre-validated IPv4 address.

    Returns:
        ``"private"``, ``"documentation"``, ``"shared-address"`` or ``"public"``.
        Only ``"public"`` can ever reach a live provider.
    """
    if _is_private(ip):
        return "private"
    if _is_documentation(ip):
        return "documentation"
    if _is_shared_address(ip):
        return "shared-address"
    return "public"


def read_ips(args_ips: list[str], file_path: Path | None) -> list[str]:
    """Collect IPs from arguments and an optional file, de-duplicated in order.

    Blank lines and ``#`` comments in the file are ignored.

    Args:
        args_ips: IPs given on the command line.
        file_path: Optional path to a newline-separated IP list.

    Returns:
        Unique IP strings in first-seen order (not yet validated).
    """
    raw = list(args_ips)
    if file_path is not None:
        for line in file_path.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                raw.append(line)
    return list(dict.fromkeys(raw))


def enrich(ips: list[str], live: bool) -> dict[str, Any]:
    """Classify and enrich *ips*, live or from the mock.

    Args:
        ips: Candidate IP strings.
        live: ``True`` to query configured providers; ``False`` never makes
            a network call.

    Returns:
        A JSON-ready report: mode, configured provider count, and one entry
        per IP (invalid addresses are reported, not raised).
    """
    configured = sum(1 for k in _PROVIDER_KEYS if env_key(k))
    # Constructing an aggregator makes no network call; it only decides which
    # clients a check() would use.
    live_view = ThreatIntelAggregator.from_env()
    mock = ThreatIntelAggregator()  # no keys: pure deterministic mock
    results: list[dict[str, Any]] = []
    with threat_intel.lookup_budget():
        for ip in ips:
            if not threat_intel.is_lookup_ip(ip):
                results.append({"ip": ip, "error": "not an IPv4 address; skipped"})
                continue
            entry: dict[str, Any] = {
                "ip": ip,
                "category": classify(ip),
                "would_query_live": live_view.needs_live_lookup(ip),
            }
            result = threat_intel.check_threat_intel(ip) if live else mock.check(ip)
            entry["result"] = json.loads(result.model_dump_json())
            entry["result_origin"] = "live" if live else "mock (dry run)"
            results.append(entry)
    return {
        "mode": "live" if live else "dry-run",
        "providers_configured": configured,
        "results": results,
    }


def main(argv: list[str] | None = None) -> int:
    """Parse arguments, run the enrichment, print JSON.

    Args:
        argv: Argument list (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code: 0 on success, 2 when no IPs were given.
    """
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("ips", nargs="*", help="IPv4 addresses to enrich")
    parser.add_argument("--file", type=Path, help="newline-separated IP list")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run",
        dest="live",
        action="store_false",
        help="classify and mock only; never call a provider (default)",
    )
    mode.add_argument(
        "--live",
        dest="live",
        action="store_true",
        help="query configured providers (spends real quota)",
    )
    parser.set_defaults(live=False)
    args = parser.parse_args(argv)

    ips = read_ips(args.ips, args.file)
    if not ips:
        parser.print_usage(sys.stderr)
        print("no IPs given", file=sys.stderr)
        return 2
    print(json.dumps(enrich(ips, args.live), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
