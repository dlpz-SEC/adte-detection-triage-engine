"""ADTE command-line interface.

Provides the ``triage`` command that ingests incidents from a local
Sentinel JSON file (``--source mock``, default) or live from a Wazuh
API (``--source wazuh``), runs the full enrichment / scoring /
decision pipeline, and outputs the verdict in JSON or pretty-printed
format.

Usage::

    python -m adte triage --input examples/incident_impossible_travel_mfa_fatigue.json
    python -m adte triage --input incident.json --execute --format pretty --explain
    python -m adte triage --source wazuh --hours 24 --format pretty --explain

NIST 800-61 Phase: Detection & Analysis — provides the operator
interface for invoking and reviewing automated triage results.
"""

from __future__ import annotations

import json
import sys
from enum import Enum
from pathlib import Path
from typing import Annotated, Any, Optional

import typer

from adte.adapters.wazuh import WazuhAdapter
from adte.config import SafetyConfig
from adte.engine import TriageEngine
from adte.intel.sigma_fp_registry import FPRegistry
from adte.models import NormalizedIncident, SentinelIncident
from adte.store.user_history import get_user_profile

app = typer.Typer(
    name="adte",
    help="Automated Detection Triage Engine for Microsoft Sentinel.",
    no_args_is_help=True,
)


@app.callback()
def _main() -> None:
    """Automated Detection Triage Engine for Microsoft Sentinel."""


class OutputFormat(str, Enum):
    """Supported output formats for triage results."""

    json = "json"
    pretty = "pretty"


class SourceType(str, Enum):
    """Alert source for the triage command."""

    mock = "mock"
    wazuh = "wazuh"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _print_pretty(output: dict[str, Any], *, explain: bool) -> None:
    """Render triage output as formatted text to stdout.

    Falls back to plain-text formatting with ANSI escape codes for
    basic colour.

    Args:
        output: The triage output dict from ``TriageEngine.to_output()``.
        explain: If ``True``, include the full signal breakdown.
    """
    verdict = output["verdict"]
    risk = output["risk_score"]
    confidence = output["confidence"]

    # Colour the verdict banner.
    colour_map = {
        "high_risk": "\033[91m",    # red
        "medium_risk": "\033[93m",  # yellow
        "low_risk": "\033[92m",     # green
    }
    reset = "\033[0m"
    colour = colour_map.get(verdict, "")

    print()
    print(f"  {colour}{'=' * 56}{reset}")
    print(f"  {colour}  VERDICT:  {verdict.upper().replace('_', ' ')}{reset}")
    print(f"  {colour}{'=' * 56}{reset}")
    print()
    print(f"  Incident:    {output['report']['incident_id']}")
    print(f"  User:        {output['report']['user']}")
    print(f"  Severity:    {output['report']['severity']}")
    print(f"  Risk Score:  {risk}/100")
    print(f"  Confidence:  {confidence}%")
    print(f"  Action:      {output['recommended_action']}")
    print()

    if output["actions"]:
        print("  Recommended actions:")
        for action in output["actions"]:
            print(f"    - {action}")
        print()

    if explain:
        print("  Signal breakdown:")
        print(f"  {'Signal':<24} {'Score':>6} {'Max':>6} {'Conf':>6}  Detail")
        print(f"  {'-' * 24} {'-' * 6} {'-' * 6} {'-' * 6}  {'-' * 40}")
        for entry in output["rationale"]:
            signal = entry["signal"]
            score = entry["score"]
            summary = output["report"]["signal_summary"][signal]
            max_pts = summary["max_possible"]
            conf = summary["confidence"]
            detail = entry["detail"]
            # Truncate long detail lines.
            if len(detail) > 70:
                detail = detail[:67] + "..."
            print(f"  {signal:<24} {score:>6.1f} {max_pts:>6} {conf:>5.0%}  {detail}")
        print()

    safety = output["safety"]
    if safety.get("human_review_required"):
        print(f"  {colour}** Human review required **{reset}")
    print()


def _load_incident(path: Path) -> NormalizedIncident:
    """Load and normalise a Sentinel incident from a JSON file.

    Args:
        path: Path to the incident JSON file.

    Returns:
        A ``NormalizedIncident`` ready for the triage pipeline.

    Raises:
        typer.Exit: If the file is not found or contains invalid JSON.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        typer.echo(f"Error: file not found: {path}", err=True)
        raise typer.Exit(code=2)
    except json.JSONDecodeError as exc:
        typer.echo(f"Error: invalid JSON in {path}: {exc}", err=True)
        raise typer.Exit(code=2)

    try:
        sentinel = SentinelIncident(**raw)
        return NormalizedIncident.from_sentinel(sentinel)
    except Exception as exc:
        typer.echo(f"Error: failed to parse incident: {exc}", err=True)
        raise typer.Exit(code=2)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

@app.command()
def triage(
    input_file: Annotated[
        Optional[Path],
        typer.Option(
            "--input", "-i",
            help="Path to Sentinel incident JSON file. Required when --source mock.",
        ),
    ] = None,
    source: Annotated[
        SourceType,
        typer.Option(
            "--source",
            help="Alert source: 'mock' reads from --input file (default); "
                 "'wazuh' fetches live from Wazuh REST API.",
        ),
    ] = SourceType.mock,
    hours: Annotated[
        int,
        typer.Option(
            "--hours",
            help="Look-back window in hours when --source wazuh (default: 24).",
            min=1,
        ),
    ] = 24,
    limit: Annotated[
        int,
        typer.Option(
            "--limit",
            help="Maximum number of Wazuh alerts to retrieve (default: 500). "
                 "A warning is printed when results are truncated.",
            min=1,
        ),
    ] = 500,
    min_level: Annotated[
        int,
        typer.Option(
            "--min-level",
            help="Minimum Wazuh rule.level to include when --source wazuh (default: 1).",
            min=1,
        ),
    ] = 1,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Run in dry-run mode (default). No write actions.",
        ),
    ] = True,
    execute: Annotated[
        bool,
        typer.Option(
            "--execute",
            help="Enable execution mode (sets DRY_RUN=false, EXECUTION_ENABLED=true).",
        ),
    ] = False,
    output_format: Annotated[
        OutputFormat,
        typer.Option(
            "--format", "-f",
            help="Output format.",
        ),
    ] = OutputFormat.json,
    explain: Annotated[
        bool,
        typer.Option(
            "--explain", "-e",
            help="Include signal breakdown in output.",
        ),
    ] = False,
    save: Annotated[
        Optional[Path],
        typer.Option(
            "--save", "-s",
            help="Save JSON output to file.",
        ),
    ] = None,
) -> None:
    """Triage incidents through the ADTE pipeline.

    Reads from a local Sentinel JSON file (--source mock, default) or
    fetches live alerts from Wazuh (--source wazuh).  Runs enrichment
    and scoring and outputs the verdict with risk score and recommended
    actions.
    """
    # Validate mutually exclusive flags.
    if execute and dry_run and "--dry-run" in sys.argv:
        typer.echo("Error: --execute and --dry-run are mutually exclusive.", err=True)
        raise typer.Exit(code=2)

    # --source mock requires --input.
    if source == SourceType.mock and input_file is None:
        typer.echo(
            "Error: --source mock requires --input <path>. "
            "Provide a Sentinel incident JSON file.",
            err=True,
        )
        raise typer.Exit(code=2)

    # Resolve safety config from CLI flags + environment.
    if execute:
        safety = SafetyConfig(dry_run=False, execution_enabled=True)
    else:
        safety = SafetyConfig(dry_run=dry_run)

    # Load incidents from the selected source.
    if source == SourceType.mock:
        incidents: list[NormalizedIncident] = [_load_incident(input_file)]  # type: ignore[arg-type]
    else:  # wazuh
        try:
            adapter = WazuhAdapter.from_env()
            incidents = adapter.fetch_incidents(hours=hours, limit=limit, min_level=min_level)
        except EnvironmentError as exc:
            typer.echo(f"Error: {exc}", err=True)
            raise typer.Exit(code=2)
        if not incidents:
            typer.echo(
                "No alerts returned from Wazuh for the given time window.",
                err=True,
            )
            raise typer.Exit(code=0)

    # Run the triage pipeline for each incident.
    results: list[dict[str, Any]] = []
    for incident in incidents:
        user_profile = get_user_profile(incident.user)
        fp_registry = FPRegistry.load()
        engine = TriageEngine(incident, user_profile, fp_registry)
        output = engine.enrich().score().decide().to_output()
        results.append(output)
        if output_format == OutputFormat.pretty:
            _print_pretty(output, explain=explain)

    # For a single incident (--source mock) output a plain dict to preserve
    # the existing output shape; for multiple incidents output a JSON array.
    out: Any = results[0] if len(results) == 1 else results

    if output_format == OutputFormat.json:
        print(json.dumps(out, indent=2, default=str))

    # Save to file if requested.
    if save and results:
        save.write_text(
            json.dumps(out, indent=2, default=str),
            encoding="utf-8",
        )
        typer.echo(f"Output saved to {save}", err=True)
