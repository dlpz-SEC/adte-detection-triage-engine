"""ADTE command-line interface.

Provides the ``triage`` command that ingests incidents from a local
Sentinel JSON file (``--source mock``, default) or live from a Wazuh
API (``--source wazuh``), runs the full enrichment / scoring /
decision pipeline, and outputs the verdict in JSON or pretty-printed
format.

Usage::

    python -m adte triage --input examples/incident_impossible_travel_mfa_fatigue.json
    python -m adte triage --input incident.json --format pretty --explain
    python -m adte triage --source wazuh --hours 24 --format pretty --explain

NIST 800-61 Phase: Detection & Analysis — provides the operator
interface for invoking and reviewing automated triage results.
"""

from __future__ import annotations

import json

from pathlib import Path
from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent.parent / ".env")  # always finds repo-root .env regardless of CWD
from enum import Enum
from typing import Annotated, Any, Optional

import typer
from pydantic import ValidationError

from adte.adapters.wazuh import WazuhAdapter
from adte.engine import TriageEngine
from adte.intel.sigma_fp_registry import FPRegistry
from adte.models import NormalizedIncident, SentinelIncident
from adte.store.user_history import get_user_profile

app = typer.Typer(
    name="adte",
    help="Automated Detection Triage Engine — source-agnostic security alert triage.",
    no_args_is_help=True,
)


@app.callback()
def _main() -> None:
    """Automated Detection Triage Engine — source-agnostic security alert triage."""


class OutputFormat(str, Enum):
    """Supported output formats for triage results."""

    json = "json"
    pretty = "pretty"


class SourceType(str, Enum):
    """Alert source for the triage command."""

    mock = "mock"
    normalized = "normalized"
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


def _read_json(path: Path) -> Any:
    """Read and parse a JSON file, exiting on error.

    Args:
        path: Path to the JSON file.

    Returns:
        The parsed JSON value.

    Raises:
        typer.Exit: If the file is not found or contains invalid JSON.
    """
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        typer.echo(f"Error: file not found: {path}", err=True)
        raise typer.Exit(code=2)
    except json.JSONDecodeError as exc:
        typer.echo(f"Error: invalid JSON in {path}: {exc}", err=True)
        raise typer.Exit(code=2)


# _load_incident and _load_normalized_incident are structurally identical
# (same error-handling blocks, same exit codes) and differ only in the
# adapter step.  Kept separate so each function's docstring accurately
# describes its schema contract without a confusing branch.
def _load_incident(path: Path) -> NormalizedIncident:
    """Load and normalise a Sentinel incident from a JSON file.

    Expects a ``SentinelIncident``-shaped payload and converts it via
    ``NormalizedIncident.from_sentinel()``.

    Args:
        path: Path to the Sentinel incident JSON file.

    Returns:
        A ``NormalizedIncident`` ready for the triage pipeline.

    Raises:
        typer.Exit: If the file is not found, contains invalid JSON,
            or cannot be parsed as a ``SentinelIncident``.
    """
    raw = _read_json(path)
    try:
        sentinel = SentinelIncident(**raw)
        return NormalizedIncident.from_sentinel(sentinel)
    except (ValidationError, TypeError, KeyError):
        typer.echo(
            "Error: incident does not match expected SentinelIncident schema — "
            "check that all required fields are present.",
            err=True,
        )
        raise typer.Exit(code=2)
    except Exception:
        typer.echo("Error: failed to parse incident — unexpected format.", err=True)
        raise typer.Exit(code=2)


def _load_normalized_incident(path: Path) -> NormalizedIncident:
    """Load a ``NormalizedIncident`` directly from a JSON file.

    Deserializes the file as a ``NormalizedIncident`` without going
    through the ``SentinelIncident`` adapter.  Use this when the input
    is already in ADTE's normalized schema (e.g. a POST body forwarded
    to the CLI, or output from a non-Sentinel source adapter).

    Args:
        path: Path to the ``NormalizedIncident`` JSON file.

    Returns:
        A ``NormalizedIncident`` ready for the triage pipeline.

    Raises:
        typer.Exit: If the file is not found, contains invalid JSON,
            or cannot be validated as a ``NormalizedIncident``.
    """
    raw = _read_json(path)
    try:
        return NormalizedIncident.model_validate(raw)
    except ValidationError:
        typer.echo(
            "Error: file does not match NormalizedIncident schema — "
            "check that all required fields are present.",
            err=True,
        )
        raise typer.Exit(code=2)
    except Exception:
        typer.echo("Error: failed to parse NormalizedIncident — unexpected format.", err=True)
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
            help="Path to incident JSON file (SentinelIncident schema). Required when --source mock.",
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
    and scoring and outputs the verdict with risk score, per-signal
    rationale, and the recommended human-review action.
    """
    # --source mock and --source normalized both require --input.
    if source in (SourceType.mock, SourceType.normalized) and input_file is None:
        typer.echo(
            f"Error: --source {source.value} requires --input <path>.",
            err=True,
        )
        raise typer.Exit(code=2)

    # Load incidents from the selected source.
    if source == SourceType.mock:
        incidents: list[NormalizedIncident] = [_load_incident(input_file)]  # type: ignore[arg-type]
    elif source == SourceType.normalized:
        incidents = [_load_normalized_incident(input_file)]  # type: ignore[arg-type]
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
