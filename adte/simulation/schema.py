"""Pydantic models for Incident Drill requests, runs and ground truth.

``Stage`` (ground truth) is internal: the run route never serialises it.  It
is revealed only by the debrief, after the analyst has submitted calls.

NIST 800-61 Phase: Preparation — structures a training exercise.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from adte.models import NormalizedIncident

# Upper bound on alerts per drill, matching /api/triage/batch.
MAX_DRILL_ALERTS: int = 25
# Seeds are non-negative 31-bit integers so they survive any JSON client.
MAX_SEED: int = 2**31 - 1
MAX_RATIONALE_CHARS: int = 280
MAX_NOTES_CHARS: int = 2000

NoiseLevel = Literal["low", "medium", "high"]
Call = Literal["true_positive", "benign_positive", "false_positive"]
TruthLabel = Literal["malicious", "benign"]


class Stage(BaseModel):
    """Ground truth for one generated alert.

    Attributes:
        label: Whether the alert is part of the attack.
        expected_call: The disposition a careful analyst should make.
        title: Short name of what the alert actually is.
        why: Plain explanation shown in the debrief.
        tactic: ATT&CK tactic of the scripted stage (attack alerts only).
        technique_ids: Native technique IDs the generator put on the alert.
    """

    model_config = ConfigDict(frozen=True)

    label: TruthLabel
    expected_call: Call
    title: str
    why: str
    tactic: str | None = None
    technique_ids: list[str] = Field(default_factory=list)


class DrillRun(BaseModel):
    """A generated drill: incidents in queue order plus their ground truth.

    Attributes:
        scenario: Scenario ID.
        seed: Seed the run was generated from.
        noise: Noise level.
        incidents: Alerts in queue (triage) order.
        truth: Ground truth, index-aligned with ``incidents``.
    """

    scenario: str
    seed: int
    noise: NoiseLevel
    incidents: list[NormalizedIncident]
    truth: list[Stage]


class Scenario(BaseModel):
    """Public catalogue entry for a drill scenario (no ground truth).

    Attributes:
        id: Stable scenario ID used in requests.
        name: Display name.
        summary: One-paragraph brief for the analyst.
        difficulty: Rough difficulty label.
        chain: ATT&CK tactics of the scripted stages, in story order.
        techniques: Native technique IDs the scenario uses.
        lessons: Teaching points the debrief always includes.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    summary: str
    difficulty: Literal["intro", "intermediate", "advanced"]
    chain: list[str]
    techniques: list[str]
    lessons: list[str]


class DrillRunRequest(BaseModel):
    """Body of ``POST /api/drill/run``."""

    model_config = ConfigDict(extra="forbid")

    scenario: str = Field(min_length=1, max_length=64)
    seed: int | None = Field(default=None, ge=0, le=MAX_SEED)
    noise: NoiseLevel = "medium"


class Disposition(BaseModel):
    """An analyst's call on one drill alert.

    Attributes:
        index: Position of the alert in the run's ``results``.
        call: True positive, benign positive or false positive.
        escalate: Whether the analyst escalated it to Tier 2.
        rationale: One-line reason, capped.
    """

    model_config = ConfigDict(extra="forbid")

    index: int = Field(ge=0, lt=MAX_DRILL_ALERTS)
    call: Call
    escalate: bool = False
    rationale: str = Field(default="", max_length=MAX_RATIONALE_CHARS)


class DrillReportRequest(BaseModel):
    """Body of ``POST /api/drill/report``.

    The run is regenerated from ``scenario``/``seed``/``noise`` and re-scored
    server-side; nothing the client sends about verdicts is trusted.
    """

    model_config = ConfigDict(extra="forbid")

    scenario: str = Field(min_length=1, max_length=64)
    seed: int = Field(ge=0, le=MAX_SEED)
    noise: NoiseLevel = "medium"
    dispositions: list[Disposition] = Field(default_factory=list, max_length=MAX_DRILL_ALERTS)
    notes: str = Field(default="", max_length=MAX_NOTES_CHARS)
