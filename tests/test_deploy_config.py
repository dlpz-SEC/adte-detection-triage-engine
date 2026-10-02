"""Pin the single-process gunicorn model in both deploy configs.

ADTE keeps rate-limit counters, threat-intel quotas and spacing, and several
caches in process memory.  Under ``--workers 2`` each process kept its own
copy, so every documented rate limit and quota was really up to 2x.  Raising
the worker count again silently reintroduces that; this test makes it loud.

To scale out deliberately, first move that state to a shared store (Redis for
Flask-Limiter's ``storage_uri``), then change this test.

Covers:
  - Dockerfile CMD (Railway, live)
  - render.yaml startCommand (Render, parked)
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]


def _dockerfile_start() -> str:
    """Return the gunicorn command from the Dockerfile's CMD line."""
    text = (_REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    cmd_lines = [ln for ln in text.splitlines() if ln.startswith("CMD ")]
    assert len(cmd_lines) == 1, "expected exactly one CMD line in the Dockerfile"
    return cmd_lines[0]


def _render_start() -> str:
    """Return render.yaml's startCommand value."""
    text = (_REPO_ROOT / "render.yaml").read_text(encoding="utf-8")
    match = re.search(r"^\s*startCommand:\s*(.+)$", text, re.MULTILINE)
    assert match, "render.yaml has no startCommand"
    return match.group(1)


@pytest.mark.parametrize("start", [_dockerfile_start(), _render_start()], ids=["docker", "render"])
def test_gunicorn_runs_one_threaded_worker(start: str) -> None:
    """One gunicorn process, concurrency from threads."""
    assert "gunicorn adte.server:app" in start
    assert re.search(r"--workers\s+1\b", start), (
        "gunicorn must run ONE worker process: rate limits, TI quotas and caches "
        "are in process memory, so N workers make every limit N times looser. "
        "Move that state to a shared store before raising this."
    )
    assert re.search(r"--worker-class\s+gthread\b", start)
    assert re.search(r"--threads\s+\d+", start)
