"""Which commit is running, for the ``GET /version`` deploy-truth check."""

from __future__ import annotations

import functools
import os
import re
import subprocess
from pathlib import Path

_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")
_REPO_ROOT = Path(__file__).resolve().parents[1]


@functools.lru_cache(maxsize=1)
def _git_head() -> str | None:
    """HEAD of the checkout this file lives in; None if git is absent or fails."""
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=2,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    return out if _SHA_RE.match(out) else None


def get_version() -> dict[str, str]:
    """``{"commit", "source"}``. Railway sets RAILWAY_GIT_COMMIT_SHA on deploy;
    locally fall back to git, else "unknown". Never echoes anything else."""
    sha = os.environ.get("RAILWAY_GIT_COMMIT_SHA", "").strip().lower()
    if _SHA_RE.match(sha):
        return {"commit": sha, "source": "railway"}
    sha = _git_head()
    if sha:
        return {"commit": sha, "source": "git"}
    return {"commit": "unknown", "source": "unknown"}
