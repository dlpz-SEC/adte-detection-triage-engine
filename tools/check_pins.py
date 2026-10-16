"""Fail when a Python dependency lacks an upper bound.

CLAUDE.md rule (2026-05-08): every dependency gets both bounds
(`flask>=3.0,<4.0`, never bare `flask>=3.0`), so a future install cannot pull
a breaking major release silently. This script makes the rule a check.

Usage: python check_pins.py FILE...   (pre-commit passes the staged files)
Reads requirements*.txt and pyproject.toml ([project] dependencies and
optional-dependencies). Exit 1 lists every unbounded requirement.

Vendored per repo on purpose: CI on a public repo cannot fetch a private one.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

UPPER = re.compile(r"(<|<=|==|~=|===)\s*[0-9]")
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*")


def bounded(spec: str) -> bool:
    req = spec.split(";", 1)[0].strip()  # drop environment markers
    if not req or "@" in req:  # direct URL references pin themselves
        return True
    return bool(UPPER.search(req))


def from_requirements(path: Path) -> list[str]:
    reqs = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split(" #", 1)[0].strip().rstrip("\\").strip()
        if not line or line.startswith(("#", "-", "--")) or not NAME.match(line):
            continue
        reqs.append(line)
    return reqs


def from_pyproject(path: Path) -> list[str]:
    project = tomllib.loads(path.read_text(encoding="utf-8")).get("project", {})
    reqs = list(project.get("dependencies", []))
    for group in project.get("optional-dependencies", {}).values():
        reqs.extend(group)
    return reqs


def main(argv: list[str]) -> int:
    bad = []
    for name in argv:
        path = Path(name)
        if path.name == "pyproject.toml":
            reqs = from_pyproject(path)
        elif path.suffix == ".txt" and path.name.startswith("requirements"):
            reqs = from_requirements(path)
        else:
            continue
        bad += [f"{path}: {r}" for r in reqs if not bounded(r)]
    for line in bad:
        print(f"no upper bound: {line}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
