"""Check the public test-count claims against the suite pytest collects.

README.md and the overview page (frontend/src/overview.jsx) state how many
tests ADTE has. A claim above the collected count is false, so it fails the
run. A claim under 90% of the collected count is only stale, so it warns (a
GitHub annotation in CI) and passes. A file with no claim fails too: a
rephrased claim must not turn this check into a silent pass.

Usage: python tools/check_public_claims.py
Collects with the running interpreter (`python -m pytest --collect-only`).
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STALE_RATIO = 0.9

# (file, pattern); group 1 is the claimed count.
CLAIMS = [
    ("README.md", re.compile(r"\b(\d[\d,]*)\+?\s+tests\b")),
    (
        "frontend/src/overview.jsx",
        re.compile(r"value:\s*'(\d[\d,]*)\+?',\s*label:\s*'Automated Tests'"),
    ),
]
COLLECTED = re.compile(r"^(\d+) tests? collected", re.MULTILINE)


def collected_count() -> int:
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    ).stdout
    match = COLLECTED.search(out)
    if match is None:
        sys.exit(f"could not read the collected count from pytest:\n{out[-2000:]}")
    return int(match.group(1))


def main() -> int:
    collected = collected_count()
    print(f"pytest collects {collected} tests")
    failed = False
    for rel, pattern in CLAIMS:
        lines = (ROOT / rel).read_text(encoding="utf-8").splitlines()
        found = 0
        for lineno, line in enumerate(lines, start=1):
            for match in pattern.finditer(line):
                found += 1
                claim = int(match.group(1).replace(",", ""))
                where = f"{rel}:{lineno}"
                if claim > collected:
                    failed = True
                    print(
                        f"::error file={rel},line={lineno}::claims {claim} tests, "
                        f"but pytest collects {collected}"
                    )
                    print(f"FAIL {where}: claims {claim}, collected {collected}")
                elif claim < STALE_RATIO * collected:
                    print(
                        f"::warning file={rel},line={lineno}::claims {claim} tests, "
                        f"pytest collects {collected} (stale)"
                    )
                    print(f"STALE {where}: claims {claim}, collected {collected}")
                else:
                    print(f"ok {where}: claims {claim}")
        if found == 0:
            failed = True
            print(f"FAIL {rel}: no test-count claim found; update the pattern in {__file__}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
