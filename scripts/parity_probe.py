"""Golden-parity probe for the Workstream B engine fix (Waiver #2).

Runs the deterministic triage pipeline over every example incident and writes
one JSON dump plus a sha256 per example, so the pre-change and post-change
outputs can be compared byte-for-byte.

Determinism contract (matches how the Phase 31/32 golden pins were captured):
  * every threat-intel and LLM key is stripped from the environment BEFORE the
    adte package is imported, forcing the mock/synthetic fallbacks
  * imports adte.engine / adte.models / adte.adapters.wazuh directly, never
    adte.cli or adte.server -- both of those call load_dotenv() at import time
    and would pull the real keys in examples/../.env back into the process
  * cluster_context=None -- solo alerts, no correlated siblings

Usage:  .venv/Scripts/python.exe scripts/parity_probe.py <out_dir>
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

# --- determinism gate: strip before importing anything from adte -------------
_VOLATILE_KEYS = [
    "ANTHROPIC_API_KEY",
    "ADTE_ABUSEIPDB_KEY",
    "ADTE_VT_API_KEY",
    "ADTE_OTX_KEY",
    "ADTE_WAZUH_HOST",
    "ADTE_WAZUH_USER",
    "ADTE_WAZUH_PASS",
]
for _key in _VOLATILE_KEYS:
    os.environ.pop(_key, None)

from adte.adapters.wazuh import WazuhAdapter  # noqa: E402
from adte.engine import TriageEngine  # noqa: E402
from adte.intel.sigma_fp_registry import FPRegistry  # noqa: E402
from adte.models import NormalizedIncident, SentinelIncident  # noqa: E402
from adte.store.user_history import get_user_profile  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
EXAMPLES = REPO / "examples"

# Identity incidents -- canonical NormalizedIncident payloads.  These carry the
# non-file golden pins (99/99/5/43) that MUST stay byte-identical.
IDENTITY = [
    "incident_account_takeover_tor_exfil.json",
    "incident_impossible_travel_mfa_fatigue.json",
    "incident_benign_vpn_travel.json",
    "incident_needs_human_ambiguous.json",
]

# Raw Wazuh malware alerts -- normalised through the real adapter.  These carry
# file evidence, so their scores move BY DESIGN under the F1b/F2 fix.
MALWARE = [
    "wazuh_malware_01_file_added.json",
    "wazuh_malware_02_virustotal_conviction.json",
    "wazuh_malware_03_active_response_deleted.json",
    "wazuh_malware_04_second_host_campaign.json",
]


def triage(incident: NormalizedIncident) -> dict[str, Any]:
    """Run the full deterministic pipeline for one incident."""
    engine = TriageEngine(
        incident,
        get_user_profile(incident.user),
        FPRegistry.load(),
        cluster_context=None,
    )
    return engine.enrich().score().decide().to_output(use_llm=False)


def main() -> int:
    out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO / "_parity_out"
    out_dir.mkdir(parents=True, exist_ok=True)

    manifest: dict[str, dict[str, Any]] = {}

    for name in IDENTITY + MALWARE:
        raw = json.loads((EXAMPLES / name).read_text(encoding="utf-8"))
        if name in IDENTITY:
            # Same load path the server's demo seeding uses: these files are
            # raw Sentinel payloads, not canonical NormalizedIncident dicts.
            incident = NormalizedIncident.from_sentinel(SentinelIncident(**raw))
        else:
            incident = WazuhAdapter.normalize_alert(raw)

        output = triage(incident)
        # The ONLY non-deterministic field in the output is the wall-clock
        # stamp written by _build_report (adte/engine.py:971).  Scrub that one
        # path by name -- a blanket sweep for every "timestamp" key would also
        # erase incident/event timestamps and could hide a real regression.
        # Assert first: if a refactor moves the key, this must fail loudly
        # rather than silently produce a false parity pass.
        assert "timestamp" in output["report"], "report.timestamp missing -- probe is stale"
        output["report"]["timestamp"] = "<SCRUBBED:wall-clock>"
        blob = json.dumps(output, indent=2, sort_keys=True, default=str)
        (out_dir / f"{name}.out.json").write_text(blob, encoding="utf-8")

        manifest[name] = {
            "sha256": hashlib.sha256(blob.encode("utf-8")).hexdigest(),
            "verdict": output["verdict"],
            "risk_score": output["risk_score"],
            "confidence": output["confidence"],
            "signals": [r["signal"] for r in output["rationale"]],
            "file_reputation": next(
                (r for r in output["rationale"] if r["signal"] == "file_reputation"),
                None,
            ),
        }

    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )

    for name, entry in manifest.items():
        fr = entry["file_reputation"]
        fr_str = f" file_rep={fr['score']}" if fr else ""
        print(
            f"{entry['sha256'][:16]}  {entry['verdict']:<12} "
            f"{entry['risk_score']:>3}/{entry['confidence']:<3}{fr_str}  {name}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
