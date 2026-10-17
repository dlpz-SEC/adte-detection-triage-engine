"""Incident Drill grading and incident report.

Two outputs, built from the server-side re-score of a drill run:

``build_debrief`` grades the analyst's dispositions against ground truth and
derives tuning findings from what ADTE actually scored.  It is the only place
ground truth leaves the server.

``build_report`` is the analyst's incident report.  It is built only from the
alerts the analyst confirmed as true positives, so it describes what the
analyst concluded, never the answer key.  Recommended actions are copied from
the engine's recommend-only action lists, minus ADTE's close-and-baseline
advice for alerts the analyst confirmed (the tuning list records that
disagreement instead): ADTE recommends, it never executes.

NIST 800-61 Phase: Post-Incident Activity — lessons learned and reporting
for a training exercise.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from adte.case_policy import KILL_CHAIN_RANK
from adte.intel.nist_csf import CSF_SUBCATEGORIES
from adte.simulation.scenarios import SCENARIOS
from adte.simulation.schema import Disposition, DrillRun

REPORT_BANNER: str = "Synthetic drill: not a real incident."

_FLAGGED = ("medium_risk", "high_risk")

# The engine's low_risk actions.  On an alert the analyst confirmed as
# malicious they are the opposite of containment, so the report drops them.
_DISMISSAL_ACTIONS = frozenset({"auto_close_incident", "update_baseline"})

# What to tune when a signal fires on a benign alert.
_SIGNAL_TUNING: dict[str, str] = {
    "impossible_travel": (
        "impossible_travel fires on VPN egress moves and on failed GeoIP lookups "
        "(0,0). Register known VPN egress ranges as known-benign and treat a 0,0 "
        "location as missing, not as a place."
    ),
    "device_novelty": (
        "device_novelty fires on refreshed hardware. Feed device enrolment into the "
        "device baseline so a newly issued laptop is known."
    ),
    "login_hour_anomaly": (
        "login_hour_anomaly fires on on-call and deadline work. Give rotations their "
        "own baseline hours."
    ),
    "mfa_fatigue": (
        "mfa_fatigue counted ordinary failed sign-ins as MFA denials. Distinguish a "
        "denied MFA prompt from a wrong password before scoring fatigue."
    ),
}


_INTERNAL_NETWORKS = tuple(
    ipaddress.IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def _is_internal(ip: str) -> bool:
    """True for RFC 1918 addresses, which are scope, not indicators."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _INTERNAL_NETWORKS)


def _alert_ok(result: dict[str, Any]) -> bool:
    return bool(result.get("ok"))


def _fired(result: dict[str, Any]) -> list[str]:
    return [r["signal"] for r in result.get("rationale", []) if r.get("score")]


def _attack_case(cases: list[dict[str, Any]], members: set[int]) -> dict[str, Any] | None:
    """The case holding the most of *members* (result indices), if any."""
    best, best_hits = None, 0
    for case in cases:
        hits = len(members.intersection(case.get("member_indices", [])))
        if hits > best_hits:
            best, best_hits = case, hits
    return best


def build_debrief(
    run: DrillRun,
    results: list[dict[str, Any]],
    cases: list[dict[str, Any]],
    dispositions: list[Disposition],
) -> dict[str, Any]:
    """Grade dispositions against ground truth and derive tuning findings.

    A call is ``correct`` when it gets malicious-versus-benign right (true
    positive for an attack alert, benign or false positive for noise).
    ``exact`` additionally requires the benign-versus-false-positive
    distinction the scenario expects.  Escalation is expected for attack
    alerts and only for them.

    Args:
        run: The regenerated run (incidents + ground truth).
        results: Re-scored results, index-aligned with ``run.incidents``.
        cases: Case summaries from the re-score (``member_indices`` set).
        dispositions: The analyst's calls (indices validated by the caller).

    Returns:
        ``{"summary", "alerts", "findings", "lessons", "kill_chain"}``.
    """
    scenario = SCENARIOS[run.scenario]
    calls = {d.index: d for d in dispositions}
    malicious = {i for i, s in enumerate(run.truth) if s.label == "malicious"}

    rows: list[dict[str, Any]] = []
    for i, (incident, stage) in enumerate(zip(run.incidents, run.truth)):
        result = results[i] if i < len(results) else {}
        d = calls.get(i)
        verdict = result.get("verdict") if _alert_ok(result) else None
        rows.append(
            {
                "index": i,
                "incident_id": incident.incident_id,
                "truth": stage.label,
                "expected_call": stage.expected_call,
                "title": stage.title,
                "why": stage.why,
                "tactic": stage.tactic,
                "analyst_call": d.call if d else None,
                "escalated": d.escalate if d else False,
                "rationale": d.rationale if d else "",
                "correct": None if d is None else (d.call == "true_positive") == (i in malicious),
                "exact": None if d is None else d.call == stage.expected_call,
                "adte_verdict": verdict,
                "adte_risk": result.get("risk_score") if verdict else None,
                "adte_signals": _fired(result) if verdict else [],
            }
        )

    graded = [r for r in rows if r["correct"] is not None]
    correct = sum(1 for r in graded if r["correct"])
    summary = {
        "alerts": len(rows),
        "malicious": len(malicious),
        "benign": len(rows) - len(malicious),
        "dispositioned": len(graded),
        "correct": correct,
        "exact": sum(1 for r in graded if r["exact"]),
        "accuracy": round(correct / len(graded), 3) if graded else None,
        "missed_malicious": [
            r["index"]
            for r in rows
            if r["truth"] == "malicious" and r["analyst_call"] != "true_positive"
        ],
        "benign_called_malicious": [
            r["index"]
            for r in rows
            if r["truth"] == "benign" and r["analyst_call"] == "true_positive"
        ],
        "benign_escalated": [r["index"] for r in rows if r["truth"] == "benign" and r["escalated"]],
        "malicious_not_escalated": [
            r["index"] for r in rows if r["truth"] == "malicious" and not r["escalated"]
        ],
        "undispositioned": [r["index"] for r in rows if r["analyst_call"] is None],
        "adte_flagged_malicious": sum(
            1 for r in rows if r["truth"] == "malicious" and r["adte_verdict"] in _FLAGGED
        ),
        "adte_low_on_malicious": [
            r["index"]
            for r in rows
            if r["truth"] == "malicious" and r["adte_verdict"] == "low_risk"
        ],
        "adte_flagged_benign": [
            r["index"] for r in rows if r["truth"] == "benign" and r["adte_verdict"] in _FLAGGED
        ],
    }

    findings: list[str] = []
    low = summary["adte_low_on_malicious"]
    if low:
        findings.append(
            f"ADTE scored {len(low)} of {len(malicious)} attack alerts low_risk on their own "
            f"({', '.join(rows[i]['title'] for i in low)}). Per-alert scoring has no detector "
            "for this behaviour; case correlation is what tied these alerts to the attack."
        )
    for signal in sorted(
        {s for i in summary["adte_flagged_benign"] for s in rows[i]["adte_signals"]}
    ):
        if signal in _SIGNAL_TUNING:
            findings.append(_SIGNAL_TUNING[signal])
    for r in rows:
        natives = {t for e in run.incidents[r["index"]].events for t in e.technique_ids}
        if "mfa_fatigue" in r["adte_signals"] and any(t.startswith("T1110") for t in natives):
            findings.append(
                f"{r['incident_id']}: mfa_fatigue fired on password-guessing failures and "
                "attributed them to T1621 (MFA Request Generation). ADTE counts every failed "
                "authentication as an MFA denial; the alert's own technique is T1110."
            )
    boosted = [
        r for r in rows if r["truth"] == "malicious" and "cluster_context" in r["adte_signals"]
    ]
    if boosted:
        findings.append(
            f"Case correlation (cluster_context) raised {len(boosted)} attack alerts above "
            "their standalone score."
        )

    case = _attack_case(cases, malicious)
    kill_chain = (case or {}).get("kill_chain") or {"detected": False, "tactics_in_order": []}
    return {
        "summary": summary,
        "alerts": rows,
        "findings": findings,
        "lessons": list(scenario.lessons),
        "kill_chain": kill_chain,
    }


def _host_or_user(user: str) -> tuple[str, str]:
    """Split a host identity (``host\\system``) from a user principal."""
    if "\\" in user:
        return "host", user.split("\\", 1)[0]
    return "user", user


def build_report(
    run: DrillRun,
    results: list[dict[str, Any]],
    cases: list[dict[str, Any]],
    dispositions: list[Disposition],
    notes: str,
) -> dict[str, Any]:
    """Build the analyst's incident report from their true-positive calls.

    Args:
        run: The regenerated run.
        results: Re-scored results, index-aligned with ``run.incidents``.
        cases: Case summaries from the re-score.
        dispositions: The analyst's calls.
        notes: The analyst's free-text lessons-learned notes.

    Returns:
        The structured report dict (rendered by ``report_markdown``).
    """
    scenario = SCENARIOS[run.scenario]
    calls = {d.index: d for d in dispositions}
    confirmed = sorted(
        (
            i
            for i, d in calls.items()
            if d.call == "true_positive" and i < len(results) and _alert_ok(results[i])
        ),
        key=lambda i: run.incidents[i].events[0].timestamp,
    )

    users: set[str] = set()
    hosts: set[str] = set()
    ips: set[str] = set()
    hashes: dict[str, str] = {}
    csf: set[str] = set()
    tactics: dict[str, dict[str, str]] = {}
    actions: list[str] = []
    timeline: list[dict[str, Any]] = []
    for i in confirmed:
        incident, result = run.incidents[i], results[i]
        kind, name = _host_or_user(incident.user)
        (hosts if kind == "host" else users).add(name)
        for e in incident.events:
            if e.ip_address and not _is_internal(e.ip_address):
                ips.add(e.ip_address)
            if e.file and e.file.sha256:
                verdict = (
                    f"{e.file.vt_positives}/{e.file.vt_total}" if e.file.vt_total else "no verdict"
                )
                hashes.setdefault(e.file.sha256, f"{e.file.path} (VirusTotal {verdict})")
        csf.update((result.get("report") or {}).get("nist_phases") or [])
        for t in result.get("mitre_details") or []:
            if t.get("tactic"):
                tactics.setdefault(t["tactic"], {})[t["id"]] = t.get("name") or t["id"]
        for a in result.get("actions") or []:
            if a not in _DISMISSAL_ACTIONS and a not in actions:
                actions.append(a)
        timeline.append(
            {
                "time": incident.events[0].timestamp.isoformat(),
                "incident_id": incident.incident_id,
                "subject": name,
                "apps": sorted({e.app_display_name for e in incident.events if e.app_display_name}),
                "techniques": [t["id"] for t in result.get("mitre_details") or []],
                "adte_verdict": result.get("verdict"),
                "adte_risk": result.get("risk_score"),
            }
        )

    attack_case = _attack_case(cases, set(confirmed))
    if confirmed:
        summary = (
            f"The analyst confirmed {len(confirmed)} of {len(run.incidents)} alerts as malicious, "
            f"involving {len(users)} user account(s) and {len(hosts)} host(s)."
        )
        # Claim only what the case covers: two or more confirmed alerts in it,
        # and the kill chain attributed to the case, not to the confirmed set.
        members = set((attack_case or {}).get("member_indices", []))
        in_case = [i for i in confirmed if i in members]
        chain = (attack_case or {}).get("kill_chain") or {}
        if len(in_case) >= 2 and chain.get("detected"):
            lead = "them" if len(in_case) == len(confirmed) else f"{len(in_case)} of them"
            summary += (
                f" ADTE correlated {lead} into one case of {len(members)} alerts, "
                "whose detected kill chain spans " + ", ".join(chain["tactics_in_order"]) + "."
            )
    else:
        summary = "The analyst confirmed no alerts as malicious."

    rows = []
    for i, incident in enumerate(run.incidents):
        result = results[i] if i < len(results) else {}
        d = calls.get(i)
        rows.append(
            {
                "index": i,
                "incident_id": incident.incident_id,
                "adte_verdict": result.get("verdict") if _alert_ok(result) else "error",
                "adte_risk": result.get("risk_score") if _alert_ok(result) else None,
                "analyst_call": d.call if d else None,
                "escalated": d.escalate if d else False,
                "rationale": d.rationale if d else "",
            }
        )

    # Both directions of disagreement, from the analyst's calls only: ADTE
    # flagged what the analyst cleared, or scored low what the analyst confirmed.
    tuning = []
    for row in rows:
        if row["adte_verdict"] == "error" or row["analyst_call"] is None:
            continue
        signals = ", ".join(_fired(results[row["index"]])) or "no signal"
        if (
            row["analyst_call"] in ("benign_positive", "false_positive")
            and row["adte_verdict"] in _FLAGGED
        ):
            tuning.append(
                f"{row['incident_id']}: ADTE scored {row['adte_verdict']} "
                f"({row['adte_risk']}) but the analyst called it {row['analyst_call']} "
                f"(signals: {signals})."
            )
        elif row["analyst_call"] == "true_positive" and row["adte_verdict"] == "low_risk":
            tuning.append(
                f"{row['incident_id']}: ADTE scored low_risk ({row['adte_risk']}) and "
                "recommended auto-close, but the analyst confirmed it as true_positive "
                f"(signals: {signals})."
            )

    return {
        "banner": REPORT_BANNER,
        "title": f"Incident report: {scenario.name}",
        "drill": {"scenario": run.scenario, "seed": run.seed, "noise": run.noise},
        "summary": summary,
        "detection": [{"id": c, "name": CSF_SUBCATEGORIES.get(c, "")} for c in sorted(csf)],
        "timeline": timeline,
        "scope": {"users": sorted(users), "hosts": sorted(hosts)},
        "iocs": {
            "ips": sorted(ips),
            "file_hashes": [{"sha256": h, "context": c} for h, c in sorted(hashes.items())],
        },
        "attack_by_tactic": [
            {"tactic": t, "techniques": [{"id": k, "name": v} for k, v in sorted(techs.items())]}
            for t, techs in sorted(tactics.items(), key=lambda kv: KILL_CHAIN_RANK.get(kv[0], 99))
        ],
        "verdicts_vs_calls": rows,
        "recommended_actions": actions,
        "recommend_only_note": (
            "ADTE recommends these actions; it never executes them. Containment, "
            "eradication and recovery are performed by the responder."
        ),
        "analyst_notes": notes.strip(),
        "tuning": tuning,
    }


def _cell(value: Any) -> str:
    """Make a value safe for one markdown table cell."""
    text = "" if value is None else str(value)
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def report_markdown(report: dict[str, Any]) -> str:
    """Render a ``build_report`` dict as a downloadable markdown document.

    Args:
        report: The structured report.

    Returns:
        Markdown text.  Analyst-supplied text is confined to table cells
        (pipes and newlines escaped) or an indented block, so it cannot add
        headings or break the table layout.
    """
    d = report["drill"]
    out = [
        f"# {report['title']}",
        "",
        f"> **{report['banner']}** Scenario `{d['scenario']}`, seed `{d['seed']}`, "
        f"noise `{d['noise']}`.",
        "",
        "## Summary",
        "",
        report["summary"],
        "",
        "## Detection (NIST CSF 2.0)",
        "",
    ]
    out += [f"- **{c['id']}** {c['name']}" for c in report["detection"]] or ["- None"]
    out += [
        "",
        "## Timeline",
        "",
        "| Time (UTC) | Incident | Subject | Techniques | ADTE |",
        "|---|---|---|---|---|",
    ]
    out += [
        f"| {_cell(t['time'])} | {_cell(t['incident_id'])} | {_cell(t['subject'])} | "
        f"{_cell(', '.join(t['techniques']))} | {_cell(t['adte_verdict'])} ({_cell(t['adte_risk'])}) |"
        for t in report["timeline"]
    ]
    scope = report["scope"]
    out += [
        "",
        "## Scope",
        "",
        f"- Users: {', '.join(scope['users']) or 'none'}",
        f"- Hosts: {', '.join(scope['hosts']) or 'none'}",
        "",
        "## Indicators of compromise",
        "",
    ]
    out += [f"- IP `{ip}`" for ip in report["iocs"]["ips"]]
    out += [
        f"- SHA-256 `{h['sha256']}`: {_cell(h['context'])}" for h in report["iocs"]["file_hashes"]
    ]
    if not report["iocs"]["ips"] and not report["iocs"]["file_hashes"]:
        out.append("- None")
    out += ["", "## ATT&CK by tactic", ""]
    out += [
        f"- **{_cell(t['tactic'])}**: "
        + ", ".join(f"{x['id']} {x['name']}" for x in t["techniques"])
        for t in report["attack_by_tactic"]
    ] or ["- None"]
    out += [
        "",
        "## ADTE verdicts vs analyst calls",
        "",
        "| # | Incident | ADTE | Analyst call | Escalated | Rationale |",
        "|---|---|---|---|---|---|",
    ]
    out += [
        f"| {r['index']} | {_cell(r['incident_id'])} | {_cell(r['adte_verdict'])} "
        f"({_cell(r['adte_risk'])}) | {_cell(r['analyst_call'] or 'not reviewed')} | "
        f"{'yes' if r['escalated'] else 'no'} | {_cell(r['rationale'])} |"
        for r in report["verdicts_vs_calls"]
    ]
    out += [
        "",
        "## Recommended containment, eradication and recovery",
        "",
        f"_{report['recommend_only_note']}_",
        "",
    ]
    out += [f"- {_cell(a)}" for a in report["recommended_actions"]] or ["- None"]
    out += ["", "## Lessons learned and tuning", ""]
    if report["analyst_notes"]:
        out += ["Analyst notes:", ""]
        out += ["    " + line for line in report["analyst_notes"].splitlines()]
        out.append("")
    out += [f"- {_cell(t)}" for t in report["tuning"]] or ["- No disagreements with ADTE."]
    return "\n".join(out) + "\n"
