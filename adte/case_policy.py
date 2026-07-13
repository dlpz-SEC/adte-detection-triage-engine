"""Case policy: correlation windows, kill-chain ordering, and case scoring.

Centralises all tuneable constants and pure functions that govern how the
correlation layer groups triaged alerts into cases and escalates them.  This
module is the case-level analogue of :mod:`adte.decision_policy` — it reads
no incident fields, performs no I/O, and is freely editable without a
change-control decision.

The case layer is strictly **post-scoring**: per-alert verdicts produced by
the triage engine are never modified.  A case aggregates member alerts that
share an entity (source IP or user) inside a rolling time window and receives
its own score, verdict, and explainable escalation rationale — e.g. three
medium-risk alerts from one IP whose techniques walk Credential Access →
Lateral Movement → Exfiltration escalate the *case* to high risk even though
no single alert crossed the threshold.

NIST 800-61 Phase: Detection & Analysis — correlation of related events is
an explicit Detection & Analysis activity (SP 800-61r2 §3.2.4).
"""

from __future__ import annotations

from typing import Any

from adte.decision_policy import classify_verdict

# ---------------------------------------------------------------------------
# Correlation window and retention
# ---------------------------------------------------------------------------

CASE_WINDOW_MINUTES: int = 60
"""Rolling correlation window.  An alert joins an existing case only when the
case's last activity (ingestion clock) is within this many minutes.  Sized for
both live streams and analyst-paced manual triage; "same IP hitting three
rules in 10 minutes" correlates at any value >= 10."""

CASE_RETENTION_DAYS: int = 30
"""Cases idle longer than this are hard-deleted on the next ingest.  Cases are
derived data — the ``verdicts`` audit table remains the forensic record — so a
lighter retention policy than the soft-delete-only audit log is appropriate."""

CASE_MAX_RELATED_IDS: int = 20
"""Maximum number of related incident IDs echoed on a triage response."""

CASE_MAX_MEMBERS: int = 150
"""Maximum member alerts per case.  A full case stops accepting joins — the
next matching alert opens a fresh case (Microsoft Sentinel caps incidents at
150 alerts for the same reason).  Bounds the per-ingest recompute (which runs
inside the store's write transaction) against alert floods."""

CASE_MAX_TECHNIQUE_IDS: int = 50
"""Maximum technique IDs stored per member.  Alert sources control
``technique_ids`` content, so an oversized hostile list is truncated rather
than persisted verbatim (tactic names are already bounded by the YAML map)."""

CASE_MAX_IPS_PER_MEMBER: int = 50
"""Maximum correlation/display IPs kept per member alert.  The same
source-controlled reasoning as :data:`CASE_MAX_TECHNIQUE_IDS`: event lists
are unbounded on input, so a many-IP alert is truncated rather than allowed
to inflate the per-ingest matching work."""

CASE_MAX_CASE_IPS: int = 500
"""Ceiling on a case's unioned IP set.  Beyond this the case stops absorbing
new IP keys (existing keys still match), bounding the JSON blob rewritten
inside the write transaction and the correlation gravity of a single case."""

CASE_MAX_HASHES_PER_MEMBER: int = 10
"""Maximum correlation file hashes kept per member alert (Phase 32).  Same
hostile-input-bounding rationale as :data:`CASE_MAX_IPS_PER_MEMBER`: event
lists are source-controlled, so a many-hash alert is truncated rather than
allowed to inflate per-ingest matching work."""

CASE_MAX_CASE_HASHES: int = 200
"""Ceiling on a case's unioned file-hash set (Phase 32).  Mirrors
:data:`CASE_MAX_CASE_IPS` — beyond this the case stops absorbing new hash
keys (existing keys still match)."""

# ---------------------------------------------------------------------------
# Correlation keys
# ---------------------------------------------------------------------------

NON_CORRELATABLE_USER_LOCALS: frozenset[str] = frozenset(
    {"system", "local service", "network service", "unknown", ""}
)
"""Lower-cased user local-parts that must never act as a correlation key.
Wazuh synthesises ``<AGENT>\\system`` for host-level events; letting that
pseudo-user correlate would glue every system alert from one agent into a
single mega-case.  Such alerts still correlate by source IP."""

# ---------------------------------------------------------------------------
# ATT&CK kill-chain ordering
# ---------------------------------------------------------------------------

KILL_CHAIN_ORDER: tuple[str, ...] = (
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
)
"""The 14 MITRE ATT&CK Enterprise tactics in canonical kill-chain order.
Tactic *names* match the ``mitre_tactic`` strings in
``adte/data/mitre_technique_map.yaml`` exactly; nothing else in the codebase
carries an ordering, so this constant is the single source of truth."""

KILL_CHAIN_RANK: dict[str, int] = {t: i for i, t in enumerate(KILL_CHAIN_ORDER)}
"""Tactic name → position in :data:`KILL_CHAIN_ORDER` (0-based)."""

KILL_CHAIN_MIN_TACTICS: int = 3
"""Minimum length of an ascending tactic progression to count as a chain."""

KILL_CHAIN_MIN_MEMBERS: int = 2
"""A progression must span at least this many distinct member alerts.  A
single alert carrying three techniques is tactic *breadth*, not cross-alert
*progression* — correlation is the feature being rewarded here.

NOTE: the detection DP tracks a *binary* crossed-members property, so the
only supported values are 1 (allow single-alert chains) and 2 (require a
cross-alert progression).  Values above 2 behave as 2 — see
:func:`detect_kill_chain` before tuning upward (a test pins this)."""

# ---------------------------------------------------------------------------
# Case scoring bonuses (structural uplift on top of the worst member)
# ---------------------------------------------------------------------------

MULTI_ALERT_BONUS: int = 5
"""Points per correlated alert beyond the first."""

MULTI_ALERT_BONUS_CAP: int = 15
"""Ceiling for the multi-alert bonus."""

TACTIC_BREADTH_BONUS: int = 5
"""Points per distinct ATT&CK tactic beyond the first across all members."""

TACTIC_BREADTH_BONUS_CAP: int = 15
"""Ceiling for the tactic-breadth bonus."""

KILL_CHAIN_BONUS: int = 20
"""Points added when an ascending kill-chain progression is detected.
Total structural uplift is capped at 50 (15 + 15 + 20), so a low-risk-only
case (base <= 29) cannot exceed 79 — volume alone never fabricates a
high-risk case without genuine breadth *and* progression."""


def detect_kill_chain(
    member_tactics: list[tuple[Any, list[str]]],
) -> dict[str, Any]:
    """Detect an ascending ATT&CK kill-chain progression across case members.

    A progression is a strictly rank-increasing subsequence of tactics (per
    :data:`KILL_CHAIN_ORDER`) drawn from members in chronological order, of
    length >= :data:`KILL_CHAIN_MIN_TACTICS`, spanning at least two distinct
    members when :data:`KILL_CHAIN_MIN_MEMBERS` >= 2 (the DP tracks a binary
    crossed-members property — values above 2 behave as 2).  Gaps are allowed
    (Credential Access → Exfiltration chains even with Discovery missing).
    Within one member, tactics are treated as simultaneous and may contribute
    in rank order.  The search is a longest-increasing-subsequence dynamic
    programme rather than a greedy walk, so an out-of-order arrival (e.g. an
    Exfiltration alert ingested first) never masks a real chain.

    Args:
        member_tactics: Chronologically ordered ``(member_key, tactic_names)``
            pairs, one per member alert.  Unknown tactic names are ignored;
            duplicate tactics within a member are deduplicated.

    Returns:
        ``{"detected": bool, "tactics_in_order": [str, ...]}`` where
        ``tactics_in_order`` is the winning progression (empty when not
        detected).
    """
    # Flatten to (rank, member_index) elements; within a member, ascending.
    seq: list[tuple[int, int]] = []
    for m_idx, (_key, tactics) in enumerate(member_tactics):
        ranks = sorted({KILL_CHAIN_RANK[t] for t in tactics if t in KILL_CHAIN_RANK})
        seq.extend((rank, m_idx) for rank in ranks)

    n = len(seq)
    if n == 0:
        return {"detected": False, "tactics_in_order": []}

    # DP over the flattened sequence.  For each element i track the longest
    # strictly-increasing chain ending at i that (a) stays within element i's
    # member ("single") and (b) spans >= 2 distinct members ("multi").  The
    # member-span requirement cannot be bolted onto a plain LIS afterwards:
    # the longest chain may sit inside one member while a shorter qualifying
    # chain crosses members.
    single = [1] * n
    multi = [0] * n  # 0 = no multi-member chain ends here
    parent_single = [-1] * n
    parent_multi = [-1] * n
    multi_via_single = [False] * n  # predecessor link came from a single chain

    for i in range(n):
        rank_i, member_i = seq[i]
        for j in range(i):
            rank_j, member_j = seq[j]
            if rank_j >= rank_i:
                continue
            if member_j == member_i and single[j] + 1 > single[i]:
                single[i] = single[j] + 1
                parent_single[i] = j
            if multi[j] > 0 and multi[j] + 1 > multi[i]:
                multi[i] = multi[j] + 1
                parent_multi[i] = j
                multi_via_single[i] = False
            if member_j != member_i and single[j] + 1 > multi[i]:
                multi[i] = single[j] + 1
                parent_multi[i] = j
                multi_via_single[i] = True

    candidates = multi if KILL_CHAIN_MIN_MEMBERS >= 2 else [
        max(s, m) for s, m in zip(single, multi)
    ]
    best_end = max(range(n), key=lambda i: candidates[i])
    if candidates[best_end] < KILL_CHAIN_MIN_TACTICS:
        return {"detected": False, "tactics_in_order": []}

    # Reconstruct the winning chain by walking parent pointers backwards.
    chain: list[int] = []
    idx = best_end
    on_multi = KILL_CHAIN_MIN_MEMBERS >= 2 or multi[idx] >= single[idx]
    while idx != -1:
        chain.append(idx)
        if on_multi:
            next_idx = parent_multi[idx]
            if multi_via_single[idx]:
                on_multi = False
        else:
            next_idx = parent_single[idx]
        idx = next_idx
    chain.reverse()
    return {
        "detected": True,
        "tactics_in_order": [KILL_CHAIN_ORDER[seq[i][0]] for i in chain],
    }


def score_case(
    member_scores: list[float],
    distinct_tactic_count: int,
    kill_chain: dict[str, Any],
    top_member_incident_id: str,
) -> tuple[int, str, bool, list[dict[str, Any]]]:
    """Score a case from its members and produce an explainable rationale.

    The formula mirrors the engine's explainability contract: every point in
    the case score is attributable to a named factor::

        case_score = min(100, base                       # worst member
                            + multi-alert bonus (capped)
                            + tactic-breadth bonus (capped)
                            + kill-chain bonus)

    ``escalated`` is True when correlation changed the verdict *class* — the
    case verdict differs from what the worst member alone would classify as.

    Args:
        member_scores: Per-member risk scores (0-100), one per member alert.
        distinct_tactic_count: Count of distinct ATT&CK tactics across all
            members' techniques.
        kill_chain: Result of :func:`detect_kill_chain`.
        top_member_incident_id: Incident ID of the highest-scoring member
            (used only in the rationale detail text).

    Returns:
        Tuple of ``(case_score, case_verdict, escalated,
        escalation_rationale)`` where the rationale is a list of
        ``{"factor", "detail", "points"}`` dicts whose points sum to the
        case score.
    """
    if not member_scores:
        return 0, classify_verdict(0), False, []

    base = max(0, min(100, round(max(member_scores))))
    alert_count = len(member_scores)
    rationale: list[dict[str, Any]] = [
        {
            "factor": "base_max_member",
            "detail": f"Highest member risk score {base} ({top_member_incident_id})",
            "points": base,
        }
    ]

    multi_points = min((alert_count - 1) * MULTI_ALERT_BONUS, MULTI_ALERT_BONUS_CAP)
    if multi_points > 0:
        rationale.append(
            {
                "factor": "multi_alert",
                "detail": (
                    f"{alert_count} correlated alerts in {CASE_WINDOW_MINUTES} min "
                    f"window (+{MULTI_ALERT_BONUS} per extra alert, "
                    f"cap {MULTI_ALERT_BONUS_CAP})"
                ),
                "points": multi_points,
            }
        )

    breadth_points = min(
        max(distinct_tactic_count - 1, 0) * TACTIC_BREADTH_BONUS,
        TACTIC_BREADTH_BONUS_CAP,
    )
    if breadth_points > 0:
        rationale.append(
            {
                "factor": "tactic_breadth",
                "detail": (
                    f"{distinct_tactic_count} distinct ATT&CK tactics "
                    f"(+{TACTIC_BREADTH_BONUS} per extra tactic, "
                    f"cap {TACTIC_BREADTH_BONUS_CAP})"
                ),
                "points": breadth_points,
            }
        )

    chain_points = KILL_CHAIN_BONUS if kill_chain.get("detected") else 0
    if chain_points:
        rationale.append(
            {
                "factor": "kill_chain",
                "detail": (
                    "Ascending kill-chain progression: "
                    + " → ".join(kill_chain.get("tactics_in_order", []))
                ),
                "points": chain_points,
            }
        )

    raw = base + multi_points + breadth_points + chain_points
    case_score = min(100, raw)
    if raw > 100:
        rationale.append(
            {
                "factor": "cap",
                "detail": "Case score capped at 100",
                "points": case_score - raw,
            }
        )

    case_verdict = classify_verdict(case_score)
    escalated = case_verdict != classify_verdict(base)
    return case_score, case_verdict, escalated, rationale
