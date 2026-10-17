"""Incident Drill — synthetic attack scenarios an analyst works through ADTE.

A drill generates a deterministic alert set (one scripted attack chain plus
benign noise) from a scenario ID, a seed and a noise level, triages it through
the same per-alert path as ``/api/triage/batch``, and later grades the
analyst's dispositions against ground truth that never leaves the server
until the report is requested.

Modules:
  ``schema``    — pydantic request, run and ground-truth models.
  ``scenarios`` — the public scenario catalogue.
  ``generator`` — seed → incidents + ground truth.
  ``debrief``   — dispositions vs ground truth, and the incident report.

Every drill incident ID starts with ``audit_log.DRILL_ID_PREFIX`` so the audit
log can hide drill rows by default.  Every IP comes from a reserved range, and
the threat-intel aggregator never sends a reserved address to a live provider:
RFC 5737 documentation addresses get its deterministic mock in every mode,
RFC 6598 shared addresses get the mock without API keys and a neutral
``shared-address-space`` result with them, and RFC 1918 internal hosts take
the private-address short-circuit.  So a drill makes no network calls, and a
seed replays the same verdicts, risk scores and confidence with or without
live API keys; only the threat-intel evidence shown for RFC 6598 addresses
changes.

NIST 800-61 Phase: Preparation — exercises the detection-and-analysis
workflow on synthetic data before a real incident needs it.
"""
