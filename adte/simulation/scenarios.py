"""Public catalogue of Incident Drill scenarios.

Each entry describes the attack an analyst will be working, without saying
which alerts belong to it.  Every technique ID here must exist in
``adte/data/mitre_technique_map.yaml`` (pinned by a test), because case
tactics and the report's ATT&CK section come from that map.

NIST 800-61 Phase: Preparation — defines the training exercises.
"""

from __future__ import annotations

from adte.simulation.schema import Scenario

SCENARIOS: dict[str, Scenario] = {
    "password-spray": Scenario(
        id="password-spray",
        name="Password spray to account takeover",
        summary=(
            "A burst of failed sign-ins hits several accounts from one source, "
            "then one account signs in successfully and starts looking around "
            "the tenant and pulling files. Benign sign-in noise is mixed in. "
            "Work out which alerts are the attack, which account fell, and what "
            "the attacker touched."
        ),
        difficulty="intro",
        chain=["Credential Access", "Initial Access", "Discovery", "Collection"],
        techniques=["T1110.003", "T1078.004", "T1087", "T1074"],
        lessons=[
            "A password spray tries one password across many accounts, so each "
            "account sees one or two failures. A per-account alert never looks "
            "alarming on its own; the pattern only appears when alerts are "
            "grouped by source IP.",
            "The successful sign-in from the spraying IP is the pivot of the "
            "incident: it is the moment the account fell, even though on its own "
            "it looks like little more than a user on a new device.",
        ],
    ),
    "identity-exfil": Scenario(
        id="identity-exfil",
        name="Identity compromise to data exfiltration",
        summary=(
            "A user signs in from an unfamiliar device and network, changes "
            "their own account settings, gathers a large set of files into one "
            "folder and syncs it to an outside host. Benign sign-in noise is "
            "mixed in. Decide how far the intrusion got and what must be "
            "contained."
        ),
        difficulty="intermediate",
        chain=["Initial Access", "Persistence", "Collection", "Exfiltration"],
        techniques=["T1078.004", "T1098", "T1074", "T1020"],
        lessons=[
            "Persistence on a cloud identity (a new authentication method or a "
            "mailbox rule) outlives a password reset. Containment has to remove "
            "it, not just rotate the password.",
            "Staging (T1074) before exfiltration (T1020) is the last point where "
            "containment still prevents the loss.",
        ],
    ),
    "malware-spread": Scenario(
        id="malware-spread",
        name="Web shell drop and lateral spread",
        summary=(
            "File integrity monitoring reports a new file on a web server. Later "
            "that file runs and drops a second file, the same second file appears "
            "on another host after an SSH login, and that host starts talking to "
            "an outside address. Routine host noise is mixed in. Trace the spread "
            "and scope the hosts."
        ),
        difficulty="advanced",
        chain=["Initial Access", "Execution", "Lateral Movement", "Command and Control"],
        techniques=["T1190", "T1059.004", "T1021.004", "T1071"],
        lessons=[
            "A freshly dropped file often has no VirusTotal detections yet (here "
            "0 of 70 engines). A clean scan at drop time is absence of evidence, "
            "not a verdict: judge the file by where it landed and what it did "
            "next, not by its scan.",
            "The same SHA-256 on a second host is the strongest scoping signal "
            "in this scenario: correlation by hash ties hosts together even when "
            "they share no user or IP.",
        ],
    ),
}
