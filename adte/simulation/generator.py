"""Deterministic Incident Drill generator: seed → incidents + ground truth.

Rules every run follows (each one pinned by ``tests/test_drill_generator.py``):

- ``random.Random`` seeded with a string, so a seed replays identically in
  every process (string seeds hash with SHA-512, not ``PYTHONHASHSEED``).  The
  attack and the noise draw from separate streams, so changing the noise level
  never changes the attack.
- Timestamps hang off a seed-derived base date, never the wall clock, and
  ``created_time`` is set explicitly (the model default is ``utcnow``).
- Every IP is reserved: attacker infrastructure from the RFC 5737 TEST-NETs,
  benign remote users from RFC 6598 outside the mock feed's ``100.64.0.0/16``,
  internal hosts from ``10.20.0.0/24``.  The threat-intel aggregator answers
  the reserved ranges from its deterministic mock, so a drill makes no
  network call.  Example and false-positive-registry addresses are excluded.
- Every file event carries an embedded VirusTotal verdict with a non-zero
  total, so the engine never makes a live hash lookup; no EICAR hash is used.
- Incident IDs start with ``DRILL_ID_PREFIX`` and are unique within a run.
- At most ``MAX_DRILL_ALERTS`` alerts.

Benign noise is built so it cannot assemble a kill chain on its own: personas
on their own known devices, no malicious IPs, fewer than three failures per
alert, and app names that match no ATT&CK keyword.

NIST 800-61 Phase: Preparation — produces the exercise data.
"""

from __future__ import annotations

import ipaddress
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable

from adte.models import FileArtifact, GeoLocation, NormalizedIncident, SignInMetadata
from adte.simulation.scenarios import SCENARIOS
from adte.simulation.schema import MAX_DRILL_ALERTS, DrillRun, NoiseLevel, Stage
from adte.store.audit_log import DRILL_ID_PREFIX
from adte.store.user_history import DRILL_PERSONA_UPNS, get_user_profile

NOISE_COUNTS: dict[str, int] = {"low": 2, "medium": 5, "high": 8}

# Drill dates fall in a fixed past window so login-hour and travel maths never
# depend on when the drill is run.
_ANCHOR: datetime = datetime(2026, 3, 2, tzinfo=timezone.utc)
_ANCHOR_SPAN_DAYS: int = 120

_ID_CODES: dict[str, str] = {
    "password-spray": "PS",
    "identity-exfil": "IX",
    "malware-spread": "MS",
}

# Never generate these: bundled example/demo addresses and committed
# false-positive-registry entries inside the ranges drills draw from.
_EXCLUDED_IPS: frozenset[str] = frozenset({"198.51.100.23", "203.0.113.5"})

_TEST_NET_1 = ipaddress.IPv4Network("192.0.2.0/24")  # mock: suspicious, never malicious
_TEST_NET_2 = ipaddress.IPv4Network("198.51.100.0/24")  # mock: known C2 (malicious)
_TEST_NET_3 = ipaddress.IPv4Network("203.0.113.0/24")  # mock: malicious proxy
_INTERNAL = ipaddress.IPv4Network("10.20.0.0/24")  # internal hosts (FP registry: corporate)
# RFC 6598 above the mock's 100.64.0.0/16: reserved and unknown to the mock.
_NOISE_FIRST = int(ipaddress.IPv4Address("100.65.0.1"))
_NOISE_LAST = int(ipaddress.IPv4Address("100.127.255.254"))

# Apps whose names match no keyword in the ATT&CK map (an alert with no native
# technique IDs is keyword-matched on app_display_name: "WordPress" contains
# "rdp", "Unmapped" contains "nmap").
_SAFE_APPS: tuple[str, ...] = (
    "Microsoft Teams",
    "Office 365 Exchange Online",
    "Outlook Web",
    "SharePoint Online",
    "Workday",
    "Slack",
    "Salesforce",
)

_ATTACKER_GEOS: tuple[GeoLocation, ...] = (
    GeoLocation(lat=44.4268, lon=26.1025, city="Bucharest", country="RO"),
    GeoLocation(lat=-23.5505, lon=-46.6333, city="Sao Paulo", country="BR"),
    GeoLocation(lat=-6.2088, lon=106.8456, city="Jakarta", country="ID"),
    GeoLocation(lat=-12.0464, lon=-77.0428, city="Lima", country="PE"),
    GeoLocation(lat=14.5995, lon=120.9842, city="Manila", country="PH"),
)
# Short hops from the personas' home cities (all under 800 km).
_TRIP_CITIES: tuple[GeoLocation, ...] = (
    GeoLocation(lat=48.8566, lon=2.3522, city="Paris", country="FR"),
    GeoLocation(lat=50.8503, lon=4.3517, city="Brussels", country="BE"),
    GeoLocation(lat=50.1109, lon=8.6821, city="Frankfurt", country="DE"),
)
_VPN_EGRESS = GeoLocation(lat=1.3521, lon=103.8198, city="Singapore", country="SG")
_NULL_ISLAND = GeoLocation(lat=0.0, lon=0.0, city="", country="")

_SPRAY_TARGETS: tuple[str, ...] = (
    "j.morales",
    "a.ibrahim",
    "k.watanabe",
    "p.silva",
    "r.osei",
    "t.lindqvist",
    "n.haddad",
    "e.kowalski",
)
_SPRAY_UA = "python-requests/2.31.0"
_BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


@dataclass
class _Alert:
    """One alert under construction, before IDs are assigned."""

    user: str
    source: str
    events: list[SignInMetadata]
    stage: Stage
    seq: int = 0


@dataclass
class _Build:
    """Shared state while one run is generated."""

    seed: int
    base: datetime
    used_ips: set[str] = field(default_factory=set)
    alerts: list[_Alert] = field(default_factory=list)

    def add(self, alert: _Alert) -> None:
        """Append an alert, remembering generation order for stable sorting."""
        alert.seq = len(self.alerts)
        self.alerts.append(alert)

    def ip_in(self, rng: random.Random, network: ipaddress.IPv4Network) -> str:
        """Draw an unused, non-excluded host address from *network*."""
        first, last = int(network.network_address) + 10, int(network.broadcast_address) - 5
        return self._draw(rng, first, last)

    def noise_ip(self, rng: random.Random) -> str:
        """Draw an unused benign remote-user address (RFC 6598, mock-unknown)."""
        return self._draw(rng, _NOISE_FIRST, _NOISE_LAST)

    def _draw(self, rng: random.Random, first: int, last: int) -> str:
        while True:
            ip = str(ipaddress.IPv4Address(rng.randint(first, last)))
            if ip not in self.used_ips and ip not in _EXCLUDED_IPS:
                self.used_ips.add(ip)
                return ip


def _hash(rng: random.Random) -> str:
    """A random SHA-256-shaped hex string (never a real sample's hash)."""
    return f"{rng.getrandbits(256):064x}"


def _event(
    user: str,
    ip: str,
    when: datetime,
    kind: str = "authentication",
    **fields: object,
) -> SignInMetadata:
    """Build one event; unset optional fields keep their model defaults."""
    return SignInMetadata(
        user_principal_name=user, ip_address=ip, type=kind, timestamp=when, **fields
    )


def _home(upn: str) -> tuple[GeoLocation, str]:
    """Return a persona's home location and primary device ID."""
    profile = get_user_profile(upn)
    if profile.last_seen_location is None or not profile.known_devices:
        raise RuntimeError(f"drill persona {upn} has no home location or device")
    return profile.last_seen_location, profile.known_devices[0].device_id


# ---------------------------------------------------------------------------
# Attack scenarios.  Each returns the persona it compromised (or None), so
# noise is drawn from the other personas and never shares a user key with
# the attack.
# ---------------------------------------------------------------------------


def _password_spray(rng: random.Random, b: _Build) -> str | None:
    victim = rng.choice(DRILL_PERSONA_UPNS)
    attacker = b.ip_in(rng, _TEST_NET_1)  # fresh infrastructure: not on any feed yet
    geo = rng.choice(_ATTACKER_GEOS)
    targets = rng.sample(_SPRAY_TARGETS, rng.randint(4, 6))
    when = b.base
    for target in targets:
        upn = f"{target}@corp.example"
        when += timedelta(minutes=rng.randint(1, 3), seconds=rng.randint(0, 59))
        b.add(
            _Alert(
                upn,
                "azure_ad",
                [
                    _event(
                        upn,
                        attacker,
                        when,
                        auth_status="failure",
                        location=geo,
                        user_agent=_SPRAY_UA,
                        app_display_name="Office 365 Exchange Online",
                        technique_ids=["T1110.003"],
                    ),
                ],
                Stage(
                    label="malicious",
                    expected_call="true_positive",
                    tactic="Credential Access",
                    technique_ids=["T1110.003"],
                    title=f"Password spray attempt on {upn}",
                    why=(
                        f"One failed sign-in from {attacker}, the same source that tried "
                        f"{len(targets)} accounts within minutes with a scripted client. "
                        "Alone it reads like a typo; grouped by source IP it is a spray."
                    ),
                ),
            )
        )
    device = f"DESKTOP-{rng.getrandbits(16):04X}"
    steps = [
        (
            8,
            "authentication",
            "T1078.004",
            "Initial Access",
            "Office 365 Exchange Online",
            {"auth_status": "success"},
            f"Successful sign-in to {victim} from the spraying IP",
            f"The spray worked: {victim} signed in from {attacker} on a never-seen "
            "device minutes after the failures. This is the moment of compromise.",
        ),
        (
            15,
            "network",
            "T1087",
            "Discovery",
            "Azure Portal",
            {},
            "Directory enumeration from the new session",
            "The compromised session lists users and groups: an attacker learning "
            "the tenant, not a user doing their job.",
        ),
        (
            35,
            "network",
            "T1074",
            "Collection",
            "SharePoint Online",
            {},
            "SharePoint files gathered into one folder",
            "Documents from several sites copied into a single folder: data staged "
            "in one place, the step before exfiltration.",
        ),
    ]
    for minutes, kind, tid, tactic, app, extra, title, why in steps:
        when += timedelta(minutes=minutes)
        b.add(
            _Alert(
                victim,
                "azure_ad",
                [
                    _event(
                        victim,
                        attacker,
                        when,
                        kind,
                        location=geo,
                        device_id=device,
                        device_name=device,
                        user_agent=_BROWSER_UA,
                        app_display_name=app,
                        technique_ids=[tid],
                        **extra,
                    ),
                ],
                Stage(
                    label="malicious",
                    expected_call="true_positive",
                    tactic=tactic,
                    technique_ids=[tid],
                    title=title,
                    why=why,
                ),
            )
        )
    return victim


def _identity_exfil(rng: random.Random, b: _Build) -> str | None:
    victim = rng.choice(DRILL_PERSONA_UPNS)
    attacker = b.ip_in(rng, _TEST_NET_2)  # known C2 infrastructure on the mock feed
    exfil = b.ip_in(rng, _TEST_NET_3)
    geo = rng.choice(_ATTACKER_GEOS)
    device = f"DESKTOP-{rng.getrandbits(16):04X}"
    steps = [
        (
            0,
            attacker,
            "authentication",
            {"auth_status": "success"},
            "T1078.004",
            "Initial Access",
            "Office 365 Exchange Online",
            f"Sign-in to {victim} from known-bad infrastructure",
            f"{attacker} is on a C2 reputation feed and the device is new: a stolen "
            "credential used from attacker infrastructure.",
        ),
        (
            12,
            attacker,
            "authentication",
            {},
            "T1098",
            "Persistence",
            "Azure Portal",
            "New authentication method registered",
            "The intruder registers their own MFA method so a password reset alone "
            "will not lock them out.",
        ),
        (
            40,
            attacker,
            "network",
            {},
            "T1074",
            "Collection",
            "SharePoint Online",
            "Files staged into one OneDrive folder",
            "Hundreds of SharePoint files copied into one folder in a single session: "
            "data staged for exfiltration.",
        ),
        (
            55,
            exfil,
            "network",
            {},
            "T1020",
            "Exfiltration",
            "OneDrive Sync",
            "Staged folder synced to an external host",
            f"A sync job copies the staged folder to {exfil}, outside the organisation: "
            "automated exfiltration, the loss event.",
        ),
    ]
    when = b.base
    for minutes, ip, kind, extra, tid, tactic, app, title, why in steps:
        when += timedelta(minutes=minutes)
        b.add(
            _Alert(
                victim,
                "azure_ad",
                [
                    _event(
                        victim,
                        ip,
                        when,
                        kind,
                        location=geo,
                        device_id=device,
                        device_name=device,
                        user_agent=_BROWSER_UA,
                        app_display_name=app,
                        technique_ids=[tid],
                        **extra,
                    ),
                ],
                Stage(
                    label="malicious",
                    expected_call="true_positive",
                    tactic=tactic,
                    technique_ids=[tid],
                    title=title,
                    why=why,
                ),
            )
        )
    return victim


def _malware_spread(rng: random.Random, b: _Build) -> str | None:
    web, app_host = rng.choice(("web-01", "web-02")), rng.choice(("app-02", "app-03"))
    web_user, app_user = f"{web}\\system", f"{app_host}\\system"
    exploit_src = b.ip_in(rng, _TEST_NET_1)
    c2 = b.ip_in(rng, _TEST_NET_2)
    web_ip = b.ip_in(rng, _INTERNAL)
    shell, payload = _hash(rng), _hash(rng)
    shell_path = (
        f"/var/www/html/uploads/{rng.choice(('thumb', 'cache', 'img'))}{rng.randint(10, 99)}.php"
    )
    payload_path = f"/tmp/.{rng.choice(('kworkerd', 'syslogd', 'dbus-daemon'))}"
    clean, convicted = (0, 70), (rng.randint(38, 55), 70)

    def file_ev(
        user: str,
        when: datetime,
        path: str,
        sha: str,
        verdict: tuple[int, int],
        kind: str = "file",
        action: str | None = "added",
        **extra: object,
    ) -> SignInMetadata:
        return _event(
            user,
            "",
            when,
            kind,
            file=FileArtifact(
                path=path,
                sha256=sha,
                fim_action=action,
                vt_positives=verdict[0],
                vt_total=verdict[1],
            ),
            **extra,
        )

    t1 = b.base
    t2, t3, t4 = t1 + timedelta(minutes=20), t1 + timedelta(minutes=45), t1 + timedelta(minutes=62)
    b.add(
        _Alert(
            web_user,
            "wazuh",
            [
                _event(
                    web_user,
                    exploit_src,
                    t1,
                    "network",
                    app_display_name="Apache httpd",
                    technique_ids=["T1190"],
                ),
                file_ev(web_user, t1 + timedelta(seconds=40), shell_path, shell, clean),
            ],
            Stage(
                label="malicious",
                expected_call="true_positive",
                tactic="Initial Access",
                technique_ids=["T1190"],
                title=f"Web shell written on {web}",
                why=(
                    f"A request from {exploit_src} is followed by a new PHP file in an "
                    "uploads folder. VirusTotal has no detections yet: a fresh drop, "
                    "not a clean file."
                ),
            ),
        )
    )
    b.add(
        _Alert(
            web_user,
            "wazuh",
            [
                file_ev(
                    web_user,
                    t2,
                    shell_path,
                    shell,
                    clean,
                    kind="process",
                    action=None,
                    technique_ids=["T1059.004"],
                ),
                file_ev(web_user, t2 + timedelta(seconds=15), payload_path, payload, convicted),
            ],
            Stage(
                label="malicious",
                expected_call="true_positive",
                tactic="Execution",
                technique_ids=["T1059.004"],
                title=f"Web shell runs a payload on {web}",
                why=(
                    "The web shell spawns a shell that writes a hidden binary under "
                    "/tmp, which VirusTotal convicts."
                ),
            ),
        )
    )
    b.add(
        _Alert(
            app_user,
            "wazuh",
            [
                _event(
                    app_user,
                    web_ip,
                    t3,
                    auth_status="success",
                    app_display_name="sshd",
                    technique_ids=["T1021.004"],
                ),
                file_ev(app_user, t3 + timedelta(minutes=1), payload_path, payload, convicted),
            ],
            Stage(
                label="malicious",
                expected_call="true_positive",
                tactic="Lateral Movement",
                technique_ids=["T1021.004"],
                title=f"SSH from {web} drops the payload on {app_host}",
                why=(
                    f"{web} ({web_ip}) logs in to {app_host} over SSH and the same "
                    "SHA-256 appears there a minute later: the infection spread."
                ),
            ),
        )
    )
    b.add(
        _Alert(
            app_user,
            "wazuh",
            [
                file_ev(
                    app_user, t4, payload_path, payload, convicted, kind="process", action=None
                ),
                _event(
                    app_user,
                    c2,
                    t4 + timedelta(seconds=5),
                    "network",
                    app_display_name="outbound connection",
                    technique_ids=["T1071"],
                ),
            ],
            Stage(
                label="malicious",
                expected_call="true_positive",
                tactic="Command and Control",
                technique_ids=["T1071"],
                title=f"Payload on {app_host} beacons out",
                why=f"The payload calls {c2}, an address on a C2 reputation feed.",
            ),
        )
    )
    return None


_SCENARIO_BUILDERS: dict[str, Callable[[random.Random, _Build], str | None]] = {
    "password-spray": _password_spray,
    "identity-exfil": _identity_exfil,
    "malware-spread": _malware_spread,
}


# ---------------------------------------------------------------------------
# Benign noise templates
# ---------------------------------------------------------------------------


def _office_time(rng: random.Random, b: _Build) -> datetime:
    """A time between 08:00 and 17:59 UTC on the drill day."""
    day = b.base.replace(hour=0, minute=0, second=0, microsecond=0)
    return day + timedelta(minutes=rng.randint(8 * 60, 18 * 60 - 1), seconds=rng.randint(0, 59))


def _benign(title: str, why: str, call: str = "benign_positive") -> Stage:
    return Stage(label="benign", expected_call=call, title=title, why=why)


def _noise_new_ip(rng: random.Random, b: _Build, upn: str) -> _Alert:
    home, device = _home(upn)
    return _Alert(
        upn,
        "azure_ad",
        [
            _event(
                upn,
                b.noise_ip(rng),
                _office_time(rng, b),
                auth_status="success",
                location=home,
                device_id=device,
                user_agent=_BROWSER_UA,
                app_display_name=rng.choice(_SAFE_APPS),
            ),
        ],
        _benign(
            "Sign-in from a new home IP",
            "Known laptop, home city, office hours. The only novelty is a new ISP address.",
        ),
    )


def _noise_trip(rng: random.Random, b: _Build, upn: str) -> _Alert:
    home, device = _home(upn)
    start = _office_time(rng, b).replace(hour=8)
    city = rng.choice(_TRIP_CITIES)
    return _Alert(
        upn,
        "azure_ad",
        [
            _event(
                upn,
                b.noise_ip(rng),
                start,
                auth_status="success",
                location=home,
                device_id=device,
                user_agent=_BROWSER_UA,
                app_display_name="Outlook Web",
            ),
            _event(
                upn,
                b.noise_ip(rng),
                start + timedelta(hours=4),
                auth_status="success",
                location=city,
                device_id=device,
                user_agent=_BROWSER_UA,
                app_display_name="Microsoft Teams",
            ),
        ],
        _benign(
            f"Sign-ins from home and {city.city}",
            "Two cities four hours apart at a plausible travel speed, on the user's own "
            "laptop: a business trip.",
        ),
    )


def _noise_vpn_hop(rng: random.Random, b: _Build, upn: str) -> _Alert:
    home, device = _home(upn)
    start = _office_time(rng, b)
    return _Alert(
        upn,
        "azure_ad",
        [
            _event(
                upn,
                b.noise_ip(rng),
                start,
                auth_status="success",
                location=home,
                device_id=device,
                user_agent=_BROWSER_UA,
                app_display_name="Outlook Web",
            ),
            _event(
                upn,
                b.noise_ip(rng),
                start + timedelta(minutes=15),
                auth_status="success",
                location=_VPN_EGRESS,
                device_id=device,
                user_agent=_BROWSER_UA,
                app_display_name="VPN Gateway",
            ),
        ],
        _benign(
            "Impossible travel via the corporate VPN",
            "The second sign-in is the VPN Gateway's Singapore egress on the same known "
            "laptop. Impossible travel fires whenever a VPN egress moves; it is the same "
            "person, so this is a benign positive.",
        ),
    )


def _noise_mfa_typo(rng: random.Random, b: _Build, upn: str) -> _Alert:
    home, device = _home(upn)
    ip, start = b.noise_ip(rng), _office_time(rng, b)
    app = rng.choice(_SAFE_APPS)
    return _Alert(
        upn,
        "azure_ad",
        [
            _event(
                upn,
                ip,
                start + timedelta(seconds=s),
                auth_status=status,
                location=home,
                device_id=device,
                user_agent=_BROWSER_UA,
                app_display_name=app,
            )
            for s, status in ((0, "failure"), (50, "failure"), (95, "success"))
        ],
        _benign(
            "Two failed MFA prompts, then success",
            "Two denials and an approval inside two minutes on the user's own device: a "
            "fumbled prompt, below the three-denial fatigue threshold.",
        ),
    )


def _noise_new_laptop(rng: random.Random, b: _Build, upn: str) -> _Alert:
    home, _ = _home(upn)
    device = f"LT-NEW-{rng.getrandbits(16):04X}"
    return _Alert(
        upn,
        "azure_ad",
        [
            _event(
                upn,
                b.noise_ip(rng),
                _office_time(rng, b),
                auth_status="success",
                location=home,
                device_id=device,
                device_name=device,
                user_agent=_BROWSER_UA,
                app_display_name=rng.choice(_SAFE_APPS),
            ),
        ],
        _benign(
            "Sign-in from an unrecognised laptop",
            "A new device at the user's home location in office hours, consistent with a "
            "hardware refresh. Confirm against IT asset records rather than escalating.",
        ),
    )


def _noise_after_hours(rng: random.Random, b: _Build, upn: str) -> _Alert:
    home, device = _home(upn)
    day = b.base.replace(hour=0, minute=0, second=0, microsecond=0)
    when = day + timedelta(minutes=rng.randint(21 * 60, 22 * 60 + 30))
    return _Alert(
        upn,
        "azure_ad",
        [
            _event(
                upn,
                b.noise_ip(rng),
                when,
                auth_status="success",
                location=home,
                device_id=device,
                user_agent=_BROWSER_UA,
                app_display_name="Slack",
            ),
        ],
        _benign(
            "Late-evening sign-in",
            "Known device and location, outside usual hours: an on-call or deadline login.",
        ),
    )


def _noise_null_island(rng: random.Random, b: _Build, upn: str) -> _Alert:
    home, device = _home(upn)
    start = _office_time(rng, b)
    return _Alert(
        upn,
        "azure_ad",
        [
            _event(
                upn,
                b.noise_ip(rng),
                start,
                auth_status="success",
                location=home,
                device_id=device,
                user_agent=_BROWSER_UA,
                app_display_name="Outlook Web",
            ),
            _event(
                upn,
                b.noise_ip(rng),
                start + timedelta(minutes=5),
                auth_status="success",
                location=_NULL_ISLAND,
                device_id=device,
                user_agent=_BROWSER_UA,
                app_display_name="Outlook Web",
            ),
        ],
        _benign(
            "Impossible travel to 0,0",
            "The second event geolocated to latitude 0, longitude 0 ('Null Island'), which "
            "is a failed GeoIP lookup, not a place. The detection fired on bad enrichment "
            "data: a false positive, and a data-quality ticket.",
            call="false_positive",
        ),
    )


def _noise_package_update(rng: random.Random, b: _Build, _upn: str) -> _Alert:
    host = rng.choice(("db-03", "ci-04", "mon-05"))
    user = f"{host}\\system"
    tool = rng.choice(("openssl", "curl", "rsync"))
    return _Alert(
        user,
        "wazuh",
        [
            _event(
                user,
                "",
                _office_time(rng, b),
                "file",
                technique_ids=["T1565.001"],
                file=FileArtifact(
                    path=f"/usr/bin/{tool}",
                    sha256=_hash(rng),
                    fim_action="modified",
                    vt_positives=0,
                    vt_total=70,
                ),
            ),
        ],
        _benign(
            f"System binary changed on {host}",
            f"File integrity monitoring saw /usr/bin/{tool} change. The ruleset tags any "
            "binary change as data manipulation, but this is a package update: one "
            "file, no execution, no network activity, no VirusTotal detections.",
        ),
    )


_IDENTITY_NOISE: tuple[Callable[[random.Random, _Build, str], _Alert], ...] = (
    _noise_new_ip,
    _noise_trip,
    _noise_vpn_hop,
    _noise_mfa_typo,
    _noise_new_laptop,
    _noise_after_hours,
    _noise_null_island,
)


def _add_noise(rng: random.Random, b: _Build, count: int, people: list[str], hosts: bool) -> None:
    """Append *count* benign alerts, cycling through shuffled templates."""
    templates = list(_IDENTITY_NOISE)
    rng.shuffle(templates)
    if hosts:
        templates.insert(0, _noise_package_update)
    for i in range(count):
        b.add(templates[i % len(templates)](rng, b, rng.choice(people)))


def generate(scenario_id: str, seed: int, noise: NoiseLevel = "medium") -> DrillRun:
    """Generate one drill run.

    Args:
        scenario_id: A key of ``SCENARIOS``.
        seed: Non-negative integer; the same seed always gives the same run.
        noise: Benign alert volume (``low``/``medium``/``high``).

    Returns:
        The run: incidents in queue order (first event time, then generation
        order) and their index-aligned ground truth.

    Raises:
        KeyError: Unknown scenario ID.
        ValueError: Unknown noise level, or a negative seed.
    """
    if scenario_id not in SCENARIOS:
        raise KeyError(scenario_id)
    if noise not in NOISE_COUNTS:
        raise ValueError(f"unknown noise level {noise!r}")
    if seed < 0:
        raise ValueError("seed must be non-negative")

    attack_rng = random.Random(f"adte-drill:{scenario_id}:{seed}:attack")
    noise_rng = random.Random(f"adte-drill:{scenario_id}:{seed}:noise:{noise}")
    base = _ANCHOR + timedelta(
        days=attack_rng.randrange(_ANCHOR_SPAN_DAYS),
        hours=attack_rng.randint(9, 12),
        minutes=attack_rng.randrange(60),
    )
    build = _Build(seed=seed, base=base)
    victim = _SCENARIO_BUILDERS[scenario_id](attack_rng, build)
    people = [p for p in DRILL_PERSONA_UPNS if p != victim]
    _add_noise(noise_rng, build, NOISE_COUNTS[noise], people, hosts=scenario_id == "malware-spread")

    alerts = sorted(build.alerts, key=lambda a: (a.events[0].timestamp, a.seq))
    if len(alerts) > MAX_DRILL_ALERTS:  # guarded by tests; never true for shipped scenarios
        raise ValueError("drill exceeds the alert cap")
    code = _ID_CODES[scenario_id]
    incidents = [
        NormalizedIncident(
            incident_id=f"{DRILL_ID_PREFIX}{code}-{seed}-{n:02d}",
            user=a.user,
            source=a.source,
            events=a.events,
            created_time=a.events[0].timestamp,
        )
        for n, a in enumerate(alerts, start=1)
    ]
    return DrillRun(
        scenario=scenario_id,
        seed=seed,
        noise=noise,
        incidents=incidents,
        truth=[a.stage for a in alerts],
    )
