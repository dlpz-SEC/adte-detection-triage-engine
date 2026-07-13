"""Threat intelligence lookups for IP reputation and file-hash reputation.

Public entry point for IP and file-hash reputation checks.  Delegates to
``ThreatIntelAggregator``, which queries live threat intel APIs when keys
are configured (``ADTE_ABUSEIPDB_KEY``, ``ADTE_VT_API_KEY``,
``ADTE_OTX_KEY``) and falls back to a deterministic mock when no keys are
set — suitable for development, testing, and dry-run triage without
requiring external API access.  File-hash reputation is VirusTotal-only
(``ADTE_VT_API_KEY``); AbuseIPDB and OTX are IP-only feeds.

NIST 800-61 Phase: Detection & Analysis — enriches observables with
threat context to support triage decisions.
"""

from __future__ import annotations

import ipaddress
import re
import threading
from typing import Literal

from adte.intel.aggregator import ThreatIntelAggregator
from adte.models import FileReputationResult, ThreatIntelResult

# Module-level singleton — reused across requests so the per-IP result cache
# persists and clients are not re-instantiated on every triage call.
_aggregator: ThreatIntelAggregator | None = None
_aggregator_lock = threading.Lock()

# Hex-digest length -> digest algorithm name.
_HASH_TYPE_BY_LENGTH: dict[int, Literal["md5", "sha1", "sha256"]] = {
    32: "md5",
    40: "sha1",
    64: "sha256",
}


def _get_aggregator() -> ThreatIntelAggregator:
    """Return the module-level aggregator, creating it on first call.

    Thread-safe: the lock ensures only one instance is created even under
    concurrent Flask requests.

    Returns:
        The shared ``ThreatIntelAggregator`` instance.
    """
    global _aggregator
    if _aggregator is None:
        with _aggregator_lock:
            if _aggregator is None:
                _aggregator = ThreatIntelAggregator.from_env()
    return _aggregator


def check_threat_intel(ip: str) -> ThreatIntelResult:
    """Look up an IP address against threat intelligence feeds.

    Validates the IP, then delegates to the module-level
    ``ThreatIntelAggregator`` singleton which selects live API sources based
    on configured environment variables or falls back to a deterministic mock
    when none are set.  Results are cached per IP for the lifetime of the
    server process.

    Args:
        ip: IPv4 address string to check (e.g. ``"198.51.100.14"``).

    Returns:
        A ``ThreatIntelResult`` with reputation data.

    Raises:
        ValueError: If *ip* is not a valid IPv4 address.
    """
    try:
        ipaddress.IPv4Address(ip)
    except ipaddress.AddressValueError as exc:
        raise ValueError(f"Invalid IPv4 address: {ip!r}") from exc

    return _get_aggregator().check(ip)


def check_file_hash(file_hash: str) -> FileReputationResult:
    """Look up a file hash against threat intelligence feeds.

    Validates the hash as a hex-encoded MD5, SHA-1, or SHA-256 digest,
    determines the digest algorithm from its length, then delegates to the
    module-level ``ThreatIntelAggregator`` singleton which queries
    VirusTotal (the only hash-capable configured source) or falls back to a
    deterministic mock when no VirusTotal key is set.  Results are cached
    per hash for the lifetime of the server process.

    Args:
        file_hash: Hex-encoded MD5 (32 chars), SHA-1 (40 chars), or SHA-256
            (64 chars) digest string.  Case-insensitive; normalised to
            lowercase before lookup.

    Returns:
        A ``FileReputationResult`` with reputation data.

    Raises:
        ValueError: If *file_hash* is not a valid MD5/SHA-1/SHA-256 hex
            digest.
    """
    if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", file_hash) is None:
        raise ValueError(f"Invalid file hash: {file_hash!r}")

    normalized = file_hash.lower()
    hash_type = _HASH_TYPE_BY_LENGTH[len(normalized)]

    return _get_aggregator().check_hash(normalized, hash_type)
