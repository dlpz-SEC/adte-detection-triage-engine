"""Sigma-aligned false-positive registry.

Loads a YAML file of known-benign IP ranges and pattern types so the
triage engine can suppress or down-weight alerts that match well-understood
benign activity (corporate VPNs, SSO quirks, travel providers, etc.).

NIST 800-61 Phase: Detection & Analysis — reduces false-positive volume
to keep analyst attention on genuine incidents.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default registry path (relative to repo root)
# ---------------------------------------------------------------------------
_DEFAULT_REGISTRY_PATH = Path(__file__).resolve().parents[2] / "examples" / "fp_registry.yaml"


class FPRegistry:
    """In-memory index of known-benign CIDR ranges keyed by pattern type.

    Typical usage::

        registry = FPRegistry.load()
        if registry.is_known_benign("10.1.2.3", "corporate_vpn"):
            ...  # suppress alert
    """

    def __init__(self, entries: dict[str, list[ipaddress.IPv4Network]]) -> None:
        """Initialise the registry from pre-parsed entries.

        Args:
            entries: Mapping of ``pattern_type`` to a list of CIDR networks.
        """
        self._entries = entries

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def load(cls, path: Path | str | None = None) -> "FPRegistry":
        """Load the false-positive registry from a YAML file.

        Args:
            path: Path to the YAML registry file.  Falls back to
                ``examples/fp_registry.yaml`` in the repository root.

        Returns:
            A populated ``FPRegistry`` instance.

        Raises:
            FileNotFoundError: If the YAML file does not exist.
            ValueError: If the YAML structure is invalid.
        """
        resolved = Path(path) if path else _DEFAULT_REGISTRY_PATH
        cache_key = str(resolved)

        with _registry_cache_lock:
            if cache_key in _registry_cache:
                return _registry_cache[cache_key]

        if not resolved.exists():
            raise FileNotFoundError(f"FP registry file not found: {resolved}")

        raw: list[dict[str, Any]] = yaml.safe_load(resolved.read_text(encoding="utf-8"))

        if not isinstance(raw, list):
            raise ValueError(f"Expected a YAML list at top level, got {type(raw).__name__}")

        entries: dict[str, list[ipaddress.IPv4Network]] = {}
        for item in raw:
            ptype = item.get("pattern_type")
            cidrs = item.get("cidrs", [])
            if not ptype:
                _log.warning("FP registry entry missing 'pattern_type' — skipping: %r", item)
                continue
            networks: list[ipaddress.IPv4Network] = []
            for cidr in cidrs:
                try:
                    networks.append(ipaddress.IPv4Network(cidr, strict=True))
                except ValueError:
                    # strict=True rejects host bits set (e.g. 10.0.0.1/24).
                    # Warn and normalise rather than silently accepting ambiguous notation.
                    normalised = ipaddress.IPv4Network(cidr, strict=False)
                    _log.warning(
                        "FP registry CIDR %r in '%s' has host bits set — "
                        "normalised to %s",
                        cidr, ptype, normalised,
                    )
                    networks.append(normalised)
            entries[ptype] = networks

        instance = cls(entries)
        with _registry_cache_lock:
            _registry_cache[cache_key] = instance
        return instance

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def is_known_benign(self, ip: str, pattern_type: str) -> bool:
        """Check whether *ip* falls within a known-benign range for *pattern_type*.

        Args:
            ip: IPv4 address string to test.
            pattern_type: Registry category to match against (e.g.
                ``"corporate_vpn"``, ``"sso_quirk"``).

        Returns:
            ``True`` if the IP matches at least one CIDR in the given
            pattern type; ``False`` otherwise (including when the
            pattern type is not present in the registry).

        Raises:
            ValueError: If *ip* is not a valid IPv4 address.
        """
        try:
            addr = ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError as exc:
            raise ValueError(f"Invalid IPv4 address: {ip!r}") from exc

        networks = self._entries.get(pattern_type, [])
        return any(addr in net for net in networks)

    def pattern_types(self) -> list[str]:
        """Return all registered pattern type keys.

        Returns:
            Sorted list of pattern type strings in the registry.
        """
        return sorted(self._entries.keys())

    def is_known_benign_any(self, ip: str) -> tuple[bool, str | None]:
        """Check whether *ip* matches any pattern type in the registry.

        Args:
            ip: IPv4 address string to test.

        Returns:
            A tuple of ``(matched, pattern_type)``.  If the IP matches,
            ``matched`` is ``True`` and ``pattern_type`` is the first
            matching category.  Otherwise ``(False, None)``.

        Raises:
            ValueError: If *ip* is not a valid IPv4 address.
        """
        for ptype in self._entries:
            if self.is_known_benign(ip, ptype):
                return True, ptype
        return False, None


# ---------------------------------------------------------------------------
# Module-level singleton cache + write helper
# ---------------------------------------------------------------------------

# Keyed by resolved path string. Populated lazily on first FPRegistry.load()
# call for a given path; invalidated by add_fp_entry() before it rewrites the
# file so the next load() picks up the fresh content.
_registry_cache: dict[str, "FPRegistry"] = {}
_registry_cache_lock: threading.Lock = threading.Lock()

# Serialises concurrent writes — callers queue rather than race (not last-write-wins).
_fp_write_lock: threading.Lock = threading.Lock()


def add_fp_entry(ip: str, comment: str, registry_path: str | Path) -> bool:
    """Append a new analyst-feedback FP entry to the YAML registry file.

    Creates a new top-level list entry with ``pattern_type: analyst_feedback``.
    Host addresses (no ``/`` in the string) are normalised to ``/32``.

    Thread safety: a module-level ``threading.Lock`` serialises all writes so
    concurrent callers queue rather than race (no lost updates).

    After a successful write the registry is reloaded via ``FPRegistry.load()``
    to verify the YAML remains parseable.

    Args:
        ip: IPv4 address or CIDR to register as benign.
        comment: Short description stored in the entry's ``description`` field.
        registry_path: Path to the YAML registry file to update.

    Returns:
        ``True`` on success, ``False`` on any failure (missing file, parse
        error, write error).  Never raises.
    """
    try:
        path = Path(registry_path)
        if not path.exists():
            _log.warning("add_fp_entry: registry path does not exist: %s", path)
            return False

        # Strict IP/CIDR validation before any filesystem write.
        try:
            if "/" in ip:
                ipaddress.IPv4Network(ip, strict=False)
            else:
                ipaddress.IPv4Address(ip)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as exc:
            _log.warning("add_fp_entry: invalid IP/CIDR %r: %s", ip, exc)
            return False

        cidr: str = ip if "/" in ip else f"{ip}/32"
        # pattern_type is always "analyst_feedback" for API-driven entries.
        # Entries added via the YAML file directly are not validated here —
        # arbitrary pattern_type strings accumulate silently in the registry.
        new_entry: dict[str, Any] = {
            "pattern_type": "analyst_feedback",
            "description": comment,
            "cidrs": [cidr],
        }

        with _fp_write_lock:
            raw: list[dict[str, Any]] = yaml.safe_load(path.read_text(encoding="utf-8")) or []
            raw.append(new_entry)
            path.write_text(
                yaml.dump(raw, default_flow_style=False, allow_unicode=True),
                encoding="utf-8",
            )
            # Invalidate cache while still holding _fp_write_lock to prevent a
            # concurrent load() from caching the pre-write content.
            # Always acquire in this order (_fp_write_lock → _registry_cache_lock)
            # to avoid deadlock with FPRegistry.load().
            with _registry_cache_lock:
                _registry_cache.pop(str(path), None)

        FPRegistry.load(path)
        return True
    except Exception as exc:
        _log.warning("add_fp_entry failed: %s", exc)
        return False
