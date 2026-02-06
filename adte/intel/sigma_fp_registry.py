"""Sigma-aligned false-positive registry.

Loads a YAML file of known-benign IP ranges and pattern types so the
triage engine can suppress or down-weight alerts that match well-understood
benign activity (corporate VPNs, SSO quirks, travel providers, etc.).

NIST 800-61 Phase: Detection & Analysis — reduces false-positive volume
to keep analyst attention on genuine incidents.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

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
                continue
            entries[ptype] = [ipaddress.IPv4Network(c, strict=False) for c in cidrs]

        return cls(entries)

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
