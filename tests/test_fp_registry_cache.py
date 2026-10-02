"""Tests for FP registry cache coherence across processes.

``FPRegistry.load()`` caches the parsed registry.  The cache used to be
invalidated only by ``add_fp_entry()`` in the SAME process, so with
``gunicorn --workers 2`` an IP promoted through one worker never reached the
other until it restarted, and the same incident scored differently depending
on which worker answered.  The cache is now keyed on the file's on-disk
signature, and writes go through an atomic replace.

Covers:
  - adte.intel.sigma_fp_registry: FPRegistry.load, add_fp_entry,
    _file_signature, _atomic_write_text

Filesystem tests use pytest's tmp_path.  The cross-process test runs a real
second interpreter, per LESSONS.md 2026-07-10: locks and in-process
invalidation prove nothing about another process.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from adte.intel import sigma_fp_registry
from adte.intel.sigma_fp_registry import (
    FPRegistry,
    _atomic_write_text,
    _file_signature,
    add_fp_entry,
)

_REPO_ROOT = Path(__file__).resolve().parents[1]

_BASE_REGISTRY = [
    {
        "pattern_type": "corporate_vpn",
        "description": "Test VPN ranges",
        "cidrs": ["10.0.0.0/8"],
    }
]

_PROMOTED_IP = "198.51.100.7"


def _make_registry(tmp_path: Path) -> Path:
    """Write a one-entry registry into *tmp_path* and return its path."""
    path = tmp_path / "fp_registry.yaml"
    path.write_text(yaml.dump(_BASE_REGISTRY, default_flow_style=False), encoding="utf-8")
    return path


def _append_entry_directly(path: Path, cidr: str) -> None:
    """Append an entry WITHOUT touching this process's cache.

    Stands in for a write made by another process: a second worker, the CLI,
    or a hand edit.
    """
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw.append({"pattern_type": "analyst_feedback", "description": "external", "cidrs": [cidr]})
    path.write_text(yaml.dump(raw, default_flow_style=False), encoding="utf-8")


# ---------------------------------------------------------------------------
# Cache reuse and invalidation
# ---------------------------------------------------------------------------


def test_load_reuses_cached_instance_while_file_unchanged(tmp_path: Path) -> None:
    """An unchanged file is parsed once; later loads return the same object."""
    path = _make_registry(tmp_path)

    first = FPRegistry.load(path)
    second = FPRegistry.load(path)

    assert first is second


def test_load_sees_write_that_bypassed_this_process_cache(tmp_path: Path) -> None:
    """A write this process's cache never heard about is still picked up."""
    path = _make_registry(tmp_path)
    assert FPRegistry.load(path).is_known_benign_any(_PROMOTED_IP) == (False, None)

    _append_entry_directly(path, f"{_PROMOTED_IP}/32")

    assert FPRegistry.load(path).is_known_benign_any(_PROMOTED_IP) == (
        True,
        "analyst_feedback",
    )


def test_promotion_in_another_process_reaches_this_process(tmp_path: Path) -> None:
    """The production failure: worker B must see worker A's FP promotion.

    This process loads (and caches) the registry, a separate interpreter
    promotes an IP through the real ``add_fp_entry``, and this process's next
    load must include it.  Before the fix it returned the cached instance.
    """
    path = _make_registry(tmp_path)
    assert FPRegistry.load(path).is_known_benign_any(_PROMOTED_IP) == (False, None)

    script = (
        "import sys\n"
        "from adte.intel.sigma_fp_registry import add_fp_entry\n"
        "ok = add_fp_entry(sys.argv[1], 'other worker', sys.argv[2])\n"
        "sys.exit(0 if ok else 1)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script, _PROMOTED_IP, str(path)],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr

    assert FPRegistry.load(path).is_known_benign_any(_PROMOTED_IP) == (
        True,
        "analyst_feedback",
    )


def test_missing_file_still_raises_file_not_found(tmp_path: Path) -> None:
    """The stat-first path keeps the original error contract."""
    with pytest.raises(FileNotFoundError, match="FP registry file not found"):
        FPRegistry.load(tmp_path / "absent.yaml")


# ---------------------------------------------------------------------------
# Atomic write
# ---------------------------------------------------------------------------


def test_atomic_rewrite_changes_signature_even_with_identical_content(tmp_path: Path) -> None:
    """Same bytes, same size: the replace still yields a new signature.

    Guards against a coarse filesystem timestamp hiding a write: the replace
    lands on a new file, so the signature changes regardless.
    """
    path = _make_registry(tmp_path)
    content = path.read_text(encoding="utf-8")
    before = _file_signature(path)

    _atomic_write_text(path, content)

    assert path.read_text(encoding="utf-8") == content
    assert _file_signature(path) != before


def test_add_fp_entry_leaves_no_temp_files(tmp_path: Path) -> None:
    """A successful promotion leaves only the registry in its directory."""
    path = _make_registry(tmp_path)

    assert add_fp_entry(_PROMOTED_IP, "test", path) is True

    assert sorted(p.name for p in tmp_path.iterdir()) == ["fp_registry.yaml"]


def test_failed_replace_keeps_original_and_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the swap fails, the registry is untouched and no temp file lingers."""
    path = _make_registry(tmp_path)
    original = path.read_text(encoding="utf-8")

    def _boom(src: str, dst: str) -> None:
        raise OSError("simulated replace failure")

    monkeypatch.setattr(sigma_fp_registry.os, "replace", _boom)

    assert add_fp_entry(_PROMOTED_IP, "test", path) is False
    assert path.read_text(encoding="utf-8") == original
    assert sorted(p.name for p in tmp_path.iterdir()) == ["fp_registry.yaml"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_atomic_write_preserves_file_mode(tmp_path: Path) -> None:
    """The replacement keeps the original permission bits, not mkstemp's 0600."""
    path = _make_registry(tmp_path)
    os.chmod(path, 0o644)

    _atomic_write_text(path, path.read_text(encoding="utf-8"))

    assert path.stat().st_mode & 0o777 == 0o644
