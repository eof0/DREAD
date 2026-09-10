"""Detect the system package manager and resolve install guidance for missing tools.

Cannon never runs a privileged install itself. It detects the manager, checks whether
the tool's package is available there, and hands back the exact command for the operator to
run. If no manager has it, the operator installs it manually and re-checks.
"""

from __future__ import annotations

import shutil
import subprocess

# name -> (install prefix, availability query)
_MANAGERS = (
    ("pacman", ("sudo", "pacman", "-S", "--needed"), ("pacman", "-Si")),
    ("apt", ("sudo", "apt", "install", "-y"), ("apt-cache", "show")),
    ("dnf", ("sudo", "dnf", "install", "-y"), ("dnf", "-q", "info")),
    ("zypper", ("sudo", "zypper", "install", "-y"), ("zypper", "info")),
    ("brew", ("brew", "install"), ("brew", "info")),
)


def detect_manager() -> tuple[str, tuple[str, ...], tuple[str, ...]] | None:
    """Return (name, install_prefix, query) for the first package manager found on PATH."""
    for name, install, query in _MANAGERS:
        if shutil.which(name):
            return name, install, query
    return None


def _available(query: tuple[str, ...], package: str) -> bool:
    try:
        result = subprocess.run([*query, package], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def install_guidance(binary: str, packages: dict[str, str] | None = None) -> dict:
    """Describe how to install a missing binary: manager, package, availability, and command."""
    manager = detect_manager()
    if manager is None:
        return {"manager": None, "package": binary, "available": False, "command": None}
    name, install, query = manager
    package = (packages or {}).get(name, binary)
    if _available(query, package):
        return {"manager": name, "package": package, "available": True, "command": " ".join([*install, package])}
    return {"manager": name, "package": package, "available": False, "command": None}
