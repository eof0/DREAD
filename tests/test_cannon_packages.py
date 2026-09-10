from __future__ import annotations

import sys
import types
from pathlib import Path

_CANNON = Path(__file__).resolve().parents[1] / "cannon"
if str(_CANNON) not in sys.path:
    sys.path.insert(0, str(_CANNON))

import packages


def _which(present):
    return lambda name: f"/usr/bin/{name}" if name in present else None


def test_detect_manager_prefers_first_on_path(monkeypatch):
    monkeypatch.setattr(packages.shutil, "which", _which({"pacman", "apt"}))
    manager = packages.detect_manager()
    assert manager is not None and manager[0] == "pacman"


def test_detect_manager_none_when_absent(monkeypatch):
    monkeypatch.setattr(packages.shutil, "which", _which(set()))
    assert packages.detect_manager() is None


def test_install_guidance_available(monkeypatch):
    monkeypatch.setattr(packages.shutil, "which", _which({"pacman"}))
    monkeypatch.setattr(packages.subprocess, "run", lambda *a, **k: types.SimpleNamespace(returncode=0))
    guidance = packages.install_guidance("nmap")
    assert guidance["available"] is True
    assert guidance["command"] == "sudo pacman -S --needed nmap"


def test_install_guidance_uses_package_map(monkeypatch):
    monkeypatch.setattr(packages.shutil, "which", _which({"pacman"}))
    monkeypatch.setattr(packages.subprocess, "run", lambda *a, **k: types.SimpleNamespace(returncode=0))
    guidance = packages.install_guidance("ab", {"pacman": "apache"})
    assert guidance["package"] == "apache"
    assert guidance["command"] == "sudo pacman -S --needed apache"


def test_install_guidance_not_in_manager(monkeypatch):
    monkeypatch.setattr(packages.shutil, "which", _which({"pacman"}))
    monkeypatch.setattr(packages.subprocess, "run", lambda *a, **k: types.SimpleNamespace(returncode=1))
    guidance = packages.install_guidance("hey")
    assert guidance["manager"] == "pacman"
    assert guidance["available"] is False
    assert guidance["command"] is None


def test_install_guidance_no_manager(monkeypatch):
    monkeypatch.setattr(packages.shutil, "which", _which(set()))
    guidance = packages.install_guidance("nmap")
    assert guidance["manager"] is None
    assert guidance["available"] is False
