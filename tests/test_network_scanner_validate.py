"""NetworkScannerPlugin._validate_service must not leak an UnboundLocalError."""

from __future__ import annotations

import socket
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_PROBE = _REPO / "probe"
for p in (str(_REPO), str(_PROBE)):
    if p not in sys.path:
        sys.path.insert(0, p)

from plugins.network_scanner import NetworkScannerPlugin


def test_validate_service_returns_false_when_socket_creation_fails(monkeypatch):
    def boom(*args, **kwargs):
        raise OSError("Too many open files")

    monkeypatch.setattr(socket, "socket", boom)

    plugin = NetworkScannerPlugin()

    assert plugin._validate_service("10.0.0.5", 22, "SSH") is False
