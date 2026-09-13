"""Optional port scoping: keep the scan on the target's port instead of scanning top-100."""

from __future__ import annotations

import sys
from pathlib import Path

_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))

from scanner.config import ScanConfig


def test_config_ports_defaults_none_and_is_settable():
    assert ScanConfig("https://example.test").ports is None
    assert ScanConfig("https://example.test", ports="3007").ports == "3007"


def test_network_scanner_uses_scoped_ports_from_url_info(monkeypatch):
    import plugins.network_scanner as ns

    captured = {}

    class FakeScanner:
        engine = "fake"

        def __init__(self, ports="top100", **kw):
            captured["ports"] = ports

        def scan(self, host):
            return []

    monkeypatch.setattr(ns, "NetworkScanner", FakeScanner)

    class _Handler:
        def get(self, url, **kw):
            return None

    # With a scoped port list, the scanner is restricted to it.
    ns.NetworkScannerPlugin().scan(
        {"url": "http://localhost:3007/", "depth": 0, "scan_ports": "3007"}, _Handler())
    assert captured["ports"] == "3007"


def test_network_scanner_defaults_to_top100_without_scope(monkeypatch):
    import plugins.network_scanner as ns

    captured = {}

    class FakeScanner:
        engine = "fake"

        def __init__(self, ports="top100", **kw):
            captured["ports"] = ports

        def scan(self, host):
            return []

    monkeypatch.setattr(ns, "NetworkScanner", FakeScanner)

    class _Handler:
        def get(self, url, **kw):
            return None

    ns.NetworkScannerPlugin().scan({"url": "http://localhost:3007/", "depth": 0}, _Handler())
    assert captured["ports"] == "top100"
