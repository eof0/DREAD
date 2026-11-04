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


def test_header_only_cdn_still_reports_exposed_services(monkeypatch):
    import plugins.network_scanner as ns

    class FakeScanner:
        engine = "fake"

        def __init__(self, ports="top100", **kw):
            pass

        def scan(self, host):
            return [{"port": 22, "response_time_ms": 1}, {"port": 443, "response_time_ms": 1}]

    class _Resp:
        headers = {"cf-ray": "abc", "server": "cloudflare"}

    class _Handler:
        def get(self, url, **kw):
            return _Resp()

    monkeypatch.setattr(ns, "NetworkScanner", FakeScanner)
    plugin = ns.NetworkScannerPlugin()
    monkeypatch.setattr(plugin, "_is_cloudflare_ip", lambda ip: False)
    monkeypatch.setattr(plugin, "_validate_service", lambda host, port, service: True)
    monkeypatch.setattr(ns.socket, "gethostbyname", lambda host: "203.0.113.10")

    findings = plugin.scan({"url": "https://example.test/", "depth": 0}, _Handler())
    titles = [f.title for f in findings]
    assert any(t.startswith("EXPOSED: SSH") for t in titles)
    assert not any(t.startswith("Protected by") for t in titles)


def test_confirmed_cdn_edge_skips_origin_service_noise(monkeypatch):
    import plugins.network_scanner as ns

    class FakeScanner:
        engine = "fake"

        def __init__(self, ports="top100", **kw):
            pass

        def scan(self, host):
            return [{"port": 22, "response_time_ms": 1}, {"port": 443, "response_time_ms": 1}]

    class _Resp:
        headers = {"cf-ray": "abc", "server": "cloudflare"}

    class _Handler:
        def get(self, url, **kw):
            return _Resp()

    monkeypatch.setattr(ns, "NetworkScanner", FakeScanner)
    plugin = ns.NetworkScannerPlugin()
    monkeypatch.setattr(plugin, "_is_cloudflare_ip", lambda ip: True)
    monkeypatch.setattr(plugin, "_validate_service", lambda host, port, service: True)
    monkeypatch.setattr(ns.socket, "gethostbyname", lambda host: "104.16.1.1")

    findings = plugin.scan({"url": "https://example.test/", "depth": 0}, _Handler())
    titles = [f.title for f in findings]
    assert any(t.startswith("Protected by") for t in titles)
    assert not any(t.startswith("EXPOSED:") for t in titles)
