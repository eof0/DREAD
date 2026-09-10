from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlparse

import pytest

_ORIGINAL_IMPORT = __import__

from scanner.active_checks.dom_xss import (
    DOM_PROBE_SCRIPT,
    build_probe_url,
    finding_from_event,
    is_allowed_browser_request,
    scan_dom,
)


def test_probe_url_preserves_target_origin_and_adds_query_and_fragment_canaries():
    probe, query_token, fragment_token = build_probe_url(
        "https://example.test/app?next=%2Fhome#old"
    )

    parsed = urlparse(probe)
    assert (parsed.scheme, parsed.netloc, parsed.path) == (
        "https",
        "example.test",
        "/app",
    )
    assert parse_qs(parsed.query)["dread_dom"] == [query_token]
    assert parsed.fragment == f"dread_dom={fragment_token}"
    assert query_token != fragment_token


def test_browser_request_policy_allows_same_origin_get_only():
    origin = ("https", "example.test", 443)
    assert is_allowed_browser_request(origin, "https://example.test/app.js", "GET")
    assert not is_allowed_browser_request(origin, "https://cdn.example.test/app.js", "GET")
    assert not is_allowed_browser_request(origin, "https://example.test/submit", "POST")
    assert not is_allowed_browser_request(origin, "javascript:alert(1)", "GET")


def test_dom_event_becomes_redacted_finding():
    finding = finding_from_event(
        "https://example.test/app",
        {"sink": "innerHTML", "source": "fragment", "element": "DIV#result"},
    )

    assert finding.title == "DOM-based XSS"
    assert finding.severity == "high"
    assert finding.url == "https://example.test/app"
    assert finding.evidence == {"sink": "innerHTML", "source": "fragment", "element": "DIV#result"}
    assert "dread" not in str(finding.evidence).lower()


def test_scan_dom_skips_when_playwright_is_unavailable(monkeypatch):
    monkeypatch.setattr("builtins.__import__", _missing_playwright_import)
    assert scan_dom("https://example.test/") == []


def test_browser_detects_fragment_value_reaching_inner_html():
    pytest.importorskip("playwright")
    from playwright.sync_api import sync_playwright

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            browser.close()
    except Exception as exc:
        pytest.skip(f"Chromium unavailable: {exc}")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"<div id='sink'></div><script>document.querySelector('#sink').innerHTML = location.hash.split('=')[1]</script>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    Thread(target=server.serve_forever, daemon=True).start()
    try:
        findings = scan_dom(f"http://127.0.0.1:{server.server_port}/")
        assert [finding.title for finding in findings] == ["DOM-based XSS"]
        assert findings[0].evidence["source"] == "fragment"
    finally:
        server.shutdown()


def test_probe_script_is_present_and_does_not_include_a_payload():
    assert "__dread_dom_events" in DOM_PROBE_SCRIPT
    assert "innerHTML" in DOM_PROBE_SCRIPT
    assert "outerHTML" in DOM_PROBE_SCRIPT
    assert "insertAdjacentHTML" in DOM_PROBE_SCRIPT
    assert "WebSockets are disabled" in DOM_PROBE_SCRIPT


def _missing_playwright_import(name, *args, **kwargs):
    if name.startswith("playwright"):
        raise ImportError("playwright unavailable")
    return _ORIGINAL_IMPORT(name, *args, **kwargs)
