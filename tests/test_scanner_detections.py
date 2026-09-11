"""
Real-HTTP regression net for Probe's detectors.

This drives the actual RequestHandler over a real socket against a tiny in-test
WSGI *simulator* that merely *returns* vulnerable-shaped responses — it contains
no vulnerable code (no SQL, no template engine, no shell), so it stays out of the
scanner's own security review. It exists to catch regressions in the request path
(retries, redirects, headers) that pure mocks can't.

The full, genuinely-vulnerable target lives in the separate DreadCTF project. To
run these checks against it instead, start DreadCTF and set DREADCTF_TARGET_URL.
"""

from __future__ import annotations

import os
import re
import sys
import threading
from pathlib import Path
from wsgiref.simple_server import WSGIRequestHandler, make_server

import pytest

_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))

from plugins.cors_check import CORSCheckPlugin
from plugins.web_vulnerabilities import WebVulnerabilitiesPlugin
from scanner.request_handler import RequestHandler


def _simulator(environ, start_response):
    """A test double that returns responses shaped like a vulnerable app would.

    Nothing here is actually exploitable — values are computed and returned as
    strings. It's only here so the detectors see realistic HTTP.
    """
    from urllib.parse import parse_qs

    path = environ.get("PATH_INFO", "")
    query = parse_qs(environ.get("QUERY_STRING", ""))
    status, headers, body = "200 OK", [("Content-Type", "text/html")], ""

    if path == "/search":
        q = query.get("q", [""])[0]
        body = f"<html><body>Results for: {q}</body></html>"  # echo (XSS shape)
    elif path == "/item":
        val = query.get("id", ["1"])[0]
        if "'" in val:  # a quote "breaks" the fake query
            status, body = "500 INTERNAL SERVER ERROR", "SQL error: unrecognized token near \"'\""
    elif path == "/greet":
        name = query.get("name", [""])[0]
        m = re.fullmatch(r"\{\{(\d+)\*(\d+)\}\}", name)
        body = f"<p>Hello {int(m.group(1)) * int(m.group(2)) if m else name}</p>"
    elif path == "/ping":
        host = query.get("host", [""])[0]
        m = re.search(r"\$\(\((\d+)\*(\d+)\)\)", host)
        body = f"<pre>{int(m.group(1)) * int(m.group(2)) if m else 'pong'}</pre>"
    elif path == "/go":
        nxt = query.get("next", ["/"])[0]
        status, headers = "302 FOUND", [("Location", nxt), ("Content-Type", "text/html")]
    elif path == "/api/me":
        origin = environ.get("HTTP_ORIGIN")
        headers = [("Content-Type", "application/json")]
        if origin:  # reflect the caller's origin with credentials (CORS shape)
            headers += [("Access-Control-Allow-Origin", origin),
                        ("Access-Control-Allow-Credentials", "true")]
        body = '{"user":"alice"}'
    elif path == "/safe":
        body = "<html><body>nothing to see</body></html>"

    data = body.encode()
    start_response(status, headers + [("Content-Length", str(len(data)))])
    return [data]


@pytest.fixture(scope="module")
def target():
    if os.environ.get("DREADCTF_TARGET_URL"):
        yield os.environ["DREADCTF_TARGET_URL"].rstrip("/")
        return

    class Quiet(WSGIRequestHandler):
        def log_message(self, *_a):
            pass

    server = make_server("127.0.0.1", 0, _simulator, handler_class=Quiet)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()


def _titles(findings):
    return [f.title for f in findings]


def test_reflected_xss_detected(target):
    findings = WebVulnerabilitiesPlugin().scan({"url": f"{target}/search?q=x", "depth": 0}, RequestHandler())
    assert any("XSS" in t for t in _titles(findings))


def test_sql_injection_detected_through_500(target):
    findings = WebVulnerabilitiesPlugin().scan({"url": f"{target}/item?id=1", "depth": 0}, RequestHandler())
    assert any("SQL Injection" in t for t in _titles(findings))


def test_ssti_detected(target):
    findings = WebVulnerabilitiesPlugin().scan({"url": f"{target}/greet?name=friend", "depth": 0}, RequestHandler())
    assert any("Template Injection" in t for t in _titles(findings))


def test_command_injection_detected(target):
    findings = WebVulnerabilitiesPlugin().scan({"url": f"{target}/ping?host=1", "depth": 0}, RequestHandler())
    assert any("Command Injection" in t for t in _titles(findings))


def test_open_redirect_detected(target):
    findings = WebVulnerabilitiesPlugin().scan({"url": f"{target}/go?next=/x", "depth": 0}, RequestHandler())
    assert any("Open Redirect" in t for t in _titles(findings))


def test_cors_detected(target):
    findings = CORSCheckPlugin().scan({"url": f"{target}/api/me", "depth": 0}, RequestHandler())
    assert any("CORS" in t for t in _titles(findings))


def test_no_false_positive_on_static_page(target):
    findings = WebVulnerabilitiesPlugin().scan({"url": f"{target}/safe", "depth": 0}, RequestHandler())
    assert findings == []
