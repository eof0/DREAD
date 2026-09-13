"""End-to-end: the browser crawler captures a fetch that only fires after user interaction."""

from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread

import pytest

_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))


def _chromium_or_skip():
    pytest.importorskip("playwright")
    from playwright.sync_api import sync_playwright

    try:
        with sync_playwright() as p:
            p.chromium.launch(headless=True).close()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Chromium unavailable: {exc}")


# A SPA whose only real API call (/api/search?q=...) happens after a button click and
# a form submit — invisible to a static HTML crawler.
_SPA = b"""<!doctype html><html><body>
<form id="f" onsubmit="event.preventDefault(); fetch('/api/login', {method:'POST',
  headers:{'Content-Type':'application/json'}, body: JSON.stringify({user: u.value})});">
  <input id="u" name="user" placeholder="username">
  <button type="submit">Login</button>
</form>
<button id="go" onclick="fetch('/api/search?q=' + encodeURIComponent('hello'))">Search</button>
</body></html>"""


def _serve(body: bytes) -> HTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self._send(body if self.path == "/" else b"{}")

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            self._send(b"{}")

        def _send(self, payload):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_a):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_captures_interaction_driven_api_calls_and_makes_targets():
    _chromium_or_skip()
    from scanner.browser_crawler import captured_to_fuzz_targets, crawl_interactive

    server = _serve(_SPA)
    host = f"127.0.0.1:{server.server_address[1]}"
    try:
        result = crawl_interactive(f"http://{host}/", {host})
    finally:
        server.shutdown()

    assert result.rendered is True
    paths = {r.url.split(host)[1].split("?")[0] for r in result.requests}
    assert "/api/search" in paths          # captured the click-driven GET fetch
    assert "/api/login" in paths           # captured the submit-driven POST fetch

    targets = captured_to_fuzz_targets(result.requests, {host})
    kinds = {(t["method"], t["location"]) for t in targets}
    assert ("GET", "query") in kinds       # /api/search?q= is now a fuzz target
    assert ("POST", "json") in kinds       # /api/login JSON body is now a fuzz target
