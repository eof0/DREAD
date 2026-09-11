"""End-to-end: a real headless browser discovers links a JS/SPA builds at runtime."""

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
        with sync_playwright() as playwright:
            playwright.chromium.launch(headless=True).close()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Chromium unavailable: {exc}")


# A page whose only navigable links are injected by JavaScript after load — a static
# HTML parse sees nothing, so this proves rendering adds real coverage.
_SPA_BODY = b"""<!doctype html><html><body>
<div id="app"></div>
<script>
  const app = document.getElementById('app');
  const routes = ['/dashboard', '/api/v1/orders', '/settings/profile'];
  routes.forEach(r => {
    const a = document.createElement('a');
    a.href = r;
    a.textContent = r;
    app.appendChild(a);
  });
</script>
</body></html>"""


def _serve(body: bytes) -> HTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_render_page_discovers_javascript_injected_links():
    _chromium_or_skip()
    from scanner.js_render import render_page

    server = _serve(_SPA_BODY)
    host = f"127.0.0.1:{server.server_port}"
    try:
        result = render_page(f"http://{host}/", {host})
    finally:
        server.shutdown()

    assert result.rendered is True
    paths = {p.replace(f"http://{host}", "") for p in result.links}
    assert {"/dashboard", "/api/v1/orders", "/settings/profile"} <= paths


def test_crawler_with_render_js_finds_spa_routes():
    _chromium_or_skip()
    from scanner.crawler import Crawler

    server = _serve(_SPA_BODY)
    host = f"127.0.0.1:{server.server_port}"

    class RH:
        def get(self, url, **kwargs):
            import requests

            try:
                return requests.get(url, timeout=5)
            except Exception:
                return None

    try:
        crawler = Crawler(f"http://{host}/", max_depth=1, max_urls=20, render_js=True)
        crawler.crawl(RH())
    finally:
        server.shutdown()

    crawled = crawler.visited_urls
    assert any(u.endswith("/api/v1/orders") for u in crawled)
    assert any(u.endswith("/dashboard") for u in crawled)
