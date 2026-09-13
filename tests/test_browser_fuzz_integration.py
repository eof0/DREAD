"""The fuzzer attacks browser-captured API endpoints that static crawling never sees."""

from __future__ import annotations

import sys
from pathlib import Path

from requests import Response

_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))

from plugins.web_vulnerabilities import WebVulnerabilitiesPlugin
from scanner import browser_crawler


def _resp(body, status=200, ctype="text/html"):
    r = Response()
    r.status_code = status
    r._content = body.encode()
    r.encoding = "utf-8"
    r.headers = {"Content-Type": ctype}
    return r


class Handler:
    """A SPA whose landing page has NO links; the vuln lives in a JS-only API call."""

    def __init__(self):
        self.calls = []

    def get(self, url, **kwargs):
        params = kwargs.get("params")
        if params is None:
            # The landing page — nothing to statically crawl.
            return _resp("<html><body><div id=app></div></body></html>")
        # The browser-discovered API endpoint, vulnerable to error-based SQLi.
        self.calls.append((url, params))
        value = params.get("id", "")
        if isinstance(value, list):
            value = value[0]
        if "'" in str(value):
            return _resp("SQL error: unrecognized token near \"'\"", status=500)
        return _resp("<html>ok</html>")

    def post(self, url, **kwargs):
        return _resp("<html>ok</html>")

    class _Session:
        cookies = []
        headers = {}

    session = _Session()


def test_browser_captured_endpoint_is_fuzzed_and_sqli_found(monkeypatch):
    # The browser "captures" a fetch to /api/item?id=1 that the static HTML never links.
    monkeypatch.setattr(browser_crawler, "crawl_interactive", lambda url, allowed, **kw:
                        browser_crawler.BrowserResult(
                            rendered=True,
                            requests=[browser_crawler.CapturedRequest(
                                "GET", "https://app.test/api/item?id=1", None, None, "xhr")]))

    findings = WebVulnerabilitiesPlugin().scan(
        {"url": "https://app.test/", "depth": 0, "render_js": True},
        Handler(),
    )

    assert any("SQL Injection" in f.title for f in findings)


def test_no_browser_crawl_without_render_js(monkeypatch):
    called = {"n": 0}
    monkeypatch.setattr(browser_crawler, "crawl_interactive",
                        lambda *a, **k: called.__setitem__("n", called["n"] + 1) or
                        browser_crawler.BrowserResult())

    WebVulnerabilitiesPlugin().scan({"url": "https://app.test/", "depth": 0}, Handler())
    assert called["n"] == 0  # browser crawl only runs when render_js is on
