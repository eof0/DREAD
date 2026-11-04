from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))

from plugins.security_headers import SecurityHeadersPlugin


class _Handler:
    def get(self, url, **kw):
        return None


def _url_info(url: str, content_type: str, extra_headers: dict | None = None):
    headers = {"Content-Type": content_type}
    if extra_headers:
        headers.update(extra_headers)
    return {
        "url": url,
        "response": SimpleNamespace(headers=headers),
    }


def test_json_api_still_checks_hsts_and_nosniff():
    plugin = SecurityHeadersPlugin()
    findings = plugin.scan(
        _url_info("https://example.test/api/v1", "application/json"),
        _Handler(),
    )
    titles = {f.title for f in findings}
    assert "Missing Strict-Transport-Security Header" in titles
    assert "Missing X-Content-Type-Options Header" in titles
    assert "Missing X-Frame-Options Header" not in titles
    assert "Missing Content-Security-Policy Header" not in titles


def test_html_still_checks_page_headers():
    plugin = SecurityHeadersPlugin()
    findings = plugin.scan(
        _url_info("https://example.test/", "text/html; charset=utf-8"),
        _Handler(),
    )
    titles = {f.title for f in findings}
    assert "Missing X-Frame-Options Header" in titles
    assert "Missing Content-Security-Policy Header" in titles
