"""JS rendering: same-site filtering is pure/testable; browser render degrades gracefully."""

from __future__ import annotations

import sys
from pathlib import Path

_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))

from scanner.js_render import RenderResult, filter_same_site, render_page


ALLOWED = {"example.test", "www.example.test"}


def test_filter_same_site_keeps_same_site_drops_assets_and_offsite():
    urls = [
        "https://example.test/api/v1/orders",
        "https://example.test/api/v1/orders#frag",   # dedup after fragment strip
        "https://www.example.test/pricing",
        "https://evil.test/collect",                  # off-site
        "https://example.test/assets/app.js",         # asset
        "https://example.test/logo.png",              # asset
    ]

    assert filter_same_site(urls, ALLOWED) == [
        "https://example.test/api/v1/orders",
        "https://www.example.test/pricing",
    ]


def test_render_page_rejects_offsite_target():
    assert render_page("https://evil.test/", ALLOWED).rendered is False


def test_render_page_without_playwright_returns_unrendered(monkeypatch):
    # Simulate Playwright not installed: import inside render_page must fail.
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("playwright"):
            raise ImportError("no playwright")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    result = render_page("https://example.test/", ALLOWED)

    assert isinstance(result, RenderResult)
    assert result.rendered is False
    assert result.links == []
