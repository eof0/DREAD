"""Crawler source-mining: endpoints hiding in HTML comments, non-anchor tags, data-*."""

from __future__ import annotations

import sys
from pathlib import Path

_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))

from scanner.crawler import Crawler

HTML = """
<html><body>
  <!-- TODO: remove /admin/secret-panel before launch; old api at /api/v1/legacy -->
  <a href="/public/page">visible</a>
  <link rel="stylesheet" href="/assets/site.css">
  <link rel="prefetch" href="/beta/dashboard">
  <iframe src="/embedded/report"></iframe>
  <area href="/map/zone-1">
  <div data-url="/api/data/feed" data-x="not a url">x</div>
  <meta http-equiv="refresh" content="3; url=/after/redirect">
  <script>const api = "/api/v1/orders";</script>
</body></html>
"""


def test_mines_hidden_endpoints_from_source():
    crawler = Crawler("https://site.test/", max_depth=2, max_urls=100)
    links = crawler.extract_links(HTML, "https://site.test/")

    # comment-hidden endpoints
    assert "https://site.test/admin/secret-panel" in links
    assert "https://site.test/api/v1/legacy" in links
    # non-anchor carriers
    assert "https://site.test/beta/dashboard" in links      # <link rel=prefetch>
    assert "https://site.test/embedded/report" in links     # <iframe>
    assert "https://site.test/map/zone-1" in links          # <area>
    # data-* url + meta refresh
    assert "https://site.test/api/data/feed" in links
    assert "https://site.test/after/redirect" in links
    # still gets the normal ones
    assert "https://site.test/public/page" in links
    assert "https://site.test/api/v1/orders" in links       # inline script


def test_mining_stays_same_site_and_skips_assets():
    crawler = Crawler("https://site.test/", max_depth=2, max_urls=100)
    html = """
    <!-- external note: https://evil.test/collect and /assets/app.css -->
    <iframe src="https://cdn.evil.test/widget"></iframe>
    """
    links = crawler.extract_links(html, "https://site.test/")
    assert all("evil.test" not in link for link in links)   # off-site dropped
    assert all(not link.endswith(".css") for link in links)  # assets dropped
