"""Crawler seeds from robots.txt + sitemap.xml and pulls endpoints out of JavaScript."""

from __future__ import annotations

import sys
from pathlib import Path

_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))

from scanner.crawler import Crawler


class FakeResponse:
    def __init__(self, text="", status=200, content_type="text/html"):
        self.text = text
        self.status_code = status
        self.headers = {"Content-Type": content_type}
        self.url = ""


class SeedHandler:
    """Serves robots.txt, sitemap.xml and a JS bundle; everything else is an empty page."""

    def __init__(self, pages):
        self.pages = pages
        self.requested = []

    def get(self, url, **kwargs):
        self.requested.append(url)
        if url in self.pages:
            return self.pages[url]
        return FakeResponse("<html></html>")


def test_seed_urls_reads_robots_and_sitemap():
    base = "https://example.test/"
    pages = {
        "https://example.test/robots.txt": FakeResponse(
            "User-agent: *\nDisallow: /admin/\nSitemap: https://example.test/sitemap.xml\n",
            content_type="text/plain",
        ),
        "https://example.test/sitemap.xml": FakeResponse(
            "<urlset><url><loc>https://example.test/pricing</loc></url>"
            "<url><loc>https://example.test/login</loc></url></urlset>",
            content_type="application/xml",
        ),
    }
    crawler = Crawler(base, max_depth=2, max_urls=50)

    seeds = crawler.seed_urls(SeedHandler(pages))

    # Disallowed paths are still worth scanning (they often hide the interesting endpoints).
    assert "https://example.test/admin/" in seeds
    assert "https://example.test/pricing" in seeds
    assert "https://example.test/login" in seeds


def test_seed_urls_follows_sitemap_index():
    base = "https://example.test/"
    pages = {
        "https://example.test/robots.txt": FakeResponse("", status=404, content_type="text/plain"),
        "https://example.test/sitemap.xml": FakeResponse(
            "<sitemapindex><sitemap><loc>https://example.test/sitemap-1.xml</loc></sitemap></sitemapindex>",
            content_type="application/xml",
        ),
        "https://example.test/sitemap-1.xml": FakeResponse(
            "<urlset><url><loc>https://example.test/deep/page</loc></url></urlset>",
            content_type="application/xml",
        ),
    }
    crawler = Crawler(base, max_depth=2, max_urls=50)

    seeds = crawler.seed_urls(SeedHandler(pages))

    assert "https://example.test/deep/page" in seeds


def test_extract_links_pulls_same_site_paths_from_javascript():
    crawler = Crawler("https://example.test/", max_depth=2, max_urls=50)
    html = """
    <html><body>
      <script src="/assets/app.js"></script>
      <script>
        const api = "/api/v1/orders";
        fetch("https://example.test/api/v1/cart/add");
        var ext = "https://evil.test/collect";
        const rel = 'user/profile?id=1';
      </script>
    </body></html>
    """

    links = crawler.extract_links(html, "https://example.test/")

    assert "https://example.test/api/v1/orders" in links
    assert "https://example.test/api/v1/cart/add" in links
    assert "https://example.test/user/profile?id=1" in links
    assert all("evil.test" not in link for link in links)


def test_javascript_bundle_endpoints_are_discovered():
    crawler = Crawler("https://example.test/", max_depth=2, max_urls=50)
    js = 'axios.post("/api/v1/login"); const p = "/dashboard/reports";'

    paths = crawler.extract_js_endpoints(js, "https://example.test/app.js")

    assert "https://example.test/api/v1/login" in paths
    assert "https://example.test/dashboard/reports" in paths


class Strict404Handler:
    """Serves the listed pages; everything else 404s (so it isn't a catch-all)."""

    def __init__(self, pages):
        self.pages = pages

    def get(self, url, **kwargs):
        return self.pages.get(url, FakeResponse("not found", status=404))


def test_seed_urls_discovers_unlinked_common_routes():
    base = "https://example.test/"
    # /login and /redirect exist (200/302); /admin is 404 (absent); robots/sitemap empty.
    pages = {
        "https://example.test/login": FakeResponse("<html>login</html>", status=200),
        "https://example.test/redirect": FakeResponse("", status=302),
    }
    crawler = Crawler(base, max_depth=2, max_urls=50)

    seeds = crawler.seed_urls(Strict404Handler(pages))

    assert "https://example.test/login" in seeds
    assert "https://example.test/redirect" in seeds       # unlinked but exists (302)
    assert "https://example.test/admin" not in seeds       # 404 -> not queued


def test_common_routes_skipped_on_catch_all_server():
    # An SPA router that returns 200 for EVERY path: route-probing would false-positive,
    # so it must be skipped (no phantom routes queued).
    class CatchAll:
        def get(self, url, **kwargs):
            return FakeResponse("<html>app</html>", status=200)

    crawler = Crawler("https://spa.test/", max_depth=2, max_urls=50)
    seeds = crawler.seed_urls(CatchAll())
    assert not any(seed.endswith(("/login", "/admin", "/redirect")) for seed in seeds)
