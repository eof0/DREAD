"""Crawl trap detection: don't let one infinite/near-infinite URL space (calendars,
session IDs, sort loops, deeply repeated path segments) burn the whole max_urls budget
instead of the site's real content.

Salvaged from the long-dead, never-wired-in probe/scanner/smart_crawler.py (a full
duplicate crawler with an inferior robots/link-extraction/BFS implementation next to
every one of those already better-built in crawler.py) — this was the one genuinely
missing safety net, so it moves into the real Crawler and the rest of that file goes.
"""

from __future__ import annotations

import sys
from pathlib import Path

_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))

from scanner.crawler import Crawler, CrawlTrapDetector


class _Resp:
    def __init__(self, status=200, text="", content_type="text/html"):
        self.status_code = status
        self.text = text
        self.headers = {"Content-Type": content_type}
        self.url = ""


# -- Unit tests: CrawlTrapDetector in isolation --------------------------------------

def test_normal_url_is_not_a_trap():
    detector = CrawlTrapDetector()
    assert detector.is_trap("https://example.test/about") is False


def test_session_id_query_param_is_a_trap():
    detector = CrawlTrapDetector()
    assert detector.is_trap("https://example.test/page?sessionid=abc123") is True
    assert detector.is_trap("https://example.test/page?jsessionid=XYZ") is True
    assert detector.is_trap("https://example.test/page?sid=99") is True


def test_excessive_query_parameters_is_a_trap():
    detector = CrawlTrapDetector()
    url = "https://example.test/search?a=1&b=2&c=3&d=4&e=5&f=6"
    assert detector.is_trap(url) is True


def test_sort_order_loop_is_a_trap():
    detector = CrawlTrapDetector()
    assert detector.is_trap("https://example.test/list?sort=asc&x=1&sort=desc") is True


def test_overlong_url_is_a_trap():
    detector = CrawlTrapDetector(max_url_length=50)
    assert detector.is_trap("https://example.test/" + "a" * 60) is True


def test_repeating_path_segments_is_a_trap():
    detector = CrawlTrapDetector()
    assert detector.is_trap("https://example.test/foo/foo/foo/foo") is True


def test_same_generalized_pattern_becomes_a_trap_after_the_limit():
    detector = CrawlTrapDetector(pattern_repeat_limit=10)
    # 10 distinct-but-structurally-identical URLs -> none flagged yet.
    for i in range(1, 11):
        assert detector.is_trap(f"https://example.test/article/{i}") is False
    # The 11th of the same pattern crosses the limit.
    assert detector.is_trap("https://example.test/article/11") is True


# -- Integration: wired into Crawler.crawl() ------------------------------------------

_ARTICLE_COUNT = 15
_ENTRY_HTML = (
    "<html>"
    + "".join(f'<a href="/article/{i}">a{i}</a>' for i in range(1, _ARTICLE_COUNT + 1))
    + '<a href="/about">about</a>'
    + '<a href="/contact?sessionid=deadbeef">contact</a>'
    + "</html>"
)


class _Handler:
    def __init__(self):
        self.fetched: list[str] = []

    def get(self, url, **kwargs):
        self.fetched.append(url)
        if url.rstrip("/") == "https://site.test":
            return _Resp(200, _ENTRY_HTML)
        return _Resp(200, "<html>leaf, no further links</html>")


def test_crawl_stops_feeding_an_article_id_trap_but_still_reaches_real_pages():
    handler = _Handler()
    crawler = Crawler("https://site.test/", max_depth=1, max_urls=50)

    results = crawler.crawl(handler)

    fetched_articles = [r for r in results if "/article/" in r["url"]]
    # The pattern-repeat limit (10) caps how many of the near-identical article URLs
    # actually get fetched -- nowhere near all 15 that were linked.
    assert len(fetched_articles) <= 10
    # The genuinely different pages still get crawled; the trap didn't eat the budget.
    assert any(r["url"].endswith("/about") for r in results)


def test_crawl_never_fetches_a_session_id_url():
    handler = _Handler()
    crawler = Crawler("https://site.test/", max_depth=1, max_urls=50)

    crawler.crawl(handler)

    assert not any("sessionid=" in url for url in handler.fetched)
