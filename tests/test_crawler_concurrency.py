"""BFS crawl batches page fetches concurrently instead of one request at a time.

The serial `queue.pop(0) -> request_handler.get(url)` loop made total crawl time
scale with (page count * round-trip latency), even though RequestHandler already
pools connections and would happily serve several in-flight requests at once.
Crawler now pulls a batch off the queue and fetches it through a ThreadPoolExecutor,
while RequestHandler's own rate limiter (a shared lock around dispatch timing)
still paces how fast the *target* actually receives requests — concurrency only
removes the scanner's own idle waiting, it does not relax politeness.
"""

from __future__ import annotations

import sys
import threading
from pathlib import Path

_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))

from scanner.crawler import Crawler, _AGGRESSIVE_CRAWL_CONCURRENCY, _DEFAULT_CRAWL_CONCURRENCY


class _Resp:
    def __init__(self, status=200, text="", content_type="text/html"):
        self.status_code = status
        self.text = text
        self.headers = {"Content-Type": content_type}
        self.url = ""


_LEAF_COUNT = 6
_ENTRY_HTML = "<html>" + "".join(
    f'<a href="/page{i}">p{i}</a>' for i in range(_LEAF_COUNT)) + "</html>"


class _ConcurrencyProbeHandler:
    """Records how many `.get()` calls were ever in flight at the same time."""

    def __init__(self, delay: float = 0.03):
        self.delay = delay
        self._lock = threading.Lock()
        self._current = 0
        self.max_concurrent = 0
        self.calls: list[str] = []

    def get(self, url, **kwargs):
        with self._lock:
            self._current += 1
            self.max_concurrent = max(self.max_concurrent, self._current)
            self.calls.append(url)
        import time
        time.sleep(self.delay)
        with self._lock:
            self._current -= 1
        if url.rstrip("/") == "https://site.test":
            return _Resp(200, _ENTRY_HTML)
        return _Resp(200, "<html>leaf, no further links</html>")


def test_crawl_dispatches_a_batch_concurrently():
    handler = _ConcurrencyProbeHandler()
    crawler = Crawler("https://site.test/", max_depth=1, max_urls=50)

    crawler.crawl(handler)

    # 6 leaf pages under a default concurrency of 5 -> at least a few must overlap.
    assert handler.max_concurrent >= 3


def test_batched_crawl_visits_every_page_exactly_once():
    handler = _ConcurrencyProbeHandler(delay=0.01)
    crawler = Crawler("https://site.test/", max_depth=1, max_urls=50)

    results = crawler.crawl(handler)

    urls = [r["url"] for r in results]
    assert len(urls) == len(set(urls))          # no duplicate fetches
    assert len(urls) == 1 + _LEAF_COUNT          # entry page + every leaf
    # seed_urls() probes robots.txt/sitemap.xml/catch-all before the BFS loop runs,
    # so handler.calls includes those too -- every *crawled* URL still appears once.
    for url in urls:
        assert handler.calls.count(url) == 1


def test_aggressive_mode_widens_crawl_concurrency():
    default_crawler = Crawler("https://site.test/", aggressive=False)
    aggressive_crawler = Crawler("https://site.test/", aggressive=True)

    assert default_crawler._crawl_concurrency == _DEFAULT_CRAWL_CONCURRENCY
    assert aggressive_crawler._crawl_concurrency == _AGGRESSIVE_CRAWL_CONCURRENCY
    assert aggressive_crawler._crawl_concurrency > default_crawler._crawl_concurrency


def test_max_urls_budget_is_still_respected_across_batches():
    handler = _ConcurrencyProbeHandler(delay=0.01)
    crawler = Crawler("https://site.test/", max_depth=1, max_urls=4)

    results = crawler.crawl(handler)

    assert len(results) <= 4
    assert len(crawler.visited_urls) <= 4


def test_cancel_checked_between_batches_stops_further_fetching():
    handler = _ConcurrencyProbeHandler(delay=0.01)
    crawler = Crawler("https://site.test/", max_depth=1, max_urls=50)

    calls = {"n": 0}

    def cancel_after_first_batch():
        calls["n"] += 1
        return calls["n"] > 1   # let the entry-page batch run, then stop

    results = crawler.crawl(handler, cancel_check=cancel_after_first_batch)

    # Only the entry page's batch was fetched; the discovered leaf batch never ran.
    assert len(results) == 1
