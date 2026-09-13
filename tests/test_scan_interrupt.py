"""Press-a-key-to-stop: cancel wiring across RequestHandler, Crawler, and the engine."""

from __future__ import annotations

import sys
from pathlib import Path

_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))

from scanner.crawler import Crawler
from scanner.interrupt import KeypressCanceller


class _Resp:
    def __init__(self, status=404):
        self.status_code = status
        self.text = "nope"
        self.headers = {"Content-Type": "text/html"}
        self.url = ""


class _Handler:
    def get(self, url, **kwargs):
        return _Resp(404)


def test_crawler_stops_immediately_on_cancel():
    crawler = Crawler("https://site.test/", max_depth=3, max_urls=50)
    urls = crawler.crawl(_Handler(), cancel_check=lambda: True)
    assert urls == []          # cancelled before crawling the entry page


def test_crawler_runs_normally_without_cancel():
    crawler = Crawler("https://site.test/", max_depth=1, max_urls=10)
    urls = crawler.crawl(_Handler())        # cancel_check defaults to never
    assert any(u["url"].startswith("https://site.test") for u in urls)


def test_keypress_canceller_is_noop_off_a_tty(monkeypatch):
    # Piped/non-TTY stdin (tests, CI, subprocess): the watcher must not engage.
    class _NotATty:
        def isatty(self):
            return False

    monkeypatch.setattr("scanner.interrupt.sys.stdin", _NotATty())
    called = []
    with KeypressCanceller(lambda: called.append(1)) as c:
        assert c.enabled is False
    assert called == []


def test_engine_request_cancel_sets_flag_and_aborts_handler():
    from scanner.config import ScanConfig
    from scanner.engine import ScanEngine

    engine = ScanEngine(ScanConfig("http://x.test"))
    assert engine._cancelled is False
    engine._request_cancel()
    assert engine._cancelled is True
    assert engine.request_handler.aborted is True
    engine._request_cancel()               # idempotent
    assert engine.request_handler.aborted is True
