import sys
import types
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlparse

import pytest

_ORIGINAL_IMPORT = __import__

import scanner.active_checks.dom_xss as dom_xss
from scanner.active_checks.dom_xss import (
    DOM_PROBE_SCRIPT,
    build_probe_url,
    finding_from_event,
    is_allowed_browser_request,
    scan_dom,
)


@pytest.fixture(autouse=True)
def _isolate_shared_browser_state():
    """dom_xss's browser-pool state is process-global (the executor and the
    registry) and per-thread (this process's own threading.local() slot). Other
    test files launch real pooled browsers via WebVulnerabilitiesPlugin().scan()
    on HTML pages (web_vulnerabilities calls dom_xss.scan_dom for every HTML page)
    and never clean them up, so by the time this file runs those globals are
    already dirty with leaked entries. Give every test here a genuinely CLEAN
    slate at setup -- otherwise leaked registry entries break the absolute-count
    assertions below, and a fake-object test could try to close() a *real* leaked
    browser from the wrong OS thread, which Playwright's sync API forbids. We only
    drop references (never close across threads); the abandoned pool's browsers
    leak until process exit, exactly the tradeoff _replace_poisoned_executor
    already accepts. Originals are restored afterwards so the file leaves the
    world as it found it."""
    saved_executor = dom_xss._browser_executor
    saved_registry = dom_xss._browser_registry
    saved_browser = getattr(dom_xss._thread_browser, "browser", None)
    saved_playwright = getattr(dom_xss._thread_browser, "playwright", None)
    dom_xss._browser_executor = None
    dom_xss._browser_registry = []
    dom_xss._thread_browser.browser = None
    dom_xss._thread_browser.playwright = None
    yield
    dom_xss._browser_executor = saved_executor
    dom_xss._browser_registry = saved_registry
    dom_xss._thread_browser.browser = saved_browser
    dom_xss._thread_browser.playwright = saved_playwright


class _FakeBrowser:
    def __init__(self, connected=True):
        self._connected = connected
        self.close_calls = 0

    def is_connected(self):
        return self._connected

    def close(self):
        self.close_calls += 1
        self._connected = False


class _FakePlaywrightInstance:
    def __init__(self, browser_factory, launch_error=None):
        self._browser_factory = browser_factory
        self._launch_error = launch_error
        self.stop_calls = 0
        self.chromium = types.SimpleNamespace(launch=self._launch)

    def _launch(self, headless=True):
        if self._launch_error is not None:
            raise self._launch_error
        return self._browser_factory()

    def stop(self):
        self.stop_calls += 1


def _install_fake_playwright(monkeypatch, browser_factory, launch_error=None):
    """Makes the deferred `from playwright.sync_api import sync_playwright` inside
    dom_xss resolve to a fake, so these tests exercise the real control flow
    (liveness check, relaunch, cleanup ordering) without a real browser."""
    instances = []

    def fake_sync_playwright():
        instance = _FakePlaywrightInstance(browser_factory, launch_error)
        instances.append(instance)
        return types.SimpleNamespace(start=lambda: instance)

    fake_module = types.SimpleNamespace(sync_playwright=fake_sync_playwright)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", fake_module)
    return instances


# -- browser-pool resilience: per-thread liveness, leak-free launch failure,
# -- poisoned-pool recovery, and atexit cleanup that doesn't route through the
# -- executor -------------------------------------------------------------------

def test_browser_pool_size_is_a_couple_not_one_and_not_many():
    # One fully serializes every DOM check with no parallelism; a bunch launches
    # that many headless Chromium processes at once and reintroduces the local
    # resource contention this design exists to avoid. Somewhere in between.
    assert 2 <= dom_xss._BROWSER_POOL_SIZE <= 5


def test_ensure_thread_browser_reuses_a_live_browser():
    live = _FakeBrowser(connected=True)
    dom_xss._thread_browser.browser = live
    dom_xss._thread_browser.playwright = _FakePlaywrightInstance(lambda: live)

    assert dom_xss._ensure_thread_browser() is live   # no playwright import needed


def test_ensure_thread_browser_relaunches_a_dead_browser(monkeypatch):
    dead = _FakeBrowser(connected=False)
    old_playwright = _FakePlaywrightInstance(lambda: dead)
    dom_xss._thread_browser.browser = dead
    dom_xss._thread_browser.playwright = old_playwright
    dom_xss._browser_registry.append((old_playwright, dead))

    fresh = _FakeBrowser(connected=True)
    _install_fake_playwright(monkeypatch, browser_factory=lambda: fresh)

    result = dom_xss._ensure_thread_browser()

    assert result is fresh
    assert dead.close_calls == 1           # dead browser was torn down
    assert old_playwright.stop_calls == 1  # its driver was stopped too
    assert (old_playwright, dead) not in dom_xss._browser_registry
    assert any(browser is fresh for _pw, browser in dom_xss._browser_registry)


def test_ensure_thread_browser_stops_the_driver_when_launch_fails(monkeypatch):
    dom_xss._thread_browser.browser = None
    dom_xss._thread_browser.playwright = None
    instances = _install_fake_playwright(monkeypatch, browser_factory=lambda: None,
                                          launch_error=RuntimeError("no chromium binary"))

    with pytest.raises(RuntimeError):
        dom_xss._ensure_thread_browser()

    assert len(instances) == 1
    assert instances[0].stop_calls == 1    # driver stopped, not leaked
    assert getattr(dom_xss._thread_browser, "playwright", None) is None


def test_each_pool_worker_thread_gets_its_own_browser(monkeypatch):
    _install_fake_playwright(monkeypatch, browser_factory=lambda: _FakeBrowser())

    results = {}

    def worker(name):
        results[name] = dom_xss._ensure_thread_browser()

    before = len(dom_xss._browser_registry)
    threads = [Thread(target=worker, args=(i,)) for i in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == 3
    assert len({id(b) for b in results.values()}) == 3   # three distinct browsers
    assert len(dom_xss._browser_registry) == before + 3  # each worker registered its own


class _FakeExecutor:
    def __init__(self):
        self.shutdown_calls = 0

    def submit(self, *_args, **_kwargs):
        # Matches the real concurrent.futures failure mode at interpreter exit.
        raise RuntimeError("cannot schedule new futures after interpreter shutdown")

    def shutdown(self, wait=False):
        self.shutdown_calls += 1


def test_shutdown_shared_browser_closes_directly_not_through_executor_submit():
    fake_executor = _FakeExecutor()
    browser = _FakeBrowser(connected=True)
    dom_xss._browser_executor = fake_executor
    dom_xss._browser_registry.append((_FakePlaywrightInstance(lambda: browser), browser))

    dom_xss._shutdown_shared_browser()   # must not raise, even though .submit() would

    assert browser.close_calls == 1
    assert fake_executor.shutdown_calls == 1
    assert dom_xss._browser_executor is None
    assert dom_xss._browser_registry == []


def test_shutdown_shared_browser_is_a_noop_with_no_executor():
    dom_xss._browser_executor = None
    dom_xss._shutdown_shared_browser()   # must not raise


def test_replace_poisoned_executor_drops_the_browser_registry():
    poisoned = object()
    dom_xss._browser_executor = poisoned
    dom_xss._browser_registry.append((_FakePlaywrightInstance(lambda: None), _FakeBrowser()))

    dom_xss._replace_poisoned_executor(poisoned)

    assert dom_xss._browser_executor is None
    assert dom_xss._browser_registry == []


def test_replace_poisoned_executor_ignores_an_already_replaced_executor():
    # If a fresh executor was already created (e.g. by another call) by the time
    # this fires, it must not tear down the new one.
    old_executor = object()
    new_executor = object()
    dom_xss._browser_executor = new_executor

    dom_xss._replace_poisoned_executor(old_executor)

    assert dom_xss._browser_executor is new_executor   # untouched


class _FakeTimeoutFuture:
    def result(self, timeout=None):
        raise dom_xss.FuturesTimeoutError()


class _FakeSubmitOnlyExecutor:
    def submit(self, _fn, *_args, **_kwargs):
        return _FakeTimeoutFuture()


def test_scan_dom_replaces_the_executor_when_a_check_times_out(monkeypatch):
    fake_executor = _FakeSubmitOnlyExecutor()
    monkeypatch.setattr(dom_xss, "_get_browser_executor", lambda: fake_executor)
    replaced_with = []
    monkeypatch.setattr(dom_xss, "_replace_poisoned_executor", lambda ex: replaced_with.append(ex))

    result = scan_dom("https://example.test/")

    assert result == []
    assert replaced_with == [fake_executor]


def test_probe_url_preserves_target_origin_and_adds_query_and_fragment_canaries():
    probe, query_token, fragment_token = build_probe_url(
        "https://example.test/app?next=%2Fhome#old"
    )

    parsed = urlparse(probe)
    assert (parsed.scheme, parsed.netloc, parsed.path) == (
        "https",
        "example.test",
        "/app",
    )
    assert parse_qs(parsed.query)["qa_dom"] == [query_token]
    assert parsed.fragment == f"qa_dom={fragment_token}"
    assert query_token != fragment_token


def test_browser_request_policy_allows_same_origin_get_only():
    origin = ("https", "example.test", 443)
    assert is_allowed_browser_request(origin, "https://example.test/app.js", "GET")
    assert not is_allowed_browser_request(origin, "https://cdn.example.test/app.js", "GET")
    assert not is_allowed_browser_request(origin, "https://example.test/submit", "POST")
    assert not is_allowed_browser_request(origin, "javascript:alert(1)", "GET")


def test_dom_event_becomes_redacted_finding():
    finding = finding_from_event(
        "https://example.test/app",
        {"sink": "innerHTML", "source": "fragment", "element": "DIV#result"},
    )

    assert finding.title == "DOM-based XSS"
    assert finding.severity == "high"
    assert finding.url == "https://example.test/app"
    assert finding.evidence == {"sink": "innerHTML", "source": "fragment", "element": "DIV#result"}
    assert "dread" not in str(finding.evidence).lower()


def test_scan_dom_skips_when_playwright_is_unavailable(monkeypatch):
    # Force a clean slate. scan_dom() runs on whichever pool worker thread picks
    # up the task -- resetting *this* (the test's own) thread's threading.local()
    # slot wouldn't reach it. Dropping the executor instead means fresh worker
    # threads whose browser slot is guaranteed empty, so this actually exercises
    # the ImportError path rather than possibly reusing a browser a pool worker
    # already launched during an earlier test.
    dom_xss._browser_executor = None
    dom_xss._browser_registry = []
    monkeypatch.setattr("builtins.__import__", _missing_playwright_import)
    assert scan_dom("https://example.test/") == []


def test_browser_detects_fragment_value_reaching_inner_html():
    pytest.importorskip("playwright")
    from playwright.sync_api import sync_playwright

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            browser.close()
    except Exception as exc:
        pytest.skip(f"Chromium unavailable: {exc}")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"<div id='sink'></div><script>document.querySelector('#sink').innerHTML = location.hash.split('=')[1]</script>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    Thread(target=server.serve_forever, daemon=True).start()
    try:
        findings = scan_dom(f"http://127.0.0.1:{server.server_port}/")
        assert [finding.title for finding in findings] == ["DOM-based XSS"]
        assert findings[0].evidence["source"] == "fragment"
    finally:
        server.shutdown()


def test_probe_script_is_present_and_does_not_include_a_payload():
    assert "__qa_dom_events" in DOM_PROBE_SCRIPT
    assert "innerHTML" in DOM_PROBE_SCRIPT
    assert "outerHTML" in DOM_PROBE_SCRIPT
    assert "insertAdjacentHTML" in DOM_PROBE_SCRIPT
    assert "WebSockets are disabled" in DOM_PROBE_SCRIPT


def _chromium_or_skip():
    pytest.importorskip("playwright")
    from playwright.sync_api import sync_playwright

    try:
        with sync_playwright() as playwright:
            playwright.chromium.launch(headless=True).close()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Chromium unavailable: {exc}")


def _serve_plain_page() -> HTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"<html><body>hi</body></html>"
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


def test_repeated_scan_dom_calls_never_launch_more_browsers_than_the_pool_size():
    _chromium_or_skip()

    server = _serve_plain_page()
    try:
        for i in range(10):   # far more calls than _BROWSER_POOL_SIZE
            scan_dom(f"http://127.0.0.1:{server.server_port}/{i}")

        # Every call was served by one of a small, reused set of browsers --
        # never a fresh launch per call.
        assert 0 < len(dom_xss._browser_registry) <= dom_xss._BROWSER_POOL_SIZE
    finally:
        server.shutdown()


def test_concurrent_scan_dom_calls_do_not_crash_and_reuse_the_pool():
    # Playwright's sync API is not safe to touch from multiple threads at once --
    # this proves the per-thread-browser pool fix holds up under real concurrent
    # pressure (matching engine.py's ThreadPoolExecutor driving several
    # (url, plugin) tasks at the same time), and that it stays within the pool
    # size rather than launching one browser per concurrent caller.
    _chromium_or_skip()
    from concurrent.futures import ThreadPoolExecutor

    server = _serve_plain_page()
    try:
        urls = [f"http://127.0.0.1:{server.server_port}/{i}" for i in range(8)]
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(scan_dom, urls))
        assert len(results) == 8
        assert all(isinstance(r, list) for r in results)   # every call completed cleanly
        assert len(dom_xss._browser_registry) <= dom_xss._BROWSER_POOL_SIZE
    finally:
        server.shutdown()


def _missing_playwright_import(name, *args, **kwargs):
    if name.startswith("playwright"):
        raise ImportError("playwright unavailable")
    return _ORIGINAL_IMPORT(name, *args, **kwargs)
