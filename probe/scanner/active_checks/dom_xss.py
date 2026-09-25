"""Bounded browser checks for JavaScript-driven DOM XSS."""

import atexit
import logging
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from plugins.base_plugin import Finding
from requests import Request

logger = logging.getLogger(__name__)
_missing_notice_lock = threading.Lock()
_missing_notice_shown = False

# web_vulnerabilities.py calls scan_dom() once per HTML page, and the engine runs
# several (url, plugin) tasks concurrently (ThreadPoolExecutor, default 8 workers) --
# a fresh sync_playwright()+chromium.launch() per call meant every scan launched and
# tore down a full headless browser per page, sometimes several at once, which is the
# dominant cost on any site with more than a handful of pages. Playwright's sync API
# is documented as unsafe to touch from more than one thread, so the fix isn't a lock
# around concurrent access -- it's a small pool of dedicated worker threads (a
# ThreadPoolExecutor reuses the same fixed set of OS threads for every submitted
# task), each with its OWN browser via threading.local(), launched lazily on first
# use and reused for that thread's life. _BROWSER_POOL_SIZE trades launch count
# against parallelism: 1 fully serializes every DOM check (no launch-thrashing, but
# no overlap either); too many launches several headless Chromium processes at once
# and reintroduces the local resource contention this was built to avoid. A handful
# is the sweet spot. Callers from any thread just get a Future back.
_BROWSER_POOL_SIZE = 3

_browser_lock = threading.Lock()
_browser_executor: ThreadPoolExecutor | None = None
_thread_browser = threading.local()          # per-worker-thread: .playwright, .browser
_browser_registry: list = []                 # every (playwright, browser) pair, for cleanup --
                                              # threading.local() data isn't reachable from
                                              # outside its owning thread, so this is the only
                                              # way atexit/pool-replacement can find them all.


def _get_browser_executor() -> ThreadPoolExecutor:
    global _browser_executor
    with _browser_lock:
        if _browser_executor is None:
            _browser_executor = ThreadPoolExecutor(max_workers=_BROWSER_POOL_SIZE,
                                                    thread_name_prefix="dom-xss-browser")
            atexit.register(_shutdown_shared_browser)
        return _browser_executor


def _replace_poisoned_executor(poisoned: ThreadPoolExecutor) -> None:
    """A submitted check didn't finish within its budget -- one of the pool's
    worker threads may be permanently wedged (a hung page.evaluate()/
    context.close() on a pathological target). Abandon the whole pool and every
    browser it might still be touching, and start fresh, rather than try to
    identify and salvage just the healthy workers -- ThreadPoolExecutor doesn't
    expose which worker ran a given future, so there's no safe way to reach into
    only the stuck one. The stuck thread(s) and their browsers leak until the
    process exits; that's the acceptable cost of not risking a new thread
    touching the same Playwright sync-API objects concurrently.
    """
    global _browser_executor, _browser_registry
    with _browser_lock:
        if _browser_executor is poisoned:
            _browser_executor = None
            _browser_registry = []


def _close_all_registered_browsers() -> None:
    """Runs directly (never through the executor -- see _shutdown_shared_browser)
    on whichever thread calls it. Only safe when every worker thread that might
    still be touching these is already dead (process exit) or was already
    abandoned (a poisoned-pool replace already cleared the registry first)."""
    global _browser_registry
    with _browser_lock:
        pairs, _browser_registry = _browser_registry, []
    for playwright, browser in pairs:
        try:
            browser.close()
        except Exception:  # noqa: BLE001 - best-effort teardown
            pass
        try:
            playwright.stop()
        except Exception:  # noqa: BLE001 - best-effort teardown
            pass


def _shutdown_shared_browser() -> None:
    """Process-exit cleanup (atexit) so a lingering scan never leaks a browser.

    Can't route this through the executor: concurrent.futures registers its own
    shutdown via threading._register_atexit, which joins every executor's worker
    threads before any plain atexit.register callback (this one included) runs --
    so executor.submit() here always raises "cannot schedule new futures after
    interpreter shutdown" (verified empirically). That join is exactly why a
    direct call is safe despite normally being a different-thread access: by the
    time this runs, every pool worker thread is already dead, so nothing else
    can be touching these objects.
    """
    global _browser_executor
    executor = _browser_executor
    if executor is None:
        return
    _close_all_registered_browsers()
    executor.shutdown(wait=False)
    _browser_executor = None


def _ensure_thread_browser():
    """Runs ON one of the pool's worker threads. Each worker lazily launches and
    keeps its own Playwright+browser (threading.local()), reused for that
    thread's remaining life, with a liveness check so a crashed/killed browser
    gets relaunched instead of silently going dark for that worker."""
    browser = getattr(_thread_browser, "browser", None)
    if browser is not None:
        if browser.is_connected():
            return browser
        _close_thread_browser()  # stale/dead -- drop it and relaunch below

    from playwright.sync_api import sync_playwright  # noqa: PLC0415 - optional dependency

    playwright = sync_playwright().start()
    try:
        browser = playwright.chromium.launch(headless=True)
    except Exception:
        # The driver process started but the browser itself failed to launch --
        # stop the driver too, so a failing/retried launch doesn't leak one
        # orphaned subprocess per attempt.
        try:
            playwright.stop()
        except Exception:  # noqa: BLE001 - best-effort teardown
            pass
        raise
    _thread_browser.playwright = playwright
    _thread_browser.browser = browser
    with _browser_lock:
        _browser_registry.append((playwright, browser))
    return browser


def _close_thread_browser() -> None:
    """Best-effort teardown of the CALLING thread's own browser -- only safe to
    call from the worker thread that owns it (threading.local() is per-thread)."""
    playwright = getattr(_thread_browser, "playwright", None)
    browser = getattr(_thread_browser, "browser", None)
    if browser is not None:
        try:
            browser.close()
        except Exception:  # noqa: BLE001 - best-effort teardown
            pass
    if playwright is not None:
        try:
            playwright.stop()
        except Exception:  # noqa: BLE001 - best-effort teardown
            pass
    _thread_browser.browser = None
    _thread_browser.playwright = None
    with _browser_lock:
        try:
            _browser_registry.remove((playwright, browser))
        except ValueError:
            pass

DOM_PROBE_SCRIPT = r"""
(() => {
  const OriginalWebSocket = window.WebSocket;
  window.WebSocket = function() {
    throw new DOMException("WebSockets are disabled during safe scanning", "SecurityError");
  };
  window.WebSocket.prototype = OriginalWebSocket.prototype;

  const queryToken = "__QUERY_TOKEN__";
  const fragmentToken = "__FRAGMENT_TOKEN__";
  const events = [];
  const record = (sink, value, element) => {
    if (typeof value !== "string") return;
    const hasQuery = value.includes(queryToken) && location.search.includes(queryToken);
    const hasFragment = value.includes(fragmentToken) && location.hash.includes(fragmentToken);
    if (!hasQuery && !hasFragment) return;
    const sources = [];
    if (hasQuery) sources.push("query");
    if (hasFragment) sources.push("fragment");
    events.push({
      sink,
      source: sources.join("+") || "unknown",
      element: element && element.tagName ? element.tagName : "document"
    });
  };
  const patchSetter = (prototype, property) => {
    const descriptor = Object.getOwnPropertyDescriptor(prototype, property);
    if (!descriptor || !descriptor.set) return;
    Object.defineProperty(prototype, property, {
      configurable: descriptor.configurable,
      enumerable: descriptor.enumerable,
      get: descriptor.get,
      set(value) {
        record(property, value, this);
        descriptor.set.call(this, value);
      }
    });
  };
  patchSetter(Element.prototype, "innerHTML");
  patchSetter(Element.prototype, "outerHTML");
  const insertAdjacentHTML = Element.prototype.insertAdjacentHTML;
  if (insertAdjacentHTML) {
    Element.prototype.insertAdjacentHTML = function(position, value) {
      record("insertAdjacentHTML", value, this);
      return insertAdjacentHTML.call(this, position, value);
    };
  }
  const write = Document.prototype.write;
  if (write) {
    Document.prototype.write = function(...values) {
      values.forEach((value) => record("document.write", value, document));
      return write.apply(this, values);
    };
  }
  const originalEval = window.eval;
  window.eval = function(value) {
    record("eval", value, document);
    return originalEval.call(this, value);
  };
  for (const name of ["setTimeout", "setInterval"]) {
    const original = window[name];
    window[name] = function(value, ...args) {
      record(name, value, document);
      return original.call(this, value, ...args);
    };
  }
  window.__qa_dom_events = events;
})();
"""


def _origin(url: str):
    try:
        parsed = urlparse(Request("GET", url).prepare().url)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower()
        port = parsed.port or {"http": 80, "https": 443}.get(scheme)
    except (UnicodeError, ValueError):
        return None
    if scheme not in {"http", "https"} or not host:
        return None
    return scheme, host, port


def build_probe_url(url: str) -> tuple[str, str, str]:
    parsed = urlparse(Request("GET", url).prepare().url)
    query_token = f"qa-q-{secrets.token_hex(8)}"
    fragment_token = f"qa-f-{secrets.token_hex(8)}"
    query = parse_qsl(parsed.query, keep_blank_values=True)
    query.append(("qa_dom", query_token))
    probe = parsed._replace(query=urlencode(query, doseq=True), fragment=f"qa_dom={fragment_token}")
    return urlunparse(probe), query_token, fragment_token


def is_allowed_browser_request(origin, url: str, method: str) -> bool:
    return method.upper() == "GET" and _origin(url) == origin


def finding_from_event(url: str, event: dict[str, Any]) -> Finding:
    return Finding(
        plugin_name="web_vulnerabilities",
        severity="high",
        title="DOM-based XSS",
        description="A URL-controlled value reached a JavaScript or HTML DOM sink.",
        url=url,
        evidence={
            "sink": str(event.get("sink", "unknown")),
            "source": str(event.get("source", "unknown")),
            "element": str(event.get("element", "document")),
        },
        remediation="Treat URL data as untrusted and use safe DOM APIs or context-aware output encoding.",
    )


def _missing_playwright_notice() -> None:
    global _missing_notice_shown
    with _missing_notice_lock:
        if not _missing_notice_shown:
            logger.warning(
                "DOM checks skipped: install Playwright and Chromium with "
                "'pip install -r requirements-dom.txt && playwright install chromium'"
            )
            _missing_notice_shown = True


def _run_dom_check(url: str, timeout_ms: int) -> list[Finding]:
    """The actual browser work. Runs ON one of the pool's dedicated browser
    threads (via the executor in scan_dom) -- never call this directly."""
    origin = _origin(url)
    if origin is None:
        return []
    try:
        browser = _ensure_thread_browser()
    except ImportError:
        _missing_playwright_notice()
        return []

    probe_url, query_token, fragment_token = build_probe_url(url)
    script = DOM_PROBE_SCRIPT.replace("__QUERY_TOKEN__", query_token).replace("__FRAGMENT_TOKEN__", fragment_token)
    try:
        # A fresh context+page per URL (cheap: no new browser process) keeps cookies,
        # the route handler, and the injected probe script isolated per check --
        # only the underlying browser process itself is shared and reused.
        context = browser.new_context(
            ignore_https_errors=False,
            service_workers="block",
        )
        try:
            page = context.new_page()

            def route_handler(route):
                request = route.request
                if is_allowed_browser_request(origin, request.url, request.method):
                    route.continue_()
                else:
                    route.abort()

            context.route("**/*", route_handler)
            page.add_init_script(script)
            page.goto(probe_url, timeout=timeout_ms, wait_until="domcontentloaded")
            events = page.evaluate("window.__qa_dom_events || []")
        finally:
            context.close()
    except Exception as exc:
        logger.debug("DOM browser check skipped for %s: %s", url, exc)
        return []

    findings = []
    seen = set()
    for event in events if isinstance(events, list) else []:
        if not isinstance(event, dict):
            continue
        key = (event.get("sink"), event.get("source"), event.get("element"))
        if key not in seen:
            seen.add(key)
            findings.append(finding_from_event(url, event))
    return findings


def scan_dom(url: str, timeout_ms: int = 10000) -> list[Finding]:
    """Safe to call from any thread: the real browser work always runs on one of
    the pool's dedicated browser threads, so this just submits and waits."""
    executor = _get_browser_executor()
    future = executor.submit(_run_dom_check, url, timeout_ms)
    try:
        return future.result(timeout=timeout_ms / 1000 + 15)
    except FuturesTimeoutError:
        # The worker thread didn't finish in time and can't be cancelled once
        # running -- it may be permanently wedged. Replace the executor so later
        # calls aren't queued behind a task that will never return, instead of
        # DOM-XSS checking silently going dark for the rest of the scan.
        logger.warning("DOM browser check timed out for %s; resetting the shared "
                        "browser worker for subsequent checks.", url)
        _replace_poisoned_executor(executor)
        return []
    except Exception as exc:  # noqa: BLE001 - never let a stuck/failed check hang the scan
        logger.debug("DOM browser check failed for %s: %s", url, exc)
        return []
