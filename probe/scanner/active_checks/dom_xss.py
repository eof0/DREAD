"""Bounded browser checks for JavaScript-driven DOM XSS."""

import atexit
import logging
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor
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
# around concurrent access -- it's pinning the one shared browser to a single dedicated
# worker thread (a ThreadPoolExecutor(max_workers=1) reuses the same OS thread for
# every submitted task) and funneling every scan_dom() call through it. Callers from
# any thread just get a Future back; the browser itself only ever runs one check at a
# time, launched once and reused for the rest of the process.
_browser_lock = threading.Lock()
_browser_executor: ThreadPoolExecutor | None = None
_shared_playwright = None
_shared_browser = None


def _get_browser_executor() -> ThreadPoolExecutor:
    global _browser_executor
    with _browser_lock:
        if _browser_executor is None:
            _browser_executor = ThreadPoolExecutor(max_workers=1,
                                                    thread_name_prefix="dom-xss-browser")
            atexit.register(_shutdown_shared_browser)
        return _browser_executor


def _close_shared_browser() -> None:
    """Runs ON the browser thread (via the executor) -- never call directly."""
    global _shared_browser, _shared_playwright
    if _shared_browser is not None:
        try:
            _shared_browser.close()
        except Exception:  # noqa: BLE001 - best-effort teardown
            pass
        _shared_browser = None
    if _shared_playwright is not None:
        try:
            _shared_playwright.stop()
        except Exception:  # noqa: BLE001 - best-effort teardown
            pass
        _shared_playwright = None


def _shutdown_shared_browser() -> None:
    """Process-exit cleanup (atexit) so a lingering scan never leaks a browser."""
    global _browser_executor
    executor = _browser_executor
    if executor is None:
        return
    try:
        executor.submit(_close_shared_browser).result(timeout=5)
    except Exception:  # noqa: BLE001 - process is exiting either way
        pass
    executor.shutdown(wait=False)
    _browser_executor = None


def _ensure_shared_browser():
    """Runs ON the browser thread. Lazily launches once; reused on every later call."""
    global _shared_browser, _shared_playwright
    if _shared_browser is not None:
        return _shared_browser
    from playwright.sync_api import sync_playwright  # noqa: PLC0415 - optional dependency

    _shared_playwright = sync_playwright().start()
    _shared_browser = _shared_playwright.chromium.launch(headless=True)
    return _shared_browser

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
    """The actual browser work. Runs ON the dedicated browser thread (via the
    single-worker executor in scan_dom) -- never call this directly from elsewhere."""
    origin = _origin(url)
    if origin is None:
        return []
    try:
        browser = _ensure_shared_browser()
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
    """Safe to call from any thread: the real browser work always runs on the one
    dedicated browser thread, so this just submits and waits for the result."""
    executor = _get_browser_executor()
    future = executor.submit(_run_dom_check, url, timeout_ms)
    try:
        return future.result(timeout=timeout_ms / 1000 + 15)
    except Exception as exc:  # noqa: BLE001 - never let a stuck/failed check hang the scan
        logger.debug("DOM browser check failed for %s: %s", url, exc)
        return []
