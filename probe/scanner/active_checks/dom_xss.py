"""Bounded browser checks for JavaScript-driven DOM XSS."""

import logging
import secrets
import threading
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from plugins.base_plugin import Finding
from requests import Request

logger = logging.getLogger(__name__)
_missing_notice_lock = threading.Lock()
_missing_notice_shown = False

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
  window.__dread_dom_events = events;
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
    query_token = f"dread-q-{secrets.token_hex(8)}"
    fragment_token = f"dread-f-{secrets.token_hex(8)}"
    query = parse_qsl(parsed.query, keep_blank_values=True)
    query.append(("dread_dom", query_token))
    probe = parsed._replace(query=urlencode(query, doseq=True), fragment=f"dread_dom={fragment_token}")
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


def scan_dom(url: str, timeout_ms: int = 10000) -> list[Finding]:
    origin = _origin(url)
    if origin is None:
        return []
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        global _missing_notice_shown
        with _missing_notice_lock:
            if not _missing_notice_shown:
                logger.warning(
                    "DOM checks skipped: install Playwright and Chromium with "
                    "'pip install -r requirements-dom.txt && playwright install chromium'"
                )
                _missing_notice_shown = True
        return []

    probe_url, query_token, fragment_token = build_probe_url(url)
    script = DOM_PROBE_SCRIPT.replace("__QUERY_TOKEN__", query_token).replace("__FRAGMENT_TOKEN__", fragment_token)
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context(
                ignore_https_errors=False,
                service_workers="block",
            )
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
            events = page.evaluate("window.__dread_dom_events || []")
            context.close()
            browser.close()
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
