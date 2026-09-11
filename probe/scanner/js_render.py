"""
Headless-browser rendering for JavaScript-driven / single-page apps.

Static HTML crawling misses everything a modern site builds at runtime: routes,
API calls, links injected by a framework. This renders a page in headless Chromium,
lets its scripts run, and returns the same-site URLs the browser actually reached
(navigations it wanted, resources it requested, and anchors in the rendered DOM).

Degrades to an empty result when Playwright/Chromium is not installed, so a scan
never fails just because the browser tooling is missing.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from urllib.parse import urlparse

logger = logging.getLogger(__name__)
_missing_notice_lock = threading.Lock()
_missing_notice_shown = False

_ASSET_SUFFIXES = (
    ".jpg", ".jpeg", ".png", ".gif", ".css", ".js", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".map", ".mp4", ".webp", ".avif",
)

# Rendering collects links from a real browser session; a page is given this long
# to settle (SPA data fetches) before we read what it reached.
DEFAULT_TIMEOUT_MS = 8000


@dataclass
class RenderResult:
    html: str = ""
    links: list[str] = field(default_factory=list)
    rendered: bool = False  # False when the browser was unavailable or failed


def _scannable(url: str) -> bool:
    return not urlparse(url).path.lower().endswith(_ASSET_SUFFIXES)


def filter_same_site(urls, allowed_netlocs) -> list[str]:
    """Deduplicated same-site, non-asset URLs (drops fragments and off-site links)."""
    out: list[str] = []
    seen: set[str] = set()
    for url in urls:
        clean = (url or "").split("#")[0]
        if not clean or clean in seen:
            continue
        if urlparse(clean).netloc in allowed_netlocs and _scannable(clean):
            seen.add(clean)
            out.append(clean)
    return out


def _warn_missing() -> None:
    global _missing_notice_shown
    with _missing_notice_lock:
        if not _missing_notice_shown:
            logger.warning(
                "JavaScript rendering skipped: install Playwright and Chromium with "
                "'pip install -r requirements-dom.txt && playwright install chromium'"
            )
            _missing_notice_shown = True


def render_page(url: str, allowed_netlocs, timeout_ms: int = DEFAULT_TIMEOUT_MS) -> RenderResult:
    """Render ``url`` and return the same-site URLs its scripts reached. Best-effort."""
    origin = urlparse(url).netloc
    if origin not in allowed_netlocs:
        return RenderResult()
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        _warn_missing()
        return RenderResult()

    requested: list[str] = []
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=False, service_workers="block")
            page = context.new_page()

            def on_request(request):
                # Record same-site requests; block navigation away from the site so a
                # rendered page can never make us scan someone else's host.
                if urlparse(request.url).netloc in allowed_netlocs:
                    requested.append(request.url)

            page.on("request", on_request)

            def route_handler(route):
                if urlparse(route.request.url).netloc in allowed_netlocs:
                    route.continue_()
                else:
                    route.abort()

            context.route("**/*", route_handler)
            try:
                page.goto(url, timeout=timeout_ms, wait_until="networkidle")
            except Exception:
                # networkidle can time out on chatty SPAs; take whatever rendered.
                pass
            html = page.content()
            hrefs = page.eval_on_selector_all(
                "a[href]", "els => els.map(e => e.href)"
            )
            context.close()
            browser.close()
    except Exception as exc:
        logger.debug("JS render skipped for %s: %s", url, exc)
        return RenderResult()

    links = filter_same_site([*requested, *hrefs], allowed_netlocs)
    return RenderResult(html=html, links=links, rendered=True)
