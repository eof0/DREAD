"""
Browser-driven crawler: act like a user, capture the real API, feed it to the fuzzer.

Static HTML crawling misses everything a JavaScript app does at runtime. This drives
the page in a headless browser — filling and submitting forms, clicking, following
SPA routes — and records every fetch/XHR the app makes. Those captured requests are
the *real* attack surface (JSON APIs, authenticated calls), which `captured_to_fuzz_targets`
converts into the same target shape the active checks already understand.

Pure conversion/dedup is testable; the Playwright driver is the only I/O and degrades
to nothing when Playwright/Chromium is unavailable.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import parse_qsl, urlparse, urlunparse

logger = logging.getLogger(__name__)

_ASSET_SUFFIXES = (
    ".jpg", ".jpeg", ".png", ".gif", ".css", ".js", ".ico", ".svg", ".woff",
    ".woff2", ".ttf", ".map", ".mp4", ".webp", ".avif", ".mp3", ".wasm",
)
_ASSET_RESOURCE_TYPES = {"image", "stylesheet", "font", "media", "script", "manifest"}
_FUZZABLE_RESOURCE_TYPES = {"xhr", "fetch", "document", "form", "other"}

# Auth headers worth carrying from the scan session into the browser so authed flows
# are reached. Single source of truth — the crawler and the plugin both use this.
_SESSION_AUTH_HEADERS = ("authorization", "x-api-key", "x-auth-token", "x-csrf-token")


def session_auth(request_handler, host: str):
    """Extract (cookies, auth-headers) from a scan session to hand to the browser.

    Shared by the crawler's one-shot capture and the web-vuln plugin's fallback
    capture so the cookie shape and the auth-header allowlist can't drift apart.
    """
    cookies, headers = [], {}
    try:
        for c in request_handler.session.cookies:
            cookies.append({"name": c.name, "value": c.value,
                            "domain": c.domain or host, "path": c.path or "/"})
    except Exception:  # noqa: BLE001
        cookies = []
    try:
        for k, v in request_handler.session.headers.items():
            if k.lower() in _SESSION_AUTH_HEADERS:
                headers[k] = v
    except Exception:  # noqa: BLE001
        headers = {}
    return cookies, headers


@dataclass(frozen=True)
class CapturedRequest:
    method: str
    url: str
    post_data: Optional[str] = None
    content_type: Optional[str] = None
    resource_type: str = "other"


@dataclass
class BrowserResult:
    html: str = ""
    links: List[str] = field(default_factory=list)
    requests: List[CapturedRequest] = field(default_factory=list)
    rendered: bool = False


def _is_asset(url: str, resource_type: str) -> bool:
    if resource_type in _ASSET_RESOURCE_TYPES:
        return True
    return urlparse(url).path.lower().endswith(_ASSET_SUFFIXES)


def _parse_body(post_data: Optional[str], content_type: Optional[str]):
    """Return (location, params) for a request body, or (None, None) if not fuzzable."""
    if not post_data:
        return None, None
    ctype = (content_type or "").lower()
    if "json" in ctype or post_data.strip()[:1] in "{[":
        try:
            data = json.loads(post_data)
        except (ValueError, TypeError):
            return None, None
        if isinstance(data, dict) and data:
            # Fuzz top-level string/number fields (mutated one at a time downstream).
            return "json", {k: v for k, v in data.items() if isinstance(v, (str, int, float, bool))}
        return None, None
    # urlencoded form body
    pairs = parse_qsl(post_data, keep_blank_values=True)
    return ("form", dict(pairs)) if pairs else (None, None)


def _shape(request: CapturedRequest) -> tuple:
    """A signature that ignores concrete values, so ?id=1 and ?id=2 count as one target."""
    parsed = urlparse(request.url)
    endpoint = urlunparse(parsed._replace(query="", fragment=""))
    query_keys = tuple(sorted(k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)))
    location, params = _parse_body(request.post_data, request.content_type)
    body_keys = tuple(sorted(params)) if params else ()
    return (request.method.upper(), endpoint, query_keys, location, body_keys)


def dedupe_requests(requests: List[CapturedRequest]) -> List[CapturedRequest]:
    seen: set = set()
    out: List[CapturedRequest] = []
    for req in requests:
        key = _shape(req)
        if key not in seen:
            seen.add(key)
            out.append(req)
    return out


def captured_to_fuzz_targets(requests: List[CapturedRequest], allowed_netlocs) -> List[Dict]:
    """Turn captured same-site requests that carry parameters into active-scan targets."""
    targets: List[Dict] = []
    seen: set = set()
    for req in requests:
        if urlparse(req.url).netloc not in allowed_netlocs:
            continue
        if req.resource_type not in _FUZZABLE_RESOURCE_TYPES or _is_asset(req.url, req.resource_type):
            continue
        parsed = urlparse(req.url)
        method = req.method.upper()

        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        location, body_params = _parse_body(req.post_data, req.content_type)

        if body_params:
            endpoint = urlunparse(parsed._replace(fragment=""))
            params, loc = body_params, location
        elif query:
            endpoint = urlunparse(parsed._replace(query="", fragment=""))
            params, loc = query, "query"
        else:
            continue  # nothing to fuzz

        key = (method, endpoint, loc, tuple(sorted(params)))
        if key in seen:
            continue
        seen.add(key)
        targets.append({"endpoint": endpoint, "params": params, "method": method, "location": loc})
    return targets


# Type-appropriate values so a form actually submits (empty required fields block it).
_FILL_RULES = (
    (("email", "e-mail"), "qa.probe@example.com"),
    (("password", "passwd", "pwd"), "QaProbe!1"),
    (("url", "website", "link", "site"), "https://example.com"),
    (("phone", "tel", "mobile"), "5551234567"),
    (("age", "number", "qty", "quantity", "amount", "count", "zip", "postal"), "42"),
    (("date", "dob", "birth"), "2000-01-01"),
    (("first", "fname", "name", "user", "login"), "qaprobe"),
    (("search", "query", "q"), "qaprobe"),
)


def form_fill_value(field_name: str) -> str:
    """A plausible value for an input, chosen from its name so the form will submit."""
    low = (field_name or "").lower()
    for needles, value in _FILL_RULES:
        if any(n in low for n in needles):
            return value
    return "qaprobe"


def playwright_proxy(proxy_url: Optional[str]):
    """Convert a proxy URL to Playwright's proxy dict, or None. Shared by the browser paths."""
    if not proxy_url:
        return None
    parsed = urlparse(proxy_url)
    if not parsed.hostname:
        return None
    scheme = parsed.scheme or "http"
    server = f"{scheme}://{parsed.hostname}"
    if parsed.port:
        server += f":{parsed.port}"
    proxy = {"server": server}
    if parsed.username:
        proxy["username"] = parsed.username
    if parsed.password:
        proxy["password"] = parsed.password
    return proxy


def crawl_interactive(
    url: str,
    allowed_netlocs,
    *,
    extra_headers: Optional[Dict[str, str]] = None,
    cookies: Optional[List[Dict]] = None,
    max_actions: int = 40,
    timeout_ms: int = 12000,
    proxy: Optional[dict] = None,
) -> BrowserResult:
    """
    Render and interact with ``url`` in a headless browser, capturing same-site API
    calls. Best-effort: returns an empty result if Playwright/Chromium is unavailable.
    """
    origin = urlparse(url).netloc
    if origin not in allowed_netlocs:
        return BrowserResult()
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        logger.warning("Browser crawl skipped: install Playwright + Chromium "
                       "(pip install -r requirements-dom.txt && playwright install chromium)")
        return BrowserResult()

    captured: List[CapturedRequest] = []
    links: set = set()
    html = ""

    def _record(request) -> None:
        try:
            if urlparse(request.url).netloc not in allowed_netlocs:
                return
            headers = request.headers
            captured.append(CapturedRequest(
                method=request.method,
                url=request.url,
                post_data=request.post_data,
                content_type=headers.get("content-type"),
                resource_type=request.resource_type,
            ))
        except Exception:  # noqa: BLE001 - never let capture break the crawl
            pass

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True,
                                                 **({"proxy": proxy} if proxy else {}))
            context = browser.new_context(ignore_https_errors=True, service_workers="block",
                                          extra_http_headers=extra_headers or {})
            if cookies:
                try:
                    context.add_cookies(cookies)
                except Exception:  # noqa: BLE001
                    pass
            page = context.new_page()
            page.on("request", _record)

            def route_handler(route):
                # Keep the browser on the target site; block navigation elsewhere.
                if urlparse(route.request.url).netloc in allowed_netlocs:
                    route.continue_()
                else:
                    route.abort()

            context.route("**/*", route_handler)
            try:
                page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
            except Exception:
                pass
            _interact(page, allowed_netlocs, links, max_actions, timeout_ms)
            try:
                html = page.content()
                for href in page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)"):
                    if urlparse(href).netloc in allowed_netlocs:
                        links.add(href.split("#")[0])
            except Exception:
                pass
            context.close()
            browser.close()
    except Exception as exc:  # noqa: BLE001
        logger.debug("Browser crawl error for %s: %s", url, exc)
        return BrowserResult(html=html, links=sorted(links), requests=dedupe_requests(captured),
                             rendered=bool(captured or html))

    return BrowserResult(html=html, links=sorted(links),
                         requests=dedupe_requests(captured), rendered=True)


def _interact(page, allowed_netlocs, links: set, max_actions: int, timeout_ms: int) -> None:
    """Fill and submit forms, then click safe interactive elements, to trigger real API calls."""
    actions = 0
    # 1. Fill every form field with a plausible value, then submit each form.
    try:
        inputs = page.query_selector_all("input, textarea, select")
    except Exception:
        inputs = []
    for element in inputs:
        if actions >= max_actions:
            break
        try:
            name = (element.get_attribute("name") or element.get_attribute("id")
                    or element.get_attribute("placeholder") or "")
            tag = element.evaluate("e => e.tagName.toLowerCase()")
            itype = (element.get_attribute("type") or "text").lower()
            if itype in ("hidden", "submit", "button", "file", "image", "checkbox", "radio"):
                continue
            if tag == "select":
                element.select_option(index=1, timeout=1000)
            else:
                element.fill(form_fill_value(name), timeout=1000)
            actions += 1
        except Exception:
            continue
    try:
        for form in page.query_selector_all("form"):
            if actions >= max_actions:
                break
            try:
                form.evaluate("f => f.requestSubmit ? f.requestSubmit() : f.submit()")
                page.wait_for_timeout(300)
                actions += 1
            except Exception:
                continue
    except Exception:
        pass

    # 2. Click buttons / role=button elements (SPA actions that fire XHR/fetch).
    try:
        clickables = page.query_selector_all(
            "button, [role=button], [type=submit], a[href^='#'], a[href^='javascript']")
    except Exception:
        clickables = []
    for element in clickables:
        if actions >= max_actions:
            break
        try:
            element.click(timeout=800, no_wait_after=True)
            page.wait_for_timeout(200)
            actions += 1
        except Exception:
            continue
    try:
        page.wait_for_load_state("networkidle", timeout=3000)
    except Exception:
        pass
