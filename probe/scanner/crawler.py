from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from typing import Set, List, Dict
import re

# Same-site path or absolute-URL literals inside JavaScript (fetch/axios/const = "/api/..").
# Matches quoted strings that start with "/" or with the site's own origin.
_JS_PATH_RE = re.compile(r"""["'`](/[A-Za-z0-9_\-./~%]+(?:\?[A-Za-z0-9_\-.=&%]*)?)["'`]""")
_JS_URL_RE = re.compile(r"""["'`](https?://[A-Za-z0-9_\-.:]+/[A-Za-z0-9_\-./~%?=&]*)["'`]""")
# Relative paths without a leading slash but that look like routes ("user/profile?id=1").
_JS_REL_RE = re.compile(r"""["'`]([A-Za-z0-9_\-]+(?:/[A-Za-z0-9_\-]+)+(?:\?[A-Za-z0-9_\-.=&%]*)?)["'`]""")

# Common application routes that are frequently NOT linked from the landing page but
# carry real attack surface. Probed during content discovery so the plugins reach them.
COMMON_ROUTES = (
    "/login", "/signin", "/logout", "/register", "/signup", "/forgot", "/reset",
    "/redirect", "/account", "/profile", "/settings", "/admin", "/dashboard",
    "/search", "/upload", "/api", "/api/me", "/api/user", "/api/users", "/api/login",
    "/api/session", "/api/config", "/graphql", "/graphiql", "/track", "/status",
    "/health", "/debug", "/server-status", "/actuator", "/swagger", "/openapi.json",
)


def _same_site_netlocs(netloc: str) -> Set[str]:
    """
    Hostnames that should be treated as one site for crawl scope.

    Many sites serve on apex and www interchangeably (redirects). The crawler
    must follow links on both; otherwise starting at apex drops all www links
    (or the reverse).
    """
    nl = (netloc or "").strip().lower()
    if not nl:
        return set()
    if nl.startswith("["):
        return {nl}
    if nl.count(":") == 1 and nl.rsplit(":", 1)[1].isdigit():
        host_only, port = nl.rsplit(":", 1)
        port_suffix = ":" + port
    else:
        host_only, port_suffix = nl, ""
    out: Set[str] = {host_only + port_suffix}
    if host_only.startswith("www."):
        out.add(host_only[4:] + port_suffix)
    else:
        out.add("www." + host_only + port_suffix)
    return out


class Crawler:
    def __init__(self, base_url: str, max_depth: int = 3, max_urls: int = 500,
                 verbose: bool = False, render_js: bool = False, aggressive: bool = False,
                 scan_ports=None, proxies=None):
        self.base_url = base_url
        self.aggressive = aggressive
        self.scan_ports = scan_ports
        self.base_domain = urlparse(base_url).netloc
        self._allowed_netlocs = _same_site_netlocs(self.base_domain)
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.verbose = verbose
        self.render_js = render_js
        self.visited_urls = set()
        self.urls_to_scan = []
        self.captured_targets = []
        # Browser traffic uses the first configured proxy (Playwright can't rotate
        # mid-context); requests-side traffic rotates the full list in RequestHandler.
        self._proxies = [p for p in (proxies or []) if p]
        
    def is_valid_url(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.netloc not in self._allowed_netlocs:
            return False
        skip_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.ico', '.svg', '.woff', '.ttf']
        if any(url.lower().endswith(ext) for ext in skip_extensions):
            return False
        return True
    
    def extract_links(self, html: str, current_url: str) -> List[str]:
        soup = BeautifulSoup(html, 'html.parser')
        links = []

        for tag in soup.find_all(['a', 'form']):
            if tag.name == 'a':
                href = tag.get('href')
                if href:
                    absolute_url = urljoin(current_url, href)
                    absolute_url = absolute_url.split('#')[0]
                    if self.is_valid_url(absolute_url):
                        links.append(absolute_url)
            elif tag.name == 'form':
                action = tag.get('action', '')
                absolute_url = urljoin(current_url, action)
                if self.is_valid_url(absolute_url):
                    links.append(absolute_url)

        # Modern sites route through JavaScript; endpoints only ever appear as string
        # literals in inline scripts, never as <a href>. Mine them so the scanner has
        # parameters to test instead of just the landing page.
        for script in soup.find_all('script'):
            if not script.get('src') and script.string:
                links.extend(self.extract_js_endpoints(script.string, current_url))

        # Endpoints hiding outside <a>/<script>: HTML comments, non-anchor carriers
        # (<link>/<iframe>/<area>/<frame>/<embed>), data-* URLs and meta-refresh — the
        # "unlisted pages / comments in view source" surface a link-crawler misses.
        links.extend(self._mine_source_extras(soup, current_url))

        return list(set(links))

    _COMMENT_URL_RE = re.compile(r"https?://[^\s\"'<>)]+|/[A-Za-z0-9_\-./]+")
    _META_REFRESH_URL_RE = re.compile(r"url=([^;]+)", re.I)

    def _mine_source_extras(self, soup, current_url: str) -> List[str]:
        from bs4 import Comment

        found: List[str] = []

        def _add(raw: str) -> None:
            if not raw:
                return
            absolute = urljoin(current_url, raw.strip().strip('"\'')).split('#')[0]
            if self.is_valid_url(absolute):
                found.append(absolute)

        # 1. URLs/paths mentioned in HTML comments (old endpoints, debug links, TODOs).
        for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
            for match in self._COMMENT_URL_RE.findall(str(comment)):
                _add(match)

        # 2. Link-bearing tags that aren't <a>.
        for tag, attr in (("link", "href"), ("iframe", "src"), ("area", "href"),
                          ("frame", "src"), ("embed", "src")):
            for el in soup.find_all(tag):
                _add(el.get(attr) or "")

        # 3. data-* attributes carrying a path or URL.
        for el in soup.find_all(True):
            for key, value in el.attrs.items():
                if (key.startswith("data-") and isinstance(value, str)
                        and (value.startswith("/") or value.startswith("http"))):
                    _add(value)

        # 4. meta-refresh destination.
        for meta in soup.find_all("meta", attrs={"http-equiv": True}):
            if str(meta.get("http-equiv", "")).lower() == "refresh":
                match = self._META_REFRESH_URL_RE.search(meta.get("content", "") or "")
                if match:
                    _add(match.group(1))

        return found

    def extract_js_endpoints(self, js: str, source_url: str) -> List[str]:
        """Same-site endpoints referenced as string literals in a JavaScript body."""
        found: Set[str] = set()
        for match in _JS_URL_RE.findall(js):
            absolute = match.split('#')[0]
            if urlparse(absolute).netloc in self._allowed_netlocs and self._scannable(absolute):
                found.add(absolute)
        for regex in (_JS_PATH_RE, _JS_REL_RE):
            for match in regex.findall(js):
                absolute = urljoin(source_url, match).split('#')[0]
                if urlparse(absolute).netloc in self._allowed_netlocs and self._scannable(absolute):
                    found.add(absolute)
        return sorted(found)

    def _session_auth(self, request_handler):
        """Cookies + auth headers from the scan session, to carry into the browser."""
        import scanner.browser_crawler as bc

        host = urlparse(self.base_url).hostname or ""
        return bc.session_auth(request_handler, host)

    def _browser_capture(self, request_handler) -> None:
        """Drive a headless browser once, capture real requests, queue + stash them."""
        try:
            import scanner.browser_crawler as bc
        except Exception as exc:
            if self.verbose:
                print(f"[VERBOSE] Browser capture unavailable: {exc}")
            return
        captured_to_fuzz_targets = bc.captured_to_fuzz_targets
        cookies, headers = self._session_auth(request_handler)
        try:
            result = bc.crawl_interactive(
                self.base_url, self._allowed_netlocs,
                extra_headers=headers or None, cookies=cookies or None,
                proxy=bc.playwright_proxy(self._proxies[0]) if self._proxies else None)
        except Exception as exc:
            if self.verbose:
                print(f"[VERBOSE] Browser capture skipped: {exc}")
            return

        # Fuzz targets need parameters; hand every one to the active plugin via the
        # entry-point url_info so it doesn't launch a second browser.
        targets = captured_to_fuzz_targets(result.requests, self._allowed_netlocs)
        self.captured_targets = targets
        if self.urls_to_scan:
            self.urls_to_scan[0]["captured_targets"] = targets

        # Queue EVERY captured same-site GET endpoint (parameters or not) as a scannable
        # URL, so CORS and other plugins reach the real API surface — e.g. a paramless
        # /api/me that carries a CORS bug but nothing to inject.
        queued = 0
        for req in result.requests:
            if req.method.upper() != "GET":
                continue
            if urlparse(req.url).netloc not in self._allowed_netlocs:
                continue
            if bc._is_asset(req.url, req.resource_type):
                continue
            url = req.url.split("#")[0]
            if url in self.visited_urls:
                continue
            self.visited_urls.add(url)
            params = parse_qs(urlparse(url).query)
            self.urls_to_scan.append({
                "url": url,
                "params": params,
                "depth": 1,
                "render_js": False,       # already rendered; don't recurse the browser
                "aggressive": self.aggressive,
                "scan_ports": self.scan_ports,
                "captured": True,         # marks an API endpoint for CORS/other checks
            })
            queued += 1
        if self.verbose:
            print(f"[VERBOSE] Browser capture: {len(targets)} fuzz target(s), "
                  f"queued {queued} GET endpoint(s)")

    def _render_links(self, url: str) -> List[str]:
        """Same-site URLs discovered by rendering the page in a headless browser."""
        try:
            from scanner.js_render import render_page
            from scanner.browser_crawler import playwright_proxy
            proxy = playwright_proxy(self._proxies[0]) if self._proxies else None
            result = render_page(url, self._allowed_netlocs, proxy=proxy)
            if self.verbose and result.rendered:
                print(f"[VERBOSE] JS render found {len(result.links)} links on {url}")
            return [u for u in result.links if self.is_valid_url(u)]
        except Exception as exc:
            if self.verbose:
                print(f"[VERBOSE] JS render skipped for {url}: {exc}")
            return []

    def _scannable(self, url: str) -> bool:
        """A URL worth queueing: same-site and not a static asset."""
        skip = ('.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.ico', '.svg',
                '.woff', '.woff2', '.ttf', '.map')
        path = urlparse(url).path.lower()
        return not path.endswith(skip)

    def seed_urls(self, request_handler) -> List[str]:
        """Same-site URLs advertised by robots.txt and sitemap.xml, before crawling starts."""
        parsed = urlparse(self.base_url)
        root = f"{parsed.scheme}://{parsed.netloc}"
        seeds: List[str] = []
        seen: Set[str] = set()

        def add(url: str) -> None:
            url = (url or "").strip().split('#')[0]
            if not url or url in seen:
                return
            if urlparse(url).netloc in self._allowed_netlocs and self._scannable(url):
                seen.add(url)
                seeds.append(url)

        sitemap_urls = [f"{root}/sitemap.xml"]
        robots = request_handler.get(f"{root}/robots.txt")
        if robots is not None and getattr(robots, "status_code", 0) == 200:
            for line in (robots.text or "").splitlines():
                key, _, value = line.partition(":")
                key = key.strip().lower()
                value = value.strip()
                if key == "sitemap" and value:
                    sitemap_urls.append(value)
                elif key in ("disallow", "allow") and value and value != "/":
                    add(urljoin(root + "/", value.lstrip("/")))

        self._collect_sitemaps(sitemap_urls, request_handler, add, seen)

        # Content discovery: probe a curated list of common app routes that are often
        # NOT linked from the homepage (login, redirect, API, admin). Queue the ones
        # that actually exist so the plugins reach them — an unlinked /redirect or
        # /api/me is invisible to a link-crawler otherwise. Skipped when the server is
        # a catch-all (an SPA router that 200s every path), where route-probing is noise.
        if not self._server_is_catch_all(request_handler, root):
            candidates = [f"{root}{p}" for p in COMMON_ROUTES if f"{root}{p}" not in seen]
            for url, status in self._probe_route_existence(request_handler, candidates):
                # A real route answers 2xx/3xx, or 401/403 (exists but gated). 404/410
                # mean absent; 5xx/400 don't confirm a distinct route, so don't queue
                # them as phantom noise.
                if 200 <= status < 400 or status in (401, 403):
                    add(url)
        return seeds

    def _probe_route_existence(self, request_handler, urls):
        """Yield (url, status) for each candidate route.

        In offensive/aggressive mode against a real session, fan the existence probes
        out concurrently through the Go/Python HTTP fast-core (the request-heavy hot
        path). Otherwise — and always in tests, whose fake handlers have no ``session``
        — fall back to the polite, rate-limited sequential handler.
        """
        session = getattr(request_handler, "session", None)
        if (self.aggressive and session is not None
                and hasattr(session, "cookies") and hasattr(session, "headers")):
            try:
                from scanner.engines.http import bulk_get

                cookies = {c.name: c.value for c in session.cookies}
                keep = ("user-agent", "accept", "accept-language", "authorization",
                        "x-api-key", "x-auth-token", "x-csrf-token")
                headers = {k: v for k, v in session.headers.items() if k.lower() in keep}
                proxy = self._proxies[0] if self._proxies else None
                insecure = not getattr(request_handler, "verify_ssl", True)
                for r in bulk_get(list(urls), headers=headers, cookies=cookies,
                                  proxy=proxy, allow_redirects=False, insecure=insecure,
                                  timeout_ms=6000):
                    yield r["url"], r.get("status", 0)
                return
            except Exception as exc:  # noqa: BLE001 - never fail the crawl over the fast path
                if self.verbose:
                    print(f"[VERBOSE] HTTP fast-core unavailable, using sequential: {exc}")

        for url in urls:
            resp = request_handler.get(url, allow_redirects=False)
            yield url, (getattr(resp, "status_code", 0) if resp is not None else 0)

    def _server_is_catch_all(self, request_handler, root: str) -> bool:
        """True if a random, almost-certainly-absent path does NOT 404 — an SPA router
        or wildcard handler, where probing common routes just yields false positives."""
        import secrets

        probe = f"{root}/qa-nope-{secrets.token_hex(8)}"
        resp = request_handler.get(probe, allow_redirects=False)
        status = getattr(resp, "status_code", 404) if resp is not None else 404
        return resp is not None and status not in (404, 410)

    def _collect_sitemaps(self, sitemap_urls, request_handler, add, seen, _depth=0) -> None:
        if _depth > 3:  # guard against sitemap-index loops
            return
        for sm in sitemap_urls:
            if sm in seen:
                continue
            seen.add(sm)
            resp = request_handler.get(sm)
            if resp is None or getattr(resp, "status_code", 0) != 200:
                continue
            # html.parser (not "xml") so we don't depend on lxml; it still finds <loc>.
            text = resp.text or ""
            soup = BeautifulSoup(text, "html.parser")
            locs = [loc.get_text(strip=True) for loc in soup.find_all("loc")]
            if "<sitemapindex" in text.lower():
                self._collect_sitemaps(locs, request_handler, add, seen, _depth + 1)
            else:
                for loc in locs:
                    add(loc)
    
    def crawl(self, request_handler, cancel_check=None) -> List[Dict]:
        queue = [(self.base_url, 0)]
        _cancelled = cancel_check or (lambda: False)

        if self.verbose:
            print(f"[VERBOSE] Starting crawl from {self.base_url}")
            print(f"[VERBOSE] Max depth: {self.max_depth}, Max URLs: {self.max_urls}")

        # Seed the queue from robots.txt / sitemap.xml so we reach pages that aren't
        # linked from the landing page (common on marketing sites and SPAs).
        try:
            for seed in self.seed_urls(request_handler):
                queue.append((seed, 1))
            if self.verbose:
                print(f"[VERBOSE] Seeded {len(queue) - 1} URLs from robots/sitemap")
        except Exception as exc:  # seeding is best-effort; never fail the crawl over it
            if self.verbose:
                print(f"[VERBOSE] Seeding skipped: {exc}")

        while queue and len(self.visited_urls) < self.max_urls:
            if _cancelled():
                print("[*] Crawl stopped by operator.")
                break
            url, depth = queue.pop(0)

            if url in self.visited_urls or depth > self.max_depth:
                if self.verbose and url in self.visited_urls:
                    print(f"[VERBOSE] Skipping already visited: {url}")
                continue

            print(f"[*] Crawling: {url} (depth: {depth})")
            self.visited_urls.add(url)

            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            url_info = {
                'url': url,
                'params': params,
                'depth': depth,
                # Signals the active plugin to also drive a headless browser and fuzz
                # the real fetch/XHR the app makes (entry point only).
                'render_js': self.render_js,
                'aggressive': self.aggressive,
                'scan_ports': self.scan_ports,
            }
            self.urls_to_scan.append(url_info)

            response = request_handler.get(url)
            url_info['response'] = response
            if response is not None and response.status_code == 200:
                content_type = response.headers.get('Content-Type', '')
                if self.verbose:
                    print(f"[VERBOSE] Response: {response.status_code}, Content-Type: {content_type}")
                if 'text/html' in content_type:
                    new_links = self.extract_links(response.text, url)
                    if self.render_js:
                        new_links = list(set(new_links) | set(self._render_links(url)))
                    if self.verbose:
                        print(f"[VERBOSE] Found {len(new_links)} new links on {url}")
                        for link in new_links[:5]:
                            print(f"[VERBOSE]   - {link}")
                        if len(new_links) > 5:
                            print(f"[VERBOSE]   ... and {len(new_links) - 5} more")
                    for link in new_links:
                        if link not in self.visited_urls:
                            queue.append((link, depth + 1))
            else:
                if self.verbose:
                    status = response.status_code if response else "No response"
                    print(f"[VERBOSE] Bad response from {url}: {status}")

        # One browser-driven pass at the entry point: interact like a user, capture
        # the real fetch/XHR, then (a) queue the captured API endpoints so every plugin
        # (CORS, etc.) sees them, and (b) hand the captured fuzz targets to the active
        # plugin so it doesn't launch a second browser.
        if self.render_js and not _cancelled():
            self._browser_capture(request_handler)

        print(f"[+] Crawling complete. Found {len(self.urls_to_scan)} URLs")
        if self.verbose:
            print(f"[VERBOSE] URLs to scan:")
            for u in self.urls_to_scan[:10]:
                print(f"[VERBOSE]   - {u['url']} (depth: {u['depth']})")
            if len(self.urls_to_scan) > 10:
                print(f"[VERBOSE]   ... and {len(self.urls_to_scan) - 10} more")
        return self.urls_to_scan
