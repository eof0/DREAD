from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from typing import Set, List, Dict
import re

# Same-site path or absolute-URL literals inside JavaScript (fetch/axios/const = "/api/..").
# Matches quoted strings that start with "/" or with the site's own origin.
_JS_PATH_RE = re.compile(r"""["'`](/[A-Za-z0-9_\-./~%]+(?:\?[A-Za-z0-9_\-.=&%]*)?)["'`]""")
_JS_URL_RE = re.compile(r"""["'`](https?://[A-Za-z0-9_\-.:]+/[A-Za-z0-9_\-./~%?=&]*)["'`]""")
# Relative paths without a leading slash but that look like routes ("user/profile?id=1").
_JS_REL_RE = re.compile(r"""["'`]([A-Za-z0-9_\-]+(?:/[A-Za-z0-9_\-]+)+(?:\?[A-Za-z0-9_\-.=&%]*)?)["'`]""")


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
                 verbose: bool = False, render_js: bool = False):
        self.base_url = base_url
        self.base_domain = urlparse(base_url).netloc
        self._allowed_netlocs = _same_site_netlocs(self.base_domain)
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.verbose = verbose
        self.render_js = render_js
        self.visited_urls = set()
        self.urls_to_scan = []
        
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

        return list(set(links))

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

    def _render_links(self, url: str) -> List[str]:
        """Same-site URLs discovered by rendering the page in a headless browser."""
        try:
            from scanner.js_render import render_page
            result = render_page(url, self._allowed_netlocs)
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
        return seeds

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
    
    def crawl(self, request_handler) -> List[Dict]:
        queue = [(self.base_url, 0)]

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

        print(f"[+] Crawling complete. Found {len(self.urls_to_scan)} URLs")
        if self.verbose:
            print(f"[VERBOSE] URLs to scan:")
            for u in self.urls_to_scan[:10]:
                print(f"[VERBOSE]   - {u['url']} (depth: {u['depth']})")
            if len(self.urls_to_scan) > 10:
                print(f"[VERBOSE]   ... and {len(self.urls_to_scan) - 10} more")
        return self.urls_to_scan
