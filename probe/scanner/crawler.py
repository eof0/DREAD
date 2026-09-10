from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from typing import Set, List, Dict
import re


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
    def __init__(self, base_url: str, max_depth: int = 3, max_urls: int = 500, verbose: bool = False):
        self.base_url = base_url
        self.base_domain = urlparse(base_url).netloc
        self._allowed_netlocs = _same_site_netlocs(self.base_domain)
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.verbose = verbose
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
        
        return list(set(links))
    
    def crawl(self, request_handler) -> List[Dict]:
        queue = [(self.base_url, 0)]

        if self.verbose:
            print(f"[VERBOSE] Starting crawl from {self.base_url}")
            print(f"[VERBOSE] Max depth: {self.max_depth}, Max URLs: {self.max_urls}")

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
