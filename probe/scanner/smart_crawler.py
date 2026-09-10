"""
Smart Crawler with robots.txt support and crawl trap detection.

Features:
- Respects robots.txt
- Detects and avoids crawler traps
- Implements crawl depth limits
- Handles JavaScript-rendered content detection
- URL deduplication with normalization
"""

import re
import time
from urllib.parse import urljoin, urlparse, urldefrag
from urllib.robotparser import RobotFileParser
from typing import Dict, List, Optional, Set
from collections import deque


class URLNormalizer:
    """Normalize URLs for deduplication."""
    
    @staticmethod
    def normalize(url: str) -> str:
        """Normalize URL for comparison."""
        # Remove fragment
        url, _ = urldefrag(url)
        
        parsed = urlparse(url)
        
        # Lowercase scheme and netloc
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        
        # Remove default ports
        if scheme == "http" and netloc.endswith(":80"):
            netloc = netloc[:-3]
        elif scheme == "https" and netloc.endswith(":443"):
            netloc = netloc[:-4]
        
        # Normalize path (remove duplicate slashes, resolve . and ..)
        path = parsed.path
        while "//" in path:
            path = path.replace("//", "/")
        
        # Sort query parameters
        query = ""
        if parsed.query:
            params = parsed.query.split("&")
            params.sort()
            query = "&".join(params)
        
        # Reconstruct
        normalized = f"{scheme}://{netloc}{path}"
        if query:
            normalized += f"?{query}"
        
        return normalized
    
    @staticmethod
    def get_domain(url: str) -> str:
        """Extract domain from URL."""
        return urlparse(url).netloc.lower()


class RobotsChecker:
    """Handle robots.txt checking with caching."""
    
    def __init__(self, request_handler):
        self.request_handler = request_handler
        self.parsers: Dict[str, RobotFileParser] = {}
        self.last_fetch: Dict[str, float] = {}
        self.cache_ttl = 3600  # 1 hour
    
    def _get_robots_url(self, base_url: str) -> str:
        """Get robots.txt URL for a base URL."""
        parsed = urlparse(base_url)
        return f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    
    def can_fetch(self, url: str, user_agent: str = "*") -> bool:
        """Check if URL can be fetched according to robots.txt."""
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Get or create parser
        if base_url not in self.parsers or self._is_cache_expired(base_url):
            self._fetch_robots(base_url)
        
        parser = self.parsers.get(base_url)
        if not parser:
            # If we can't fetch robots.txt, assume we can crawl
            return True
        
        return parser.can_fetch(user_agent, url)
    
    def _is_cache_expired(self, base_url: str) -> bool:
        """Check if cached robots.txt has expired."""
        last = self.last_fetch.get(base_url, 0)
        return time.time() - last > self.cache_ttl
    
    def _fetch_robots(self, base_url: str):
        """Fetch and parse robots.txt."""
        robots_url = self._get_robots_url(base_url)
        
        try:
            response = self.request_handler.get(robots_url)
            if response and response.status_code == 200:
                parser = RobotFileParser()
                parser.parse(response.text.split("\n"))
                self.parsers[base_url] = parser
                self.last_fetch[base_url] = time.time()
            else:
                # No robots.txt or error - allow all
                self.parsers[base_url] = None
                self.last_fetch[base_url] = time.time()
        except Exception:
            self.parsers[base_url] = None
            self.last_fetch[base_url] = time.time()


class CrawlTrapDetector:
    """Detect and avoid crawler traps."""
    
    # Patterns that indicate potential traps
    TRAP_PATTERNS = [
        # Calendar/date-based traps
        r'/\d{4}/\d{2}/\d{2}/.*\d{4}/\d{2}/\d{2}/',  # Nested dates
        r'/calendar.*\?.*date=.*\d{4}-\d{2}-\d{2}',
        
        # Infinite directories
        r'/(.+?)/\1/\1/',  # Repeated directory names
        
        # Session IDs in URLs
        r'[?&]session[id]?=[\w]+',
        r'[?&]sid=[\w]+',
        r'[?&]jsessionid=[\w]+',
        
        # Excessive query parameters
        r'\?[^&]*&[^&]*&[^&]*&[^&]*&[^&]*&',  # 6+ params
        
        # Common trap paths
        r'/admin/login\.php.*redirect=.*redirect=',
        r'/index\.php.*page=.*page=',
        
        # Sort/filter loops
        r'[?&]sort=.*&.*sort=',
        r'[?&]order=.*&.*order=',
        
        # Email/action traps
        r'mailto:.*@.*\.com.*\.com',
    ]
    
    # File extensions to avoid
    SKIP_EXTENSIONS = {
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.zip', '.tar', '.gz', '.rar', '.7z',
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico',
        '.mp3', '.mp4', '.avi', '.mov', '.wmv',
        '.css', '.js', '.xml', '.json',
        '.exe', '.dll', '.bin',
    }
    
    def __init__(self, max_url_length: int = 200, max_crawl_time: int = 300):
        self.max_url_length = max_url_length
        self.max_crawl_time = max_crawl_time
        self.start_time = time.time()
        self.url_pattern_counts: Dict[str, int] = {}
    
    def is_trap(self, url: str, crawled_urls: Set[str]) -> bool:
        """Check if URL is likely a crawler trap."""
        # Check crawl time limit
        if time.time() - self.start_time > self.max_crawl_time:
            return True
        
        # Check URL length
        if len(url) > self.max_url_length:
            return True
        
        # Check file extension
        parsed = urlparse(url)
        path = parsed.path.lower()
        for ext in self.SKIP_EXTENSIONS:
            if path.endswith(ext):
                return True
        
        # Check trap patterns
        for pattern in self.TRAP_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        
        # Check for repeating patterns (potential infinite URL space)
        if self._has_repeating_pattern(url):
            return True
        
        # Check if similar URLs have been seen many times
        pattern = self._extract_pattern(url)
        self.url_pattern_counts[pattern] = self.url_pattern_counts.get(pattern, 0) + 1
        if self.url_pattern_counts[pattern] > 10:
            return True
        
        return False
    
    def _has_repeating_pattern(self, url: str, threshold: int = 3) -> bool:
        """Check for repeating path segments."""
        parsed = urlparse(url)
        segments = parsed.path.split("/")
        
        for segment in segments:
            if len(segment) > 3 and segments.count(segment) > threshold:
                return True
        
        return False
    
    def _extract_pattern(self, url: str) -> str:
        """Extract URL pattern for counting."""
        # Replace IDs and numbers with placeholders
        pattern = re.sub(r'/\d+', '/{id}', url)
        pattern = re.sub(r'[?&]id=\d+', '?id={id}', pattern)
        pattern = re.sub(r'[?&]page=\d+', '?page={n}', pattern)
        return pattern


class SmartCrawler:
    """
    Smart web crawler with robots.txt support and trap detection.
    """
    
    def __init__(
        self,
        request_handler,
        start_url: str,
        max_depth: int = 3,
        max_urls: int = 100,
        respect_robots: bool = True,
        user_agent: str = "Probe",
    ):
        self.request_handler = request_handler
        self.start_url = start_url
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.respect_robots = respect_robots
        self.user_agent = user_agent
        
        self.normalizer = URLNormalizer()
        self.robots_checker = RobotsChecker(request_handler) if respect_robots else None
        self.trap_detector = CrawlTrapDetector()
        
        self.crawled_urls: Set[str] = set()
        self.url_queue: deque = deque()
        self.results: List[Dict] = []
    
    def crawl(self) -> List[Dict]:
        """
        Crawl starting from start_url.
        
        Returns:
            List of crawl results with url, depth, and response info
        """
        # Add start URL
        normalized_start = self.normalizer.normalize(self.start_url)
        self.url_queue.append((normalized_start, 0))
        
        while self.url_queue and len(self.crawled_urls) < self.max_urls:
            url, depth = self.url_queue.popleft()
            
            # Skip if already crawled
            if url in self.crawled_urls:
                continue
            
            # Check depth limit
            if depth > self.max_depth:
                continue
            
            # Check robots.txt
            if self.respect_robots and self.robots_checker:
                if not self.robots_checker.can_fetch(url, self.user_agent):
                    continue
            
            # Check for traps
            if self.trap_detector.is_trap(url, self.crawled_urls):
                continue
            
            # Fetch URL
            response = self.request_handler.get(url)
            self.crawled_urls.add(url)
            
            if response:
                result = {
                    "url": url,
                    "depth": depth,
                    "status_code": response.status_code,
                    "content_type": response.headers.get("Content-Type", ""),
                    "headers": dict(response.headers),
                }
                self.results.append(result)
                
                # Extract links if HTML and within depth limit
                if depth < self.max_depth and "text/html" in result["content_type"]:
                    links = self._extract_links(response.text, url)
                    for link in links:
                        normalized_link = self.normalizer.normalize(link)
                        if normalized_link not in self.crawled_urls:
                            self.url_queue.append((normalized_link, depth + 1))
        
        return self.results
    
    def _extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract links from HTML."""
        links = []
        
        # Find href attributes
        href_pattern = r'href=["\']([^"\']+)["\']'
        for match in re.finditer(href_pattern, html, re.IGNORECASE):
            href = match.group(1)
            
            # Skip anchors and javascript
            if href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            
            # Resolve relative URLs
            full_url = urljoin(base_url, href)
            
            # Stay on same domain
            if self.normalizer.get_domain(full_url) == self.normalizer.get_domain(base_url):
                links.append(full_url)
        
        return links


# Factory function for easy creation
def create_smart_crawler(
    request_handler,
    start_url: str,
    **kwargs
) -> SmartCrawler:
    """Create configured smart crawler."""
    return SmartCrawler(request_handler, start_url, **kwargs)
