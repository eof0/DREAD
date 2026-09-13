"""
Enhanced Request Handler

Features:
- Configurable retry logic with exponential backoff
- Connection pooling and limits
- Smart rate limiting
- Authentication support (cookies, tokens, basic auth)
- SSL/TLS configuration
"""

import requests
import time
import random
import threading
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional, Tuple
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# Header names that must never survive a redirect to a different host, on top of
# any operator-supplied ``-H`` headers (which may themselves be API keys).
_ALWAYS_SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-api-key",
    "x-api-token",
    "x-apikey",
    "api-key",
    "apikey",
    "x-auth-token",
    "auth-token",
    "x-access-token",
    "x-csrf-token",
    "x-xsrf-token",
    "x-session-token",
}


class _RedirectSafeSession(requests.Session):
    """
    A session that strips credentials when a redirect crosses to another host.

    ``requests`` already drops ``Authorization`` on a hostname change, but not
    the cookie jar (session cookies are stored domain-less and are otherwise
    sent everywhere) or arbitrary secret headers. A scan target that returns a
    cross-host 3xx could otherwise exfiltrate the operator's session cookie or
    API keys to an attacker-controlled URL.
    """

    def __init__(self, sensitive_headers=None):
        super().__init__()
        self._sensitive_headers = _ALWAYS_SENSITIVE_HEADERS | {
            str(name).lower() for name in (sensitive_headers or ())
        }

    def rebuild_auth(self, prepared_request, response):
        super().rebuild_auth(prepared_request, response)
        try:
            source_host = urlparse(response.request.url).hostname
            target_host = urlparse(prepared_request.url).hostname
        except ValueError:
            source_host = target_host = None

        if source_host and target_host and source_host != target_host:
            headers = prepared_request.headers
            for name in list(headers.keys()):
                if name.lower() in self._sensitive_headers:
                    del headers[name]
            if getattr(prepared_request, "_cookies", None) is not None:
                prepared_request._cookies.clear()
                prepared_request.prepare_cookies(prepared_request._cookies)


class RequestHandler:
    """
    Enhanced HTTP request handler with retry logic, connection pooling,
    authentication support, and smart rate limiting.
    """
    
    def __init__(
        self,
        rate_limit: int = 10,
        timeout: int = 10,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
        pool_connections: int = 10,
        pool_maxsize: int = 10,
        auth: Optional[Dict] = None,
        cookies: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        verify_ssl: bool = True,
        verbose: bool = False,
        proxies: Optional[List[str]] = None,
        max_host_failures: int = 4,
        cache_enabled: bool = True,
    ):
        """
        Initialize request handler.

        Args:
            rate_limit: Maximum requests per second
            timeout: Request timeout in seconds
            max_retries: Maximum number of retries for failed requests
            backoff_factor: Backoff factor for retries (exponential)
            pool_connections: Number of connection pools to cache
            pool_maxsize: Maximum connections to save in pool
            auth: Authentication dict with 'type' (basic/bearer/cookie) and 'credentials'
            cookies: Dictionary of cookies to include with requests
            headers: Additional headers to include with all requests
            verify_ssl: Whether to verify SSL certificates
            verbose: Enable verbose request/response logging
        """
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        self.last_request_time = 0
        self._rate_limit_lock = threading.Lock()

        # Optional proxy rotation (round-robin, per request). Empty = no proxy.
        self._proxies = [p.strip() for p in (proxies or []) if str(p).strip()]
        self._proxy_idx = 0
        self._proxy_lock = threading.Lock()

        # Dead-host circuit breaker: after this many consecutive connect/DNS/timeout
        # failures for a host, mark it down and stop scanning it (no point testing an
        # offline subdomain). A success resets the host's counter.
        self._max_host_failures = max(1, int(max_host_failures))
        self._host_failures: Dict[str, int] = {}
        self._down_hosts: set = set()
        self._failure_lock = threading.Lock()

        # Per-scan GET response cache — collapses the many duplicate page fetches
        # (crawl + every plugin re-requesting the same URL) into one round-trip.
        self._cache_enabled = bool(cache_enabled)
        self._cache: Dict[tuple, requests.Response] = {}
        self._cache_lock = threading.Lock()
        self._cache_max = 4096

        # Hard abort: when the operator quits the scan, every subsequent request
        # returns None immediately so the crawl and all plugins wind down fast.
        self._aborted = threading.Event()

        # Create session with connection pooling. The redirect-safe session
        # drops the cookie jar and any operator-supplied secret headers when a
        # redirect crosses to a different host.
        self.session = _RedirectSafeSession(
            sensitive_headers=list((headers or {}).keys())
        )
        
        # Configure retry strategy. A 500 is often the SIGNAL for a security scanner
        # (error-based SQLi, stack traces), so we must not retry it away or raise on it
        # — retry only transient infrastructure errors, and always hand back the final
        # response so plugins can inspect the error body.
        # connect=1: fail fast on a dead host (DNS/refused) instead of retrying it 3x —
        # the circuit breaker then skips it entirely. Status retries stay at max_retries.
        retry_strategy = Retry(
            total=max_retries,
            connect=1,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"],
            raise_on_status=False,
        )
        
        # Configure connection adapter with pooling
        adapter = HTTPAdapter(
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
            max_retries=retry_strategy,
        )
        
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set default headers
        default_headers = {
            # A realistic browser UA; the old "Security Scanner" string was an instant
            # WAF block, hiding real findings behind a 403.
            'User-Agent': (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                '(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
            ),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
        }
        
        # Add custom headers
        if headers:
            default_headers.update(headers)
        
        self.session.headers.update(default_headers)
        
        # Set up authentication
        self._setup_authentication(auth)
        
        # Set cookies
        if cookies:
            self.session.cookies.update(cookies)
    
    def _setup_authentication(self, auth: Optional[Dict]):
        """Configure authentication based on type."""
        if not auth:
            return
        
        auth_type = auth.get("type", "").lower()
        credentials = auth.get("credentials", {})
        
        if auth_type == "basic":
            username = credentials.get("username", "")
            password = credentials.get("password", "")
            self.session.auth = (username, password)
        
        elif auth_type == "bearer":
            token = credentials.get("token", "")
            self.session.headers["Authorization"] = f"Bearer {token}"
        
        elif auth_type == "api_key":
            key = credentials.get("key", "")
            header_name = credentials.get("header", "X-API-Key")
            self.session.headers[header_name] = key
        
        elif auth_type == "cookie":
            # Cookies are handled separately
            pass
    
    def _respect_rate_limit(self):
        """Implement rate limiting with jitter."""
        with self._rate_limit_lock:
            if self.rate_limit > 0:
                time_since_last = time.time() - self.last_request_time
                min_interval = 1.0 / self.rate_limit
                jitter = min_interval * 0.1 * (2 * random.random() - 1)
                min_interval_with_jitter = min_interval + jitter

                if time_since_last < min_interval_with_jitter:
                    time.sleep(min_interval_with_jitter - time_since_last)

            self.last_request_time = time.time()
    
    def abort(self) -> None:
        """Stop all further network activity (operator quit) — every request returns None."""
        self._aborted.set()

    @property
    def aborted(self) -> bool:
        return self._aborted.is_set()

    def is_host_down(self, host: str) -> bool:
        """True once a host has crossed the consecutive-failure threshold."""
        return host in self._down_hosts

    @staticmethod
    def _host_of(url: str) -> str:
        try:
            return (urlparse(url).hostname or "").lower()
        except ValueError:
            return ""

    def _next_proxy(self) -> Optional[Dict[str, str]]:
        """Round-robin the configured proxy list; None when no proxies are set."""
        if not self._proxies:
            return None
        with self._proxy_lock:
            proxy = self._proxies[self._proxy_idx % len(self._proxies)]
            self._proxy_idx += 1
        return {"http": proxy, "https": proxy}

    @staticmethod
    def _cache_key(method: str, url: str, kwargs: dict):
        """Key a cacheable GET by url + params + per-request headers + redirect policy.

        Headers matter because cors_check sends a distinct Origin on the same URL and
        must get its own request, not the plain-fetch cache entry.
        """
        params = kwargs.get("params")
        if isinstance(params, dict):
            params_key = tuple(sorted((str(k), str(v)) for k, v in params.items()))
        elif params:
            params_key = tuple((str(k), str(v)) for k, v in params)
        else:
            params_key = ()
        headers = kwargs.get("headers") or {}
        headers_key = tuple(sorted((str(k).lower(), str(v)) for k, v in headers.items()))
        return (method, url, params_key, headers_key, bool(kwargs.get("allow_redirects", True)))

    def _record_failure(self, host: str) -> None:
        if not host:
            return
        with self._failure_lock:
            count = self._host_failures.get(host, 0) + 1
            self._host_failures[host] = count
            newly_down = count >= self._max_host_failures and host not in self._down_hosts
            if newly_down:
                self._down_hosts.add(host)
        if newly_down:
            print(f"[!] {host} appears offline after {count} failed requests — "
                  "skipping further scanning of this host.")

    def _record_success(self, host: str) -> None:
        if host and self._host_failures.get(host):
            with self._failure_lock:
                self._host_failures[host] = 0

    def _make_request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> Optional[requests.Response]:
        """Make HTTP request with caching, a dead-host breaker, proxy rotation, and
        rate limiting."""
        no_cache = kwargs.pop("no_cache", False)

        # Operator aborted the scan: stop everything immediately.
        if self._aborted.is_set():
            return None

        host = self._host_of(url)

        # Circuit breaker: never touch a host already judged down.
        if host and host in self._down_hosts:
            return None

        # Per-scan GET cache (safe: GET is idempotent). Injection GETs carry unique
        # mutated params -> unique keys, so they never collide with a baseline fetch.
        cache_key = None
        if self._cache_enabled and method == "GET" and not no_cache:
            cache_key = self._cache_key(method, url, kwargs)
            with self._cache_lock:
                cached = self._cache.get(cache_key)
            if cached is not None:
                return cached

        if self.verbose:
            print(f"[VERBOSE] Request: {method} {url}")
            if kwargs.get('headers'):
                print(f"[VERBOSE]   Headers: {kwargs['headers']}")
            if kwargs.get('data'):
                _data_str = str(kwargs['data'])
                print(f"[VERBOSE]   Data: {_data_str[:200]}..." if len(_data_str) > 200 else f"[VERBOSE]   Data: {_data_str}")

        self._respect_rate_limit()

        if "timeout" not in kwargs:
            kwargs["timeout"] = self.timeout
        kwargs["verify"] = self.verify_ssl
        if self._proxies and "proxies" not in kwargs:
            kwargs["proxies"] = self._next_proxy()

        try:
            start_time = time.time()
            response = self.session.request(method, url, **kwargs)
            elapsed = time.time() - start_time

            if self.verbose:
                print(f"[VERBOSE] Response: {response.status_code} in {elapsed:.2f}s")
                print(f"[VERBOSE]   Content-Length: {response.headers.get('Content-Length', 'unknown')}")
                print(f"[VERBOSE]   Content-Type: {response.headers.get('Content-Type', 'unknown')}")
                if response.headers.get('Server'):
                    print(f"[VERBOSE]   Server: {response.headers.get('Server')}")

            self._record_success(host)
            if cache_key is not None:
                with self._cache_lock:
                    if len(self._cache) < self._cache_max:
                        self._cache[cache_key] = response
            return response

        except requests.exceptions.SSLError as e:
            print(f"[!] SSL Error for {url}: {str(e)}")
            self._record_failure(host)
            return None

        except requests.exceptions.ConnectionError as e:
            print(f"[!] Connection Error for {url}: {str(e)}")
            self._record_failure(host)
            return None

        except requests.exceptions.Timeout as e:
            print(f"[!] Timeout for {url}: {str(e)}")
            self._record_failure(host)
            return None

        except requests.exceptions.TooManyRedirects as e:
            # A working host that over-redirects is not "down" — don't count it.
            print(f"[!] Too many redirects for {url}: {str(e)}")
            return None

        except requests.exceptions.RequestException as e:
            print(f"[!] Request failed for {url}: {str(e)}")
            return None
    
    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make GET request."""
        return self._make_request("GET", url, **kwargs)
    
    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make POST request."""
        return self._make_request("POST", url, **kwargs)
    
    def head(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make HEAD request."""
        return self._make_request("HEAD", url, **kwargs)
    
    def options(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make OPTIONS request."""
        return self._make_request("OPTIONS", url, **kwargs)
    
    def put(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make PUT request."""
        return self._make_request("PUT", url, **kwargs)
    
    def delete(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make DELETE request."""
        return self._make_request("DELETE", url, **kwargs)
    
    def close(self):
        """Close session and release connections."""
        self.session.close()
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


def create_authenticated_handler(
    target_url: str,
    auth_type: str,
    credentials: Dict,
    **kwargs
) -> RequestHandler:
    """
    Factory function to create authenticated request handler.
    
    Example:
        # Basic auth
        handler = create_authenticated_handler(
            "https://example.com",
            "basic",
            {"username": "admin", "password": "secret"}
        )
        
        # Bearer token
        handler = create_authenticated_handler(
            "https://api.example.com",
            "bearer",
            {"token": "eyJ0eXAiOiJKV1QiLCJhbGc..."}
        )
    """
    auth_config = {
        "type": auth_type,
        "credentials": credentials,
    }
    
    return RequestHandler(auth=auth_config, **kwargs)
