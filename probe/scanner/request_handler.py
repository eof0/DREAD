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
from typing import Dict, Optional, Tuple
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
        retry_strategy = Retry(
            total=max_retries,
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
    
    def _make_request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> Optional[requests.Response]:
        """Make HTTP request with rate limiting and error handling."""
        if self.verbose:
            print(f"[VERBOSE] Request: {method} {url}")
            if kwargs.get('headers'):
                print(f"[VERBOSE]   Headers: {kwargs['headers']}")
            if kwargs.get('data'):
                print(f"[VERBOSE]   Data: {kwargs['data'][:200]}..." if len(str(kwargs['data'])) > 200 else f"[VERBOSE]   Data: {kwargs['data']}")

        self._respect_rate_limit()

        # Merge timeout if not provided
        if "timeout" not in kwargs:
            kwargs["timeout"] = self.timeout

        # Set SSL verification
        kwargs["verify"] = self.verify_ssl

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

            return response
            
        except requests.exceptions.SSLError as e:
            print(f"[!] SSL Error for {url}: {str(e)}")
            return None
            
        except requests.exceptions.ConnectionError as e:
            print(f"[!] Connection Error for {url}: {str(e)}")
            return None
            
        except requests.exceptions.Timeout as e:
            print(f"[!] Timeout for {url}: {str(e)}")
            return None
            
        except requests.exceptions.TooManyRedirects as e:
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
