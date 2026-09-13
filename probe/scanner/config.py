from typing import List, Optional, Dict, Any
from urllib.parse import urlparse


# Predefined scan profiles
SCAN_PROFILES = {
    "quick": {
        "name": "quick",
        "description": "Fast reconnaissance scan",
        "depth": 1,
        "max_urls": 20,
        "rate_limit": 0.5,
        "timeout": 10,
        "parallel_workers": 4,
        "enabled_plugins": [
            "fingerprinting",
            "security_headers",
            "tls_analysis",
        ],
    },
    "safe-active": {
        "name": "safe-active",
        "description": "Bounded active web vulnerability checks",
        "depth": 2,
        "max_urls": 50,
        "rate_limit": 1.0,
        "timeout": 30,
        "parallel_workers": 8,
        "active_scan_mode": "safe",
        "enabled_plugins": [
            "fingerprinting",
            "security_headers",
            "tls_analysis",
            "sensitive_files",
            "wordpress_scan",
            "web_vulnerabilities",
            "access_control",
            "cve_correlation",
            "api_discovery",
            "cors_check",
            "misconfiguration",
        ],
    },
    "standard": {
        "name": "standard",
        "description": "Balanced depth and speed",
        "depth": 2,
        "max_urls": 50,
        "rate_limit": 1.0,
        "timeout": 30,
        "parallel_workers": 8,
        "enabled_plugins": [
            "fingerprinting",
            "security_headers",
            "tls_analysis",
            "sensitive_files",
            "wordpress_scan",
            "web_vulnerabilities",
            "access_control",
            "auth_bypass",
            "cve_correlation",
            "api_discovery",
            "cors_check",
            "misconfiguration",
        ],
    },
    "full": {
        "name": "full",
        "description": "Comprehensive security assessment",
        "depth": 5,
        "max_urls": 500,
        "rate_limit": 2.0,
        "timeout": 60,
        "parallel_workers": 16,
        "render_js": True,
        "enabled_plugins": [
            "fingerprinting",
            "security_headers",
            "tls_analysis",
            "sensitive_files",
            "wordpress_scan",
            "web_vulnerabilities",
            "access_control",
            "auth_bypass",
            "cve_correlation",
            "api_discovery",
            "cors_check",
            "misconfiguration",
            "network_scanner",
            "infrastructure",
        ],
    },
    "infrastructure": {
        "name": "infrastructure",
        "description": "Network and infrastructure focus",
        "depth": 1,
        "max_urls": 10,
        "rate_limit": 0.2,
        "timeout": 30,
        "parallel_workers": 20,
        "enabled_plugins": [
            "network_scanner",
            "tls_analysis",
            "fingerprinting",
        ],
    },
}


class ScanConfig:
    """
    Configuration for Probe scans.
    
    Supports predefined profiles (quick, standard, full, infrastructure)
    or custom configuration.
    """
    
    def __init__(
        self,
        target_url: str,
        depth: Optional[int] = None,
        max_urls: Optional[int] = None,
        rate_limit: Optional[float] = None,
        enabled_plugins: Optional[List[str]] = None,
        output_name: Optional[str] = None,
        output_formats: Optional[List[str]] = None,
        output_dir: str = "REPORTS",
        parallel_workers: Optional[int] = None,
        profile: Optional[str] = None,
        verbose: bool = False,
        active_scan_mode: str = "safe",
        render_js: Optional[bool] = None,
        aggressive: bool = False,
        ports: Optional[str] = None,
        proxies: Optional[List[str]] = None,
        password_spray: bool = False,
        auth: Optional[Dict[str, Any]] = None,
        auth_secondary: Optional[Dict[str, Any]] = None,
        cookies: Optional[Dict[str, str]] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ):
        # Precedence for each setting: explicit argument > profile value > built-in
        # default. Passing None means "not specified", so an explicit --depth always
        # wins over a --profile, and a profile always wins over the hard default.
        profile_config = self._get_profile_config(profile)

        def _resolve(value, key, default):
            if value is not None:
                return value
            return profile_config.get(key, default)

        # Authentication / session context (see scanner.auth).
        # ``auth`` is the primary identity; ``auth_secondary`` is an optional
        # lower-or-equal privilege identity used for two-identity IDOR checks.
        self.auth = auth
        self.auth_secondary = auth_secondary
        self.cookies = cookies
        self.extra_headers = extra_headers
        
        self.target_url = self._normalize_target_url(target_url)
        self.depth = _resolve(depth, "depth", 2)
        self.max_urls = _resolve(max_urls, "max_urls", 50)
        self.rate_limit = _resolve(rate_limit, "rate_limit", 1.0)
        self.parallel_workers = _resolve(parallel_workers, "parallel_workers", 8)
        # Aggressive/offensive mode: for targets you own or are authorized to hammer.
        # It always drives the headless browser (to reach the JS/SPA attack surface)
        # and raises probe budgets; the engine and active plugin read it.
        self.aggressive = bool(aggressive)
        self.render_js = True if self.aggressive else _resolve(render_js, "render_js", False)
        # Optional port scope (e.g. "3007", "80,443", "1-1000"). When set, the network
        # scanner stays on these ports instead of the top-100.
        self.ports = ports.strip() if isinstance(ports, str) and ports.strip() else None
        # Optional outbound proxies (rotated round-robin). Empty = direct connection.
        self.proxies = [str(p).strip() for p in (proxies or []) if str(p).strip()]
        # Opt-in end-of-scan credential spray (small default-creds list, off by default).
        self.password_spray = bool(password_spray)
        self.output_name = output_name
        self.output_formats = output_formats or ["json", "md", "pdf"]
        self.output_dir = output_dir
        self.verbose = verbose
        self.active_scan_mode = _resolve(
            None if active_scan_mode == "safe" else active_scan_mode, "active_scan_mode", active_scan_mode
        )
        
        # Use profile plugins or default to all
        if enabled_plugins:
            self.enabled_plugins = enabled_plugins
        elif profile:
            self.enabled_plugins = profile_config.get("enabled_plugins", [
                "fingerprinting",
                "security_headers",
                "sensitive_files",
                "wordpress_scan",
                "web_vulnerabilities",
                "access_control",
                "auth_bypass",
                "cve_correlation",
                "api_discovery",
                "cors_check",
                "misconfiguration",
                "network_scanner",
                "tls_analysis",
                "infrastructure",
            ])
        else:
            self.enabled_plugins = [
                "fingerprinting",
                "security_headers",
                "sensitive_files",
                "wordpress_scan",
                "web_vulnerabilities",
                "access_control",
                "auth_bypass",
                "cve_correlation",
                "api_discovery",
                "cors_check",
                "misconfiguration",
                "network_scanner",
                "tls_analysis",
            ]

    def _get_profile_config(self, profile: Optional[str]) -> Dict[str, Any]:
        """Get configuration for a named profile."""
        if profile and profile in SCAN_PROFILES:
            return SCAN_PROFILES[profile]
        return {}

    @staticmethod
    def list_profiles() -> Dict[str, Dict[str, Any]]:
        """Return available scan profiles."""
        return SCAN_PROFILES.copy()

    def _normalize_target_url(self, url: str) -> str:
        """Ensure targets without a scheme default to https://."""
        cleaned = url.strip()
        parsed = urlparse(cleaned)
        if not parsed.scheme:
            return f"https://{cleaned}"
        if parsed.scheme and not parsed.netloc and parsed.path:
            return f"{parsed.scheme}://{parsed.path}"
        return cleaned
