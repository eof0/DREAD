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
            "cve_correlation",
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
        "enabled_plugins": [
            "fingerprinting",
            "security_headers",
            "tls_analysis",
            "sensitive_files",
            "wordpress_scan",
            "web_vulnerabilities",
            "access_control",
            "cve_correlation",
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
        depth: int = 2,
        max_urls: int = 50,
        rate_limit: float = 1.0,
        enabled_plugins: Optional[List[str]] = None,
        output_name: Optional[str] = None,
        output_formats: Optional[List[str]] = None,
        output_dir: str = "REPORTS",
        parallel_workers: int = 8,
        profile: Optional[str] = None,
        verbose: bool = False,
        active_scan_mode: str = "safe",
        auth: Optional[Dict[str, Any]] = None,
        auth_secondary: Optional[Dict[str, Any]] = None,
        cookies: Optional[Dict[str, str]] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ):
        # Apply profile settings first, then override with explicit parameters
        profile_config = self._get_profile_config(profile)

        # Authentication / session context (see scanner.auth).
        # ``auth`` is the primary identity; ``auth_secondary`` is an optional
        # lower-or-equal privilege identity used for two-identity IDOR checks.
        self.auth = auth
        self.auth_secondary = auth_secondary
        self.cookies = cookies
        self.extra_headers = extra_headers
        
        self.target_url = self._normalize_target_url(target_url)
        self.depth = depth if profile is None else profile_config.get("depth", depth)
        self.max_urls = max_urls if profile is None else profile_config.get("max_urls", max_urls)
        self.rate_limit = rate_limit if profile is None else profile_config.get("rate_limit", rate_limit)
        self.parallel_workers = parallel_workers if profile is None else profile_config.get("parallel_workers", parallel_workers)
        self.output_name = output_name
        self.output_formats = output_formats or ["json", "md", "pdf"]
        self.output_dir = output_dir
        self.verbose = verbose
        self.active_scan_mode = (
            active_scan_mode if profile is None else profile_config.get("active_scan_mode", active_scan_mode)
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
                "cve_correlation",
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
                "cve_correlation",
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
