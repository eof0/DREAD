"""
Subdomain discovery via multiple sources.
"""

import json
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Dict, List, Set
from urllib.parse import urlsplit
import requests

DNS_BRUTEFORCE_WORKERS = 20

# crt.sh often dribbles a large response slowly, so a per-read timeout alone can
# still hang for minutes. These bound the connect, per-read, and total time.
CRTSH_CONNECT_TIMEOUT = 5
CRTSH_READ_TIMEOUT = 15
CRTSH_DEADLINE = 25.0
CRTSH_MAX_BYTES = 25_000_000


def normalize_target_hostname(raw: str) -> str:
    """
    Normalize user input (bare domain, URL, or host with path) to a bare hostname.
    Used by Scope discovery phases so cloud/IP intel match subdomain discovery.
    """
    value = (raw or "").strip().lower()
    if not value:
        return ""
    if "://" not in value:
        value = f"https://{value}"
    parsed = urlsplit(value)
    host = (parsed.hostname or "").strip().rstrip(".")
    return host


class SubdomainDiscovery:
    """Discover subdomains from multiple sources."""
    
    SOURCES = ["crtsh", "dns", "ssl", "permutations"]
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Scope/1.0 (Security Research)"
        })
    
    def discover(
        self,
        domain: str,
        progress_callback: Callable[[str, str, dict], None] | None = None,
    ) -> Dict[str, List[str]]:
        """
        Discover subdomains from all sources.
        
        Returns dict with source -> subdomain list.
        """
        domain = normalize_target_hostname(domain)
        if not domain:
            return {
                "certificate_transparency": [],
                "common_wordlist": [],
                "ssl_certificate": [],
                "all_unique": [],
            }

        all_subdomains: Set[str] = set()
        results = {}
        
        source_specs = [
            ("crtsh", "certificate_transparency", self._from_crtsh),
            ("dns_bruteforce", "common_wordlist", self._common_subdomains),
            ("ssl_certificate", "ssl_certificate", self._from_ssl_cert),
        ]

        for source_name, result_key, source_func in source_specs:
            started = time.time()
            if progress_callback:
                progress_callback("source_start", source_name, {})
            try:
                source_results = source_func(domain)
                results[result_key] = source_results
                all_subdomains.update(source_results)
                if progress_callback:
                    progress_callback(
                        "source_progress",
                        source_name,
                        {"count": len(all_subdomains)},
                    )
            except Exception as e:
                results[result_key] = [f"Error: {e}"]
            finally:
                if progress_callback:
                    progress_callback(
                        "source_done",
                        source_name,
                        {"elapsed": time.time() - started},
                    )
        
        # Deduplicated list
        results["all_unique"] = sorted(all_subdomains)
        
        return results

    def _from_crtsh(self, domain: str) -> List[str]:
        """Query crt.sh certificate transparency logs, bounded by a hard deadline.

        A per-read timeout cannot cap a slow trickle, so enforce a total time and
        size budget and skip the source rather than stall the whole scan.
        """
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        deadline = time.monotonic() + CRTSH_DEADLINE
        try:
            response = self.session.get(
                url, timeout=(CRTSH_CONNECT_TIMEOUT, CRTSH_READ_TIMEOUT), stream=True
            )
            response.raise_for_status()
            chunks: List[bytes] = []
            total = 0
            for chunk in response.iter_content(chunk_size=65536):
                if not chunk:
                    continue
                chunks.append(chunk)
                total += len(chunk)
                if total > CRTSH_MAX_BYTES or time.monotonic() > deadline:
                    response.close()
                    return []
            data = json.loads(b"".join(chunks).decode("utf-8", "replace"))
        except (requests.RequestException, ValueError):
            return []

        if not isinstance(data, list):
            return []

        subdomains: Set[str] = set()
        for entry in data:
            name = entry.get("name_value", "") if isinstance(entry, dict) else ""
            for line in name.split("\n"):
                line = line.strip().lower()
                if line.endswith(f".{domain}") or line == domain:
                    if line.startswith("*."):
                        line = line[2:]
                    if line:
                        subdomains.add(line)

        return sorted(subdomains)
    
    def _common_subdomains(self, domain: str) -> List[str]:
        """Check common subdomain prefixes."""
        common = [
            "www", "mail", "ftp", "admin", "blog", "shop", "api",
            "dev", "staging", "test", "demo", "app", "portal",
            "support", "help", "docs", "wiki", "status", "monitor",
            "cdn", "static", "assets", "media", "img", "images",
            "secure", "vpn", "remote", "ssh", "ftp", "sftp",
            "git", "github", "gitlab", "ci", "jenkins", "build",
            "db", "database", "mysql", "postgres", "redis", "mongo",
            "k8s", "kubernetes", "docker", "registry", "harbor",
            "prometheus", "grafana", "monitoring", "logs", "elk",
            "webmail", "email", "mx", "smtp", "imap", "pop",
            "ns1", "ns2", "dns", "hostmaster", "whois",
            "beta", "alpha", "preview", "new", "old", "v1", "v2",
            "autodiscover", "autoconfig", "m", "mobile", "amp",
        ]
        
        candidates = [f"{sub}.{domain}" for sub in common]
        with ThreadPoolExecutor(max_workers=DNS_BRUTEFORCE_WORKERS) as pool:
            resolvable = pool.map(self._is_resolvable, candidates)
        found = [c for c, ok in zip(candidates, resolvable, strict=True) if ok]

        return sorted(found)
    
    def _from_ssl_cert(self, domain: str) -> List[str]:
        """Extract subdomains from SSL certificate SAN."""
        subdomains: Set[str] = set()
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    sans = cert.get("subjectAltName", [])
                    for san in sans:
                        if san[0] == "DNS":
                            subdomains.add(san[1].lower())
        except Exception:
            pass
        
        return sorted(subdomains)
    
    def _is_resolvable(self, hostname: str) -> bool:
        """Check if hostname resolves."""
        try:
            socket.gethostbyname(hostname)
            return True
        except socket.gaierror:
            return False
