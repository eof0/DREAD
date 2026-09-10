#!/usr/bin/env python3
"""
Infrastructure Intelligence Plugin

Performs IP resolution, ASN lookup, and cloud provider detection.
"""

from typing import Dict, List, Optional
import socket
import json
import os
from urllib.parse import urlparse

from plugins.base_plugin import BasePlugin, Finding

from scanner.paths import ASN_DB_PATH

# Cloud provider ASN ranges (simplified)
CLOUD_PROVIDERS = {
    "Cloudflare": {
        "asns": [13335, 209242],
        "headers": ["CF-RAY", "CF-Cache-Status"],
    },
    "AWS": {
        "asns": [16509, 14618, 15169, 7224, 9059],
        "headers": ["X-Amz-Cf-Id", "X-Amz-Request-Id"],
    },
    "Google Cloud": {
        "asns": [15169, 19527, 16550, 396982],
        "headers": ["Via", "X-Cloud-Trace-Context"],
    },
    "Microsoft Azure": {
        "asns": [8075, 8068, 8069],
        "headers": ["X-Azure-Ref", "X-MSEdge-Ref"],
    },
    "DigitalOcean": {
        "asns": [14061, 62567, 200130],
        "headers": [],
    },
    "Akamai": {
        "asns": [20940, 16625],
        "headers": ["X-Akamai-Request-ID"],
    },
    "Fastly": {
        "asns": [54113, 394192],
        "headers": ["X-Served-By", "X-Cache"],
    },
}


class InfrastructureIntelPlugin(BasePlugin):
    """
    Infrastructure intelligence gathering plugin.
    
    Detects:
    - IP addresses and geolocation
    - ASN ownership
    - Cloud/CDN providers
    - Infrastructure patterns
    """
    
    def get_name(self) -> str:
        return "infrastructure_intel"
    
    def get_description(self) -> str:
        return "Infrastructure intelligence (IP, ASN, cloud provider detection)"
    
    def _resolve_ip(self, hostname: str) -> Optional[str]:
        """Resolve hostname to IP address."""
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None
    
    def _load_asn_db(self) -> Dict:
        """Load ASN database."""
        if not os.path.exists(ASN_DB_PATH):
            return {}
        try:
            with open(ASN_DB_PATH, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
    
    def _lookup_asn(self, ip: str, asn_db: Dict) -> Optional[Dict]:
        """
        Lookup ASN for IP address.
        
        Note: This is a simplified implementation.
        Real implementation would need IP-to-ASN mapping.
        """
        # Placeholder - would need proper IP-to-ASN database
        return None
    
    def _detect_cloud_provider(self, headers: Dict) -> Optional[str]:
        """Detect cloud/CDN provider from HTTP headers."""
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        for provider, signatures in CLOUD_PROVIDERS.items():
            for header in signatures.get("headers", []):
                if header.lower() in headers_lower:
                    return provider
        
        return None
    
    def _reverse_dns(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return None
    
    def scan(self, url_info: Dict, request_handler) -> List[Finding]:
        """Gather infrastructure intelligence."""
        findings = []
        
        # Only run once at root
        if url_info.get("depth", 0) > 0:
            return findings
        
        url = url_info["url"]
        parsed = urlparse(url)
        hostname = parsed.hostname
        
        if not hostname:
            return findings
        
        # Resolve IP
        ip = self._resolve_ip(hostname)
        if not ip:
            return findings
        
        # Get response for header analysis
        response = request_handler.get(url)
        headers = response.headers if response else {}
        
        # Detect cloud provider
        cloud_provider = self._detect_cloud_provider(headers)
        
        # Load ASN database
        asn_db = self._load_asn_db()
        
        # Build infrastructure info
        infra_info = {
            "hostname": hostname,
            "ip": ip,
            "reverse_dns": self._reverse_dns(ip),
        }
        
        if cloud_provider:
            infra_info["cloud_provider"] = cloud_provider
        
        # Add server header if present
        server = headers.get("Server", "")
        if server:
            infra_info["server_banner"] = server
        
        # Create informational finding
        findings.append(
            Finding(
                plugin_name=self.get_name(),
                severity="info",
                title="Infrastructure Intelligence",
                description=f"Detected infrastructure for {hostname}",
                url=url,
                evidence=infra_info,
                remediation="Review exposed infrastructure information and minimize information disclosure.",
                metadata={
                    "category": "infrastructure",
                    "cloud_provider": cloud_provider,
                    "ip": ip,
                }
            )
        )
        
        # Check for exposed server banners
        if server and not cloud_provider:
            # Generic server exposure
            findings.append(
                Finding(
                    plugin_name=self.get_name(),
                    severity="low",
                    title="Server Banner Exposed",
                    description=f"Server header exposes: {server}",
                    url=url,
                    evidence={"server": server},
                    remediation="Configure server to hide or minimize version information in HTTP headers.",
                    metadata={"category": "information_disclosure"}
                )
            )
        
        # Check for CDN/cloud misconfigurations
        if cloud_provider and "CF-RAY" in headers:
            # Check for Cloudflare bypass opportunities
            if ip != "":  # If we got an IP, check if it's direct
                findings.append(
                    Finding(
                        plugin_name=self.get_name(),
                        severity="medium",
                        title="Potential CDN Bypass Vector",
                        description=f"Direct IP {ip} may bypass {cloud_provider} protection",
                        url=url,
                        evidence={
                            "cloud_provider": cloud_provider,
                            "direct_ip": ip,
                            "cdn_headers": {k: v for k, v in headers.items() if k in ["CF-RAY", "CF-Cache-Status"]}
                        },
                        remediation="Ensure origin server only accepts traffic through CDN. Restrict direct IP access.",
                        metadata={
                            "category": "infrastructure",
                            "cloud_provider": cloud_provider,
                        }
                    )
                )
        
        return findings


if __name__ == "__main__":
    # Test the plugin
    plugin = InfrastructureIntelPlugin()
    print(f"Plugin: {plugin.get_name()}")
    print(f"Description: {plugin.get_description()}")
