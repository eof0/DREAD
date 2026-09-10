"""
Network Scanner Plugin - High Performance

Uses Go/native engine for fast scanning with proper CDN detection.
"""

from typing import Dict, List, Optional
import socket
from urllib.parse import urlparse

from plugins.base_plugin import BasePlugin, Finding
from scanner.engines.network import NetworkScanner


class NetworkScannerPlugin(BasePlugin):
    """
    High-performance network scanner with CDN-aware detection.
    Uses Go or native async engine for speed.
    """

    WEB_PORTS = {80: "HTTP", 443: "HTTPS", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"}
    
    ORIGIN_PORTS = {
        21: ("FTP", "high"),
        22: ("SSH", "high"),
        23: ("Telnet", "high"),
        25: ("SMTP", "medium"),
        53: ("DNS", "low"),
        110: ("POP3", "medium"),
        143: ("IMAP", "medium"),
        3306: ("MySQL", "critical"),
        5432: ("PostgreSQL", "critical"),
        6379: ("Redis", "critical"),
        27017: ("MongoDB", "critical"),
        9200: ("Elasticsearch", "critical"),
    }

    CDN_PROVIDERS = {
        "cloudflare": "Cloudflare",
        "cloudfront": "AWS CloudFront",
        "fastly": "Fastly",
        "akamai": "Akamai",
        "incapsula": "Incapsula",
        "sucuri": "Sucuri",
    }

    # Cloudflare IP ranges
    CF_IP_RANGES = [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
        "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
        "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
        "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    ]

    def __init__(self):
        self.scanner = NetworkScanner(
            ports="top100",
            timeout_ms=2000,
            concurrency=200,
        )

    def get_name(self) -> str:
        return "network_scanner"

    def get_description(self) -> str:
        return f"High-performance network scanner ({self.scanner.engine} engine)"

    def _is_cloudflare_ip(self, ip: str) -> bool:
        """Check if IP is in Cloudflare ranges."""
        try:
            from ipaddress import ip_address, ip_network
            addr = ip_address(ip)
            for cf_range in self.CF_IP_RANGES:
                if addr in ip_network(cf_range):
                    return True
        except Exception:
            pass
        return False

    def _detect_provider(self, response_headers: Dict) -> Optional[str]:
        """Detect CDN provider from headers."""
        headers = {k.lower(): v.lower() for k, v in response_headers.items()}
        
        if "cloudflare" in headers.get("server", "") or "cf-ray" in headers:
            return "cloudflare"
        if "cloudfront" in headers.get("via", ""):
            return "cloudfront"
        if "fastly" in headers.get("via", ""):
            return "fastly"
        
        return None

    def _validate_service(self, host: str, port: int, expected_service: str) -> bool:
        """Validate service with protocol probes."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, port))
            
            if expected_service == "SSH":
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                if "SSH-" in banner:
                    return True
                    
            elif expected_service == "FTP":
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                if "220" in banner and "FTP" in banner.upper():
                    return True
                    
            elif expected_service in ["MySQL", "PostgreSQL", "Redis", "MongoDB", "Elasticsearch"]:
                banner = sock.recv(1024)
                if len(banner) > 0 and not banner.startswith(b"HTTP"):
                    return True
                    
            elif port in [80, 443, 8080, 8443]:
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                if response.startswith("HTTP/"):
                    return True
            else:
                banner = sock.recv(1024)
                if not banner.startswith(b"HTTP") and len(banner) > 0:
                    return True
                    
        except Exception:
            pass
        finally:
            sock.close()
        
        return False

    def scan(self, url_info: Dict, request_handler) -> List[Finding]:
        findings = []
        
        if url_info.get("depth", 0) > 0:
            return findings

        url = url_info["url"]
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return findings

        # Detect provider
        provider = None
        try:
            resp = request_handler.get(url)
            if resp:
                provider = self._detect_provider(resp.headers)
        except Exception:
            pass

        # Resolve IP
        try:
            ip = socket.gethostbyname(hostname)
            is_cf_ip = self._is_cloudflare_ip(ip)
        except Exception:
            ip = hostname
            is_cf_ip = False

        provider_name = self.CDN_PROVIDERS.get(provider, provider or "Unknown")
        is_cdn = is_cf_ip or provider is not None

        # Use high-performance scanner
        all_ports = self.scanner.scan(hostname)
        
        # Categorize findings
        web_ports_found = []
        origin_ports_found = []
        other_ports = []
        
        for port_info in all_ports:
            port = port_info["port"]
            
            if port in self.WEB_PORTS:
                web_ports_found.append(port_info)
            elif port in self.ORIGIN_PORTS:
                origin_ports_found.append(port_info)
            else:
                other_ports.append(port_info)

        # ============================================
        # CASE 1: Site is on CDN
        # ============================================
        if is_cdn:
            # Web ports on CDN edge are expected
            for port_info in web_ports_found:
                port = port_info["port"]
                service = self.WEB_PORTS.get(port, "Web")
                
                findings.append(
                    Finding(
                        plugin_name=self.get_name(),
                        severity="info",
                        title=f"{provider_name} {service} (port {port})",
                        description=f"{service} via {provider_name} edge infrastructure.",
                        url=f"{hostname}:{port}",
                        evidence={
                            "port": port,
                            "service": service,
                            "cdn_ip": ip,
                            "provider": provider_name,
                            "response_time_ms": port_info.get("response_time_ms", 0),
                        },
                        metadata={
                            "actual_risk": False,
                            "edge_infrastructure": True,
                            "third_party_cdn": True,
                        },
                        remediation="No action needed - expected CDN behavior.",
                    )
                )
            
            # Non-web ports on CDN IP are suspicious
            for port_info in origin_ports_found:
                port = port_info["port"]
                service, _ = self.ORIGIN_PORTS.get(port, ("Unknown", "medium"))
                
                # Validate it's actually the service
                if self._validate_service(ip, port, service):
                    findings.append(
                        Finding(
                            plugin_name=self.get_name(),
                            severity="critical",
                            title=f"ORIGIN LEAKED: {service} exposed through CDN",
                            description=f"{service} on port {port} is accessible on the CDN IP. This suggests origin exposure.",
                            url=f"{ip}:{port}",
                            evidence={
                                "port": port,
                                "service": service,
                                "cdn_ip": ip,
                                "provider": provider_name,
                                "validated": True,
                            },
                            metadata={
                                "actual_risk": True,
                                "origin_leaked": True,
                            },
                            remediation=f"Block port {port} at firewall. Only allow CDN IPs to access origin.",
                        )
                    )
            
            # Summary finding if no issues
            if not any(f.metadata.get("origin_leaked") for f in findings):
                findings.append(
                    Finding(
                        plugin_name=self.get_name(),
                        severity="info",
                        title=f"Protected by {provider_name}",
                        description=f"Site served via {provider_name}. Origin properly hidden.",
                        url=url,
                        evidence={
                            "cdn_provider": provider_name,
                            "cdn_ip": ip,
                            "origin_protected": True,
                            "open_ports": len(all_ports),
                        },
                        metadata={
                            "actual_risk": False,
                            "edge_infrastructure": True,
                        },
                        remediation="No action needed.",
                    )
                )
        
        # ============================================
        # CASE 2: Direct origin (no CDN)
        # ============================================
        else:
            for port_info in origin_ports_found:
                port = port_info["port"]
                service, severity = self.ORIGIN_PORTS.get(port, ("Unknown", "medium"))
                
                if self._validate_service(ip, port, service):
                    findings.append(
                        Finding(
                            plugin_name=self.get_name(),
                            severity=severity,
                            title=f"EXPOSED: {service} on port {port}",
                            description=f"{service} is directly accessible on origin server.",
                            url=f"{ip}:{port}",
                            evidence={
                                "port": port,
                                "service": service,
                                "validated": True,
                                "response_time_ms": port_info.get("response_time_ms", 0),
                            },
                            metadata={
                                "actual_risk": True,
                                "edge_infrastructure": False,
                            },
                            remediation=f"Block port {port} in firewall or restrict to trusted IPs.",
                        )
                    )
            
            # Web ports on direct origin
            for port_info in web_ports_found:
                port = port_info["port"]
                service = self.WEB_PORTS.get(port, "Web")
                
                findings.append(
                    Finding(
                        plugin_name=self.get_name(),
                        severity="low",
                        title=f"{service} on port {port}",
                        description=f"{service} service detected.",
                        url=f"{ip}:{port}",
                        evidence={
                            "port": port,
                            "service": service,
                        },
                        metadata={
                            "actual_risk": False,
                        },
                        remediation="Ensure service is up-to-date and properly configured.",
                    )
                )
            
            # Other interesting ports
            for port_info in other_ports[:5]:  # Limit to top 5
                port = port_info["port"]
                findings.append(
                    Finding(
                        plugin_name=self.get_name(),
                        severity="info",
                        title=f"Open port {port}",
                        description=f"Port {port} is open but service unknown.",
                        url=f"{ip}:{port}",
                        evidence={
                            "port": port,
                            "banner": port_info.get("banner", "")[:100],
                        },
                        metadata={
                            "actual_risk": False,
                        },
                        remediation="Identify and secure unknown services.",
                    )
                )
        
        return findings
