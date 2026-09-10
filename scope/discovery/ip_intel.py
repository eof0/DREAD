"""
IP intelligence and ASN lookups.
"""

import socket
from typing import Dict, List, Optional
import requests


class IPIntel:
    """IP range and ASN intelligence."""
    
    def __init__(self):
        self.session = requests.Session()
    
    def get_ip_ranges(self, domain: str) -> Dict:
        """Get IP ranges associated with domain."""
        results = {
            "domain": domain,
            "resolutions": [],
            "asn_info": [],
        }
        
        # Resolve domain to IP
        try:
            ips = socket.getaddrinfo(domain, None)
            seen_ips = set()
            for ip in ips:
                ip_str = ip[4][0]
                if ip_str not in seen_ips:
                    seen_ips.add(ip_str)
                    results["resolutions"].append({
                        "ip": ip_str,
                        "type": "IPv6" if ":" in ip_str else "IPv4",
                    })
                    
                    # Get ASN info for IP
                    asn = self._get_asn_info(ip_str)
                    if asn and asn not in results["asn_info"]:
                        results["asn_info"].append(asn)
        except socket.gaierror:
            pass
        
        return results
    
    def _get_asn_info(self, ip: str) -> Optional[Dict]:
        """Get ASN info for IP using ip-api.com."""
        try:
            response = self.session.get(
                f"http://ip-api.com/json/{ip}?fields=as,isp,org,asname",
                timeout=10
            )
            data = response.json()
            
            if data.get("status") == "success":
                return {
                    "ip": ip,
                    "asn": data.get("as"),
                    "asn_name": data.get("asname"),
                    "isp": data.get("isp"),
                    "organization": data.get("org"),
                }
        except Exception:
            pass
        
        return None
    
    def get_asn_ranges(self, asn: str) -> List[str]:
        """Get IP ranges for an ASN."""
        # Would use BGP data or RIPE API for real implementation
        return []
