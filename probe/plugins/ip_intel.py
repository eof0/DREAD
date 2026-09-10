from plugins.base_plugin import BasePlugin, Finding
from typing import Dict, List
import socket
import requests


class IPIntelPlugin(BasePlugin):
    """
    Public IP intelligence: ASN, org, country, city.
    Public data only.
    """

    def get_name(self) -> str:
        return "ip_intel"

    def get_description(self) -> str:
        return "Public IP intelligence (ASN, organization, geolocation)"

    def scan(self, url_info: Dict, request_handler) -> List[Finding]:
        findings: List[Finding] = []

        # only once at root
        if url_info.get("depth", 0) > 0:
            return findings

        host = url_info.get("hostname") or url_info["url"]
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            return findings

        try:
            resp = requests.get(
                f"https://ipinfo.io/{ip}/json",
                timeout=10,
                headers={"User-Agent": "Probe/1.0"},
            )
            if resp.status_code != 200:
                return findings

            data = resp.json()

        except Exception:
            return findings

        is_edge = False
        org = data.get("org", "").lower()

        if any(x in org for x in ["cloudflare", "akamai", "fastly", "cloudfront"]):
            is_edge = True

        finding = Finding(
            plugin_name=self.get_name(),
            severity="info",
            title="Public IP Intelligence",
            description="Publicly available IP intelligence information",
            url=host,
            evidence={
                "ip": ip,
                "asn": data.get("org"),
                "hostname": data.get("hostname"),
                "city": data.get("city"),
                "region": data.get("region"),
                "country": data.get("country"),
                "edge_infrastructure": is_edge,
            },
            remediation="None required. Informational context only.",
            metadata={
                "edge_infrastructure": is_edge,
                "public_data": True,
            },
        )

        findings.append(finding)
        return findings
