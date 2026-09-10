from typing import Dict, List

from plugins.base_plugin import BasePlugin, Finding
from scanner.fingerprints import fingerprint_technologies


class FingerprintingPlugin(BasePlugin):
    """
    Passive technology fingerprinting (server, framework, language, CDN, analytics)
    """

    def get_name(self) -> str:
        return "fingerprinting"

    def get_description(self) -> str:
        return "Passive technology fingerprinting (server, framework, language, CDN, analytics)"

    def scan(self, url_info: Dict, request_handler) -> List[Finding]:
        findings: List[Finding] = []
        verbose = getattr(request_handler, 'verbose', False)

        # Only run once at root
        if url_info.get("depth", 0) > 0:
            return findings

        url = url_info["url"]
        if verbose:
            print(f"[VERBOSE] [fingerprinting] Fingerprinting {url}")

        response = request_handler.get(url)
        if response is None:
            if verbose:
                print(f"[VERBOSE] [fingerprinting] No response from {url}")
            return findings

        tech = fingerprint_technologies(response)
        if verbose:
            print(f"[VERBOSE] [fingerprinting] Detected {len(tech)} technologies")
            for t in tech:
                print(f"[VERBOSE] [fingerprinting]   - {t.get('name', 'unknown')}: {t.get('version', 'unknown')}")

        if not tech:
            return findings

        findings.append(
            Finding(
                plugin_name=self.get_name(),
                severity="info",
                title="Technology Fingerprinting",
                description="Passive identification of technologies used by the target",
                url=url,
                evidence=tech,
                remediation="Use this information to correlate against known CVEs and version-specific vulnerabilities.",
            )
        )

        return findings
