from typing import Dict, List

from plugins.base_plugin import BasePlugin, Finding


class SecurityHeadersPlugin(BasePlugin):
    # A missing hardening header is not, on its own, a vulnerability: it is the
    # absence of a defense-in-depth control. Real impact requires a separate
    # bug (an injectable sink for CSP, a framing-sensitive page for XFO, an
    # active MITM for HSTS). These are reported as informational hardening
    # recommendations (classification "warning") so they are listed but never
    # counted as vulnerabilities or added to the risk score.
    REQUIRED_HEADERS = {
        "X-Frame-Options": {
            "severity": "low",
            "description": (
                "X-Frame-Options is not set. Framing-based clickjacking is only "
                "exploitable on pages with sensitive state-changing UI and no "
                "frame-ancestors CSP directive."
            ),
            "remediation": 'Add "X-Frame-Options: DENY" or "X-Frame-Options: SAMEORIGIN" (or a frame-ancestors CSP directive)',
        },
        "X-Content-Type-Options": {
            "severity": "info",
            "description": (
                "X-Content-Type-Options is not set. MIME sniffing is only a risk "
                "where user-controlled content is served without a correct "
                "Content-Type."
            ),
            "remediation": 'Add "X-Content-Type-Options: nosniff"',
        },
        "Content-Security-Policy": {
            "severity": "low",
            "description": (
                "No Content-Security-Policy is set. CSP is a mitigation layer for "
                "injection bugs, not a vulnerability in itself."
            ),
            "remediation": "Implement an appropriate Content-Security-Policy",
        },
        "Strict-Transport-Security": {
            "severity": "low",
            "description": (
                "HSTS is not set. Downgrade/SSL-strip attacks require an active "
                "network position; a permanent HTTPS redirect limits exposure."
            ),
            "remediation": 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains"',
        },
    }

    # Marks every finding as an informational hardening recommendation.
    _HARDENING_METADATA = {"classification": "warning", "category": "hardening"}

    def get_name(self) -> str:
        return "security_headers"

    def get_description(self) -> str:
        return "Checks for missing or weak HTTP security headers"

    def scan(self, url_info: Dict, request_handler) -> List[Finding]:
        findings: List[Finding] = []
        verbose = getattr(request_handler, 'verbose', False)

        url = url_info["url"]
        if verbose:
            print(f"[VERBOSE] [security_headers] Checking headers for {url}")

        response = request_handler.get(url)
        if response is None:
            if verbose:
                print(f"[VERBOSE] [security_headers] No response from {url}")
            return findings

        headers = response.headers
        found_headers = list(headers.keys())

        if verbose:
            print(f"[VERBOSE] [security_headers] Response has {len(found_headers)} headers")
            print(f"[VERBOSE] [security_headers] Found headers: {', '.join(found_headers[:10])}{'...' if len(found_headers) > 10 else ''}")

        for header, info in self.REQUIRED_HEADERS.items():
            if header not in headers:
                if header == "Strict-Transport-Security" and not url.startswith("https"):
                    if verbose:
                        print(f"[VERBOSE] [security_headers] Skipping HSTS check (non-HTTPS)")
                    continue

                if verbose:
                    print(f"[VERBOSE] [security_headers] MISSING: {header}")

                findings.append(
                    Finding(
                        plugin_name=self.get_name(),
                        severity=info["severity"],
                        title=f"Missing {header} Header",
                        description=info["description"],
                        url=url,
                        evidence={"missing_header": header},
                        remediation=info["remediation"],
                        metadata=dict(self._HARDENING_METADATA),
                    )
                )
            else:
                if verbose:
                    print(f"[VERBOSE] [security_headers] PRESENT: {header} = {headers[header][:50]}..." if len(str(headers[header])) > 50 else f"[VERBOSE] [security_headers] PRESENT: {header} = {headers[header]}")

        if "X-Frame-Options" in headers:
            value = headers["X-Frame-Options"].upper()
            if value not in ["DENY", "SAMEORIGIN"]:
                if verbose:
                    print(f"[VERBOSE] [security_headers] WEAK: X-Frame-Options = {headers['X-Frame-Options']}")

                findings.append(
                    Finding(
                        plugin_name=self.get_name(),
                        severity="low",
                        title="Weak X-Frame-Options Configuration",
                        description=f"X-Frame-Options is set to '{headers['X-Frame-Options']}'",
                        url=url,
                        evidence={"header_value": headers["X-Frame-Options"]},
                        remediation='Set X-Frame-Options to "DENY" or "SAMEORIGIN"',
                        metadata=dict(self._HARDENING_METADATA),
                    )
                )

        if verbose:
            print(f"[VERBOSE] [security_headers] Found {len(findings)} header issues on {url}")

        return findings
