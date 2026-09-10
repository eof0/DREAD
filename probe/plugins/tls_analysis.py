from typing import Dict, List
from urllib.parse import urlparse
import socket
import ssl
from datetime import datetime, timezone

from plugins.base_plugin import BasePlugin, Finding


class TLSAnalysisPlugin(BasePlugin):
    """
    Analyzes TLS configuration for the target host: certificate, expiry, protocol, cipher.
    """

    def get_name(self) -> str:
        return "tls_analysis"

    def get_description(self) -> str:
        return "Performs basic TLS inspection (certificate, expiry, protocol, cipher)"

    def _flatten_name(self, name_parts):
        flat = []
        for part in name_parts:
            for key, value in part:
                flat.append(f"{key}={value}")
        return ", ".join(flat)

    def _analyze_port(self, host: str, port: int) -> List[Finding]:
        findings: List[Finding] = []

        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()
                    cipher = ssock.cipher()
        except Exception:
            return findings

        now = datetime.now(timezone.utc)
        not_after_str = cert.get("notAfter")
        not_after = None
        days_left = None

        if not_after_str:
            try:
                not_after = datetime.strptime(
                    not_after_str, "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=timezone.utc)
                days_left = (not_after - now).days
            except Exception:
                pass

        severity = "low"
        reasons = []

        if not_after and now > not_after:
            severity = "high"
            reasons.append("Certificate is expired.")
        elif not_after and days_left is not None and days_left < 30:
            severity = "medium"
            reasons.append(f"Certificate expires soon ({days_left} days).")

        if protocol in ("TLSv1", "TLSv1.1"):
            if severity != "high":
                severity = "medium"
            reasons.append(f"Weak TLS protocol in use: {protocol}.")

        subject = self._flatten_name(cert.get("subject", []))
        issuer = self._flatten_name(cert.get("issuer", []))

        description = (
            f"TLS is enabled on port {port} using protocol {protocol} with cipher "
            f"{cipher[0]} ({cipher[2]}-bit)."
        )

        evidence = {
            "port": port,
            "protocol": protocol,
            "cipher": cipher,
            "not_after": not_after_str,
            "days_until_expiry": days_left,
            "subject": subject,
            "issuer": issuer,
        }
        if not reasons:
            return [
                Finding(
                    plugin_name=self.get_name(),
                    severity="info",
                    title=f"TLS Configuration on Port {port}",
                    description=(
                        description + " This is a healthy configuration observation, "
                        "not a vulnerability."
                    ),
                    url=f"{host}:{port}",
                    evidence=evidence,
                    remediation="No action required based on this TLS observation.",
                    metadata={"classification": "warning"},
                )
            ]

        description += " " + " ".join(reasons)
        findings.append(
            Finding(
                plugin_name=self.get_name(),
                severity=severity,
                title=f"TLS Configuration on Port {port}",
                description=description,
                url=f"{host}:{port}",
                evidence=evidence,
                remediation=(
                    "Renew certificates before expiration and ensure only modern TLS "
                    "protocols and strong ciphers are enabled."
                ),
            )
        )

        return findings

    def scan(self, url_info: Dict, request_handler) -> List[Finding]:
        findings: List[Finding] = []

        if url_info.get("depth", 0) > 0:
            return findings

        url = url_info["url"]
        parsed = urlparse(url)
        host = parsed.hostname

        if not host:
            return findings

        for port in [443, 8443]:
            findings.extend(self._analyze_port(host, port))

        return findings
