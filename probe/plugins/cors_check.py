"""
Cross-Origin Resource Sharing (CORS) misconfiguration check.

Sends an attacker-controlled ``Origin`` and inspects the response's
Access-Control-Allow-Origin / Access-Control-Allow-Credentials headers. The
dangerous pattern is a server that reflects an arbitrary origin *and* allows
credentials: any website can then read the victim's authenticated responses.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional
from urllib.parse import urlparse

from plugins.base_plugin import BasePlugin, Finding

# A believable attacker origin. Reflection of this exact value is the tell.
PROBE_ORIGIN = "https://qa-cors-probe.example"


def _looks_like_api(url: str) -> bool:
    """A path that is probably a JSON/GraphQL API worth a CORS check on any page."""
    path = urlparse(url).path.lower()
    if any(seg in path for seg in ("/api/", "/api.", "/graphql", "/rest/")) \
            or path.endswith(("/api", "/graphql")):
        return True
    # Version-prefixed APIs sit at the path ROOT (/v1/users), not mid-path
    # (/guide/v1/intro) — the old substring match flagged ordinary content pages.
    return bool(re.match(r"/v[0-9]+/", path))


def _header(headers, name: str) -> str:
    for key, value in (headers or {}).items():
        if key.lower() == name.lower():
            return str(value)
    return ""


def evaluate_cors(sent_origin: str, response_headers) -> Optional[Dict]:
    """Classify a CORS response. Returns a finding dict or None when safe."""
    acao = _header(response_headers, "Access-Control-Allow-Origin")
    acac = _header(response_headers, "Access-Control-Allow-Credentials").lower() == "true"
    if not acao:
        return None

    reflects_attacker = acao == sent_origin and sent_origin not in ("", "*")
    allows_null = acao == "null" and sent_origin == "null"

    if (reflects_attacker or allows_null) and acac:
        return {
            "severity": "high",
            "title": "CORS: credentialed access from an untrusted origin",
            "description": (
                "The server reflects an arbitrary Origin in Access-Control-Allow-Origin "
                "and allows credentials, so any website can read this endpoint's "
                "authenticated responses on a victim's behalf."
            ),
            "remediation": (
                "Never reflect the request Origin. Allow only an explicit allowlist of "
                "trusted origins, and do not combine a wildcard/reflected origin with "
                "Access-Control-Allow-Credentials: true."
            ),
        }
    if reflects_attacker or allows_null:
        return {
            "severity": "low",
            "title": "CORS: arbitrary origin reflected without credentials",
            "description": (
                "The server reflects an arbitrary Origin. Without credentials the impact "
                "is limited, but it still exposes any data readable without authentication."
            ),
            "remediation": "Reflect only trusted origins from an explicit allowlist.",
        }
    if acao == "*" and acac:
        return {
            "severity": "high",
            "title": "CORS: wildcard origin with credentials",
            "description": "A wildcard Access-Control-Allow-Origin with credentials is invalid "
                           "and, where honored, exposes authenticated data to any site.",
            "remediation": "Do not use '*' together with Access-Control-Allow-Credentials: true.",
        }
    if acao == "*":
        return {
            "severity": "info",
            "title": "CORS: wildcard origin",
            "description": "Access-Control-Allow-Origin is '*'. This is only safe for public, "
                           "non-authenticated data.",
            "remediation": "Confirm this endpoint serves only public data.",
        }
    return None


class CORSCheckPlugin(BasePlugin):
    def get_name(self) -> str:
        return "cors_check"

    def get_description(self) -> str:
        return "Detects permissive Cross-Origin Resource Sharing configurations"

    def scan(self, url_info: Dict, request_handler) -> List[Finding]:
        # Test the entry point, plus every API endpoint the browser captured — the
        # real CORS bugs live on /api/* calls, not the landing page.
        url = url_info["url"]
        if url_info.get("depth", 0) != 0 and not url_info.get("captured") \
                and not _looks_like_api(url):
            return []
        response = request_handler.get(url, headers={"Origin": PROBE_ORIGIN})
        if response is None:
            return []
        verdict = evaluate_cors(PROBE_ORIGIN, getattr(response, "headers", {}))
        if verdict is None:
            return []
        return [
            Finding(
                plugin_name=self.get_name(),
                severity=verdict["severity"],
                title=verdict["title"],
                description=verdict["description"],
                url=url,
                evidence={
                    "sent_origin": PROBE_ORIGIN,
                    "access_control_allow_origin": _header(response.headers, "Access-Control-Allow-Origin"),
                    "access_control_allow_credentials": _header(response.headers, "Access-Control-Allow-Credentials"),
                },
                remediation=verdict["remediation"],
            )
        ]
