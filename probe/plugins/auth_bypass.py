"""Access-control bypass checks.

When a URL is access-controlled (returns 401/403), try the classic path- and
header-based tricks that misconfigured gateways/proxies fall for — a trailing slash,
case change, dot/encoded-dot segments, `;/`, and rewrite/forwarded headers — and flag
any mutation that turns the 403 into real 200 content (not another login/deny page).
Only runs on URLs that are actually protected, so it stays low-noise.
"""

from __future__ import annotations

from typing import Dict, List
from urllib.parse import urlparse, urlunparse

from plugins.base_plugin import BasePlugin, Finding

# Markers that mean a 200 is really still an auth wall, not a bypass.
_CHALLENGE_MARKERS = (
    "please sign in", "please log in", "sign in to continue", "login required",
    "unauthorized", "forbidden", "access denied", "not authorized", "authentication required",
)


def _looks_like_real_content(response) -> bool:
    if response is None or response.status_code != 200:
        return False
    body = (response.text or "")
    if len(body) < 200:
        return False
    low = body.lower()
    return not any(marker in low for marker in _CHALLENGE_MARKERS)


def _path_variants(url: str) -> List[tuple]:
    """(mutated_url, human description) pairs that a broken authz layer may let through."""
    parsed = urlparse(url)
    path = parsed.path or "/"

    def _with(new_path: str) -> str:
        return urlunparse(parsed._replace(path=new_path))

    variants: List[tuple] = []
    if not path.endswith("/"):
        variants.append((_with(path + "/"), "trailing slash"))
    variants.append((_with(path + "/."), "trailing /."))
    variants.append((_with(path + "/.."), "trailing /.."))
    variants.append((_with(path + "%2f"), "encoded trailing slash"))
    variants.append((_with(path + ";/"), "path parameter ;/"))
    variants.append((_with(path + "..;/"), "..;/ segment"))
    if path != path.upper():
        variants.append((_with(path.upper()), "uppercased path"))
    if path != path.capitalize():
        variants.append((_with(path.capitalize()), "capitalized path"))
    # //segment and /./segment forms
    trimmed = path.lstrip("/")
    if trimmed:
        variants.append((_with("//" + trimmed), "double leading slash"))
        variants.append((_with("/./" + trimmed), "/./ prefix"))
    return variants


def _header_bypasses(url: str) -> List[tuple]:
    parsed = urlparse(url)
    path = parsed.path or "/"
    return [
        ({"X-Original-URL": path}, "X-Original-URL rewrite"),
        ({"X-Rewrite-URL": path}, "X-Rewrite-URL rewrite"),
        ({"X-Forwarded-For": "127.0.0.1"}, "X-Forwarded-For: 127.0.0.1"),
        ({"X-Forwarded-Host": "127.0.0.1"}, "X-Forwarded-Host: 127.0.0.1"),
        ({"X-Custom-IP-Authorization": "127.0.0.1"}, "X-Custom-IP-Authorization"),
        ({"X-Originating-IP": "127.0.0.1"}, "X-Originating-IP: 127.0.0.1"),
    ]


class AuthBypassPlugin(BasePlugin):
    def get_name(self) -> str:
        return "auth_bypass"

    def get_description(self) -> str:
        return "Path- and header-based access-control bypass on protected (401/403) URLs"

    def scan(self, url_info: Dict, request_handler) -> List[Finding]:
        url = url_info["url"]
        base = url_info.get("response") or request_handler.get(url, allow_redirects=False)
        if base is None or base.status_code not in (401, 403):
            return []

        for variant, how in _path_variants(url):
            resp = request_handler.get(variant, allow_redirects=False)
            if _looks_like_real_content(resp):
                return [self._finding(url, how, variant, resp)]

        for headers, how in _header_bypasses(url):
            resp = request_handler.get(url, headers=headers, allow_redirects=False)
            if _looks_like_real_content(resp):
                return [self._finding(url, how, url, resp)]

        return []

    @staticmethod
    def _finding(url: str, how: str, where: str, resp) -> Finding:
        return Finding(
            plugin_name="auth_bypass",
            severity="high",
            title="Access control bypass",
            description=(
                f"{url} is protected (401/403), but the '{how}' mutation returned 200 with "
                "real content — the authorization check can be bypassed."
            ),
            url=url,
            evidence={
                "protected_url": url,
                "bypass_via": how,
                "bypass_request": where,
                "bypass_status": resp.status_code,
                "category": "access-control",
            },
            remediation=(
                "Enforce authorization in the application, not only at the edge/proxy by path "
                "prefix. Normalize the path (decode, collapse ./ and ;), ignore client rewrite "
                "headers (X-Original-URL, X-Rewrite-URL) and spoofable source-IP headers, and "
                "match routes case-insensitively before the authz decision."
            ),
        )
