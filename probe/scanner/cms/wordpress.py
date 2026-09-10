"""
WordPress deep enumeration.

Passive-first: everything that can be read from the homepage HTML is read from
there. A bounded number of follow-up requests (plugin/theme readme files, the
REST users route, a handful of well-known exposure paths) fills in the gaps.

The output feeds two things: informational findings that inventory what is
installed, and CVE correlation against the concrete plugin/theme/core versions
discovered here (which the passive fingerprinter usually cannot see).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse, urlunparse

_ASSET_RE = re.compile(
    r"/wp-content/(?P<kind>plugins|themes)/(?P<slug>[a-z0-9][a-z0-9._-]*)/"
    r"(?P<path>[^\s\"'?>]*)(?P<query>\?[^\s\"'>]*)?",
    re.I,
)
_VER_PARAM_RE = re.compile(r"[?&]ver=([0-9][0-9a-zA-Z.\-_]*)", re.I)
_FEED_GENERATOR_RE = re.compile(r"wordpress\.org/\?v=([0-9][0-9.]*)", re.I)
_META_GENERATOR_RE = re.compile(
    r"""<meta[^>]+name=["']generator["'][^>]+content=["']WordPress\s+([0-9][0-9.]*)""",
    re.I,
)
_README_VERSION_RE = re.compile(r"[Vv]ersion\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)")
_WP_EMBED_RE = re.compile(
    r"/wp-includes/js/wp-embed(?:\.min)?\.js\?ver=([0-9][0-9.]*)", re.I
)
_STABLE_TAG_RE = re.compile(r"^Stable tag:\s*([0-9][0-9a-zA-Z.\-]*)", re.M | re.I)
_STYLE_VERSION_RE = re.compile(r"^\s*Version:\s*([0-9][0-9a-zA-Z.\-]*)", re.M | re.I)

_MAX_COMPONENT_FETCHES = 20


@dataclass
class WordPressReport:
    is_wordpress: bool = False
    core_version: Optional[str] = None
    core_version_source: Optional[str] = None
    homepage_has_generator: bool = False
    plugins: Dict[str, Dict] = field(default_factory=dict)
    themes: Dict[str, Dict] = field(default_factory=dict)
    users: List[Dict] = field(default_factory=list)
    exposures: List[Dict] = field(default_factory=list)


def is_wordpress(html: str, headers: Optional[Dict] = None) -> bool:
    """True if the page HTML or its response headers look like WordPress."""
    # Header names are case-insensitive; normalize so a lowercase-header server
    # (or a plain dict built from one) still matches.
    lower = {str(k).lower(): v for k, v in (headers or {}).items()}
    haystack = html or ""
    if re.search(r"/wp-(?:content|includes)/", haystack, re.I):
        return True
    if _META_GENERATOR_RE.search(haystack):
        return True
    pingback = str(lower.get("x-pingback", ""))
    if pingback.rstrip("/").endswith("xmlrpc.php"):
        return True
    link = str(lower.get("link", ""))
    if "/wp-json/" in link:
        return True
    return False


def _base_url(url: str) -> str:
    """
    Crawl-root base URL, keeping any subdirectory the install lives under.

    ``https://host/blog`` and ``https://host/blog/`` both -> ``https://host/blog/``
    so component/user/feed/exposure requests resolve under ``/blog/``.
    """
    parsed = urlparse(url)
    path = parsed.path or "/"
    if not path.endswith("/"):
        path += "/"
    return urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))


def _extract_components(texts: List[str]) -> Dict[str, Dict[str, Dict]]:
    """Plugin/theme slugs (and ``?ver=`` versions) referenced by the given HTML."""
    found: Dict[str, Dict[str, Dict]] = {"plugins": {}, "themes": {}}
    for text in texts:
        if not text:
            continue
        for match in _ASSET_RE.finditer(text):
            kind = match.group("kind").lower()
            slug = match.group("slug").lower()
            bucket = found["plugins" if kind == "plugins" else "themes"]
            entry = bucket.setdefault(slug, {"version": None, "source": None})
            query = match.group("query") or ""
            ver_match = _VER_PARAM_RE.search(query)
            if ver_match and not entry["version"]:
                candidate = ver_match.group(1)
                # WordPress' own bundled version string is the core version, not
                # the component's — ignore obvious core echoes.
                if candidate.lower() not in {"", "1", "trunk"}:
                    entry["version"] = candidate
                    entry["source"] = "asset-ver"
    return found


def _fill_component_versions(
    http, root_url: str, kind: str, components: Dict[str, Dict]
) -> None:
    """Fetch ``readme.txt`` / ``style.css`` for slugs that had no inline version."""
    fetches = 0
    readme_name = "readme.txt" if kind == "plugins" else "style.css"
    pattern = _STABLE_TAG_RE if kind == "plugins" else _STYLE_VERSION_RE
    for slug, entry in components.items():
        if entry["version"] or fetches >= _MAX_COMPONENT_FETCHES:
            continue
        fetches += 1
        target = urljoin(root_url, f"wp-content/{kind}/{slug}/{readme_name}")
        response = http.get(target, allow_redirects=False)
        if response is None or response.status_code != 200:
            continue
        body = response.text or ""
        match = pattern.search(body)
        if match:
            entry["version"] = match.group(1)
            entry["source"] = readme_name


def _detect_core_version(http, root_url: str, homepage: str) -> tuple:
    """Best-effort ``(version, source)`` for WordPress core; ``(None, None)`` if unknown."""
    meta = _META_GENERATOR_RE.search(homepage or "")
    if meta:
        return meta.group(1), "meta-generator"

    embed = _WP_EMBED_RE.search(homepage or "")
    if embed:
        return embed.group(1), "wp-embed-asset"

    # Do not follow redirects: a cross-host Location on feed/ would send
    # scanner traffic to an unauthorized target.
    feed = http.get(urljoin(root_url, "feed/"), allow_redirects=False)
    if feed is not None and feed.status_code == 200:
        feed_match = _FEED_GENERATOR_RE.search(feed.text or "")
        if feed_match:
            return feed_match.group(1), "rss-generator"

    readme = http.get(urljoin(root_url, "readme.html"), allow_redirects=False)
    if readme is not None and readme.status_code == 200:
        readme_match = _README_VERSION_RE.search(readme.text or "")
        if readme_match:
            return readme_match.group(1), "readme.html"

    return None, None


def _enumerate_users(http, root_url: str) -> List[Dict]:
    """Usernames exposed via the REST users route or the ``?author=`` redirect."""
    users: List[Dict] = []
    seen = set()

    rest = http.get(urljoin(root_url, "wp-json/wp/v2/users"), allow_redirects=False)
    if rest is not None and rest.status_code == 200:
        try:
            payload = json.loads(rest.text or "")
        except (ValueError, TypeError):
            payload = None
        if isinstance(payload, list):
            for item in payload:
                if not isinstance(item, dict):
                    continue
                slug = str(item.get("slug") or "").strip()
                name = str(item.get("name") or "").strip()
                key = slug or name
                if key and key not in seen:
                    seen.add(key)
                    users.append(
                        {
                            "id": item.get("id"),
                            "slug": slug,
                            "name": name,
                            "source": "wp-json",
                        }
                    )

    author = http.get(urljoin(root_url, "?author=1"), allow_redirects=False)
    if author is not None and author.status_code in (301, 302):
        location = str(author.headers.get("Location", ""))
        slug_match = re.search(r"/author/([^/?#]+)", location)
        if slug_match:
            slug = slug_match.group(1)
            if slug not in seen:
                seen.add(slug)
                users.append(
                    {"id": 1, "slug": slug, "name": "", "source": "author-redirect"}
                )

    return users


def _check_exposures(http, root_url: str) -> List[Dict]:
    """Probe a small set of well-known WordPress exposures (xmlrpc, uploads autoindex)."""
    exposures: List[Dict] = []

    xmlrpc = http.get(urljoin(root_url, "xmlrpc.php"), allow_redirects=False)
    if xmlrpc is not None and xmlrpc.status_code in (200, 405):
        if "XML-RPC server accepts POST requests only" in (xmlrpc.text or ""):
            exposures.append(
                {
                    "name": "xmlrpc.php enabled",
                    "severity": "low",
                    "detail": (
                        "xmlrpc.php is reachable. It enables pingback SSRF and "
                        "amplified credential brute-forcing via system.multicall."
                    ),
                }
            )

    uploads = http.get(urljoin(root_url, "wp-content/uploads/"), allow_redirects=False)
    if uploads is not None and uploads.status_code == 200 and re.search(
        r"<title>\s*Index of /", uploads.text or "", re.I
    ):
        exposures.append(
            {
                "name": "Directory listing on wp-content/uploads",
                "severity": "low",
                "detail": "Autoindex is enabled for the uploads directory.",
            }
        )

    return exposures


def enumerate_wordpress(
    http,
    url: str,
    homepage_text: Optional[str] = None,
    extra_texts: Optional[List[str]] = None,
) -> WordPressReport:
    """Run the full WordPress enumeration for one site and return a report."""
    root_url = _base_url(url)

    homepage = homepage_text
    headers: Dict = {}
    if homepage is None:
        response = http.get(root_url)
        if response is None:
            return WordPressReport(is_wordpress=False)
        homepage = response.text or ""
        headers = dict(response.headers)

    report = WordPressReport(is_wordpress=is_wordpress(homepage, headers))
    if not report.is_wordpress:
        return report

    report.homepage_has_generator = bool(_META_GENERATOR_RE.search(homepage or ""))

    texts = [homepage, *(extra_texts or [])]
    components = _extract_components(texts)
    _fill_component_versions(http, root_url, "plugins", components["plugins"])
    _fill_component_versions(http, root_url, "themes", components["themes"])
    report.plugins = components["plugins"]
    report.themes = components["themes"]

    report.core_version, report.core_version_source = _detect_core_version(
        http, root_url, homepage
    )
    report.users = _enumerate_users(http, root_url)
    report.exposures = _check_exposures(http, root_url)

    return report
