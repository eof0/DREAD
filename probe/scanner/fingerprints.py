#!/usr/bin/env python3
"""
Advanced Technology Fingerprinting

Detects web technologies, frameworks, servers, CDNs, and analytics
from HTTP responses.
"""

from typing import Dict, Optional, List, Tuple
from urllib.parse import parse_qs, urlparse
import re


# Technology signatures for detection
TECH_SIGNATURES = {
    # Web Frameworks
    "frameworks": {
        "WordPress": {
            "body_patterns": [r"wp-content", r"wp-includes", r"wordpress"],
            "meta": [r"WordPress ([\d.]+)"],
        },
        "Laravel": {
            "body_patterns": [r"laravel", r"csrf-token"],
            "cookies": [r"laravel_session"],
        },
        "Django": {
            "body_patterns": [r"csrfmiddlewaretoken", r"django"],
            "headers": {"Server": r"WSGIServer"},
            "cookies": [r"csrftoken", r"django_sessionid"],
        },
        "Rails": {
            "body_patterns": [r"csrf-param", r"csrf-token", r"ruby-on-rails"],
            "cookies": [r"_session_id", r"_rails"],
        },
        "Express": {
            "headers": {"X-Powered-By": r"Express"},
        },
        "Next.js": {
            "body_patterns": [r"__NEXT_DATA__", r"_next/static"],
            "headers": {"X-Powered-By": r"Next.js"},
        },
        "React": {
            "body_patterns": [r'reactroot', r'data-reactroot', r'react\.js', r'react\.production\.min\.js'],
        },
        "Angular": {
            "body_patterns": [r"ng-app", r"ng-controller", r"angular\.js"],
        },
        "Vue.js": {
            "body_patterns": [r"vue\.js", r"v-app", r"data-v-"],
        },
        "Astro": {
            "body_patterns": [r"astro@", r"data-astro-cid"],
        },
    },
    
    # Web Servers
    "servers": {
        "Apache": {
            "headers": {"Server": r"Apache(?:[/\s]([\d.]+))?"},
        },
        "Nginx": {
            "headers": {"Server": r"nginx(?:[/\s]([\d.]+))?"},
        },
        "IIS": {
            "headers": {"Server": r"Microsoft-IIS(?:[/\s]([\d.]+))?"},
        },
        "Caddy": {
            "headers": {"Server": r"Caddy"},
        },
        "LiteSpeed": {
            "headers": {"Server": r"LiteSpeed"},
        },
    },
    
    # CDNs and Cloud
    "cdn": {
        "Cloudflare": {
            "headers": {"CF-RAY": r".+", "Server": r"cloudflare"},
            "body_patterns": [r"cloudflare"],
        },
        "AWS CloudFront": {
            "headers": {"X-Amz-Cf-Id": r".+", "Via": r"[\d.]+ cloudfront"},
        },
        "Fastly": {
            "headers": {"X-Served-By": r"cache-", "X-Cache": r"."},
        },
        "Akamai": {
            "headers": {"X-Akamai-Request-ID": r".+", "X-Cache": r"TCP_"},
        },
        "MaxCDN": {
            "headers": {"X-CDN-Provider": r"MaxCDN"},
        },
    },
    
    # Programming Languages
    "languages": {
        "PHP": {
            "headers": {"X-Powered-By": r"PHP(?:[/\s]([\d.]+))?"},
            "cookies": [r"PHPSESSID"],
        },
        "Python": {
            "headers": {"Server": r"WSGIServer|Python/[\d.]+"},
        },
        "Node.js": {
            "headers": {"X-Powered-By": r"Express|Node\.js"},
        },
        "Ruby": {
            "headers": {"Server": r"WEBrick|Puma|Unicorn|Passenger"},
        },
        "ASP.NET": {
            "headers": {"X-AspNet-Version": r".+", "X-Powered-By": r"ASP\.NET"},
            "cookies": [r"ASPSESSIONID", r"ASP\.NET_SessionId"],
        },
        "Java": {
            "headers": {"Server": r"Apache-Coyote|Tomcat|Jetty|JBoss"},
            "cookies": [r"JSESSIONID"],
        },
    },
    
    # Analytics
    "analytics": {
        "Google Analytics": {
            "body_patterns": [r"google-analytics", r"googletagmanager", r"gtag", r"ga\("],
        },
        "Google Tag Manager": {
            "body_patterns": [r"googletagmanager\.com/gtm\.js"],
        },
        "Mixpanel": {
            "body_patterns": [r"mixpanel", r"mixpanel\.track"],
        },
        "Segment": {
            "body_patterns": [r"segment\.com", r"analytics\.track"],
        },
        "Hotjar": {
            "body_patterns": [r"hotjar", r"hj\("],
        },
        "Cloudflare Insights": {
            "body_patterns": [r"cloudflareinsights"],
        },
    },
    
    # Databases (indirect detection)
    "databases": {
        "MySQL": {
            "body_patterns": [r"mysql", r"mysqli"],
        },
        "PostgreSQL": {
            "body_patterns": [r"postgresql", r"postgres"],
        },
        "MongoDB": {
            "body_patterns": [r"mongodb", r"mongoose"],
        },
        "Redis": {
            "body_patterns": [r"redis"],
        },
    },
    
    # JavaScript Libraries
    "js_libraries": {
        "jQuery": {
            "body_patterns": [r"jquery[.-]?([\d.]+)?", r"jquery\.min\.js"],
        },
        "Bootstrap": {
            "body_patterns": [r"bootstrap[.-]?([\d.]+)?", r"bootstrap\.min\.css"],
        },
        "React": {
            "body_patterns": [r"react[.-]?([\d.]+)?", r"react\.production\.min\.js"],
        },
        "Vue": {
            "body_patterns": [r"vue[.-]?([\d.]+)?", r"vue\.min\.js"],
        },
        "Angular": {
            "body_patterns": [r"angular[.-]?([\d.]+)?"],
        },
        "Lodash": {
            "body_patterns": [r"lodash", r"_\."],
        },
        "Axios": {
            "body_patterns": [r"axios", r"axios\.min\.js"],
        },
    },
}


def extract_version(text: str, pattern: str) -> Optional[str]:
    """Extract version number from text using pattern."""
    match = re.search(pattern, text, re.IGNORECASE)
    if match:
        return match.group(1) if match.groups() else match.group(0)
    return None


def check_body_patterns(body: str, patterns: List[str]) -> Tuple[bool, Optional[str]]:
    """Check if any pattern matches in body. Returns (found, version)."""
    for pattern in patterns:
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            version = None
            if match.groups():
                version = match.group(1)
            return True, version
    return False, None


def check_headers(headers: Dict, signatures: Dict) -> Tuple[bool, Optional[str]]:
    """Check if header signatures match."""
    for header_name, pattern in signatures.items():
        header_value = headers.get(header_name, "")
        if header_value:
            match = re.search(pattern, header_value, re.IGNORECASE)
            if match:
                version = match.group(1) if match.groups() else None
                return True, version
    return False, None


def check_cookies(headers: Dict, patterns: List[str]) -> bool:
    """Check if any cookie pattern matches."""
    cookie_header = headers.get("Set-Cookie", "") or headers.get("Cookie", "")
    for pattern in patterns:
        if re.search(pattern, cookie_header, re.IGNORECASE):
            return True
    return False


_VERSION_RE = r"\d+(?:\.\d+){1,3}"

# Filename / path segment -> canonical library name.
_LIB_ALIASES = {
    "jquery": "jQuery",
    "jquery-migrate": "jQuery Migrate",
    "jquery.migrate": "jQuery Migrate",
    "jquery-ui": "jQuery UI",
    "bootstrap": "Bootstrap",
    "react": "React",
    "react-dom": "React",
    "vue": "Vue",
    "angular": "Angular",
    "@angular/core": "Angular",
    "lodash": "Lodash",
    "underscore": "Underscore",
    "moment": "Moment.js",
    "d3": "D3.js",
    "axios": "Axios",
    "popper": "Popper.js",
    "@popperjs/core": "Popper.js",
    "swiper": "Swiper",
    "gsap": "GSAP",
    "three": "Three.js",
    "alpinejs": "Alpine.js",
    "alpine": "Alpine.js",
    "htmx": "htmx",
    "htmx.org": "htmx",
    "select2": "Select2",
    "datatables": "DataTables",
    "datatables.net": "DataTables",
    "fontawesome": "Font Awesome",
    "font-awesome": "Font Awesome",
    "tailwindcss": "Tailwind CSS",
    "modernizr": "Modernizr",
    "handlebars": "Handlebars",
    "backbone": "Backbone.js",
    "ember": "Ember.js",
    "knockout": "Knockout",
}

# Distro / platform token -> (os name, os family). Ordered: first match wins.
_OS_MARKERS = [
    (re.compile(r"\bubuntu\b", re.I), "Ubuntu", "Linux"),
    (re.compile(r"\bdebian\b", re.I), "Debian", "Linux"),
    (re.compile(r"\bcentos\b", re.I), "CentOS", "Linux"),
    (re.compile(r"\b(?:red\s?hat|rhel)\b", re.I), "Red Hat Enterprise Linux", "Linux"),
    (re.compile(r"\bfedora\b", re.I), "Fedora", "Linux"),
    (re.compile(r"\b(?:amzn|amazon\s+linux)\b", re.I), "Amazon Linux", "Linux"),
    (re.compile(r"\b(?:suse|sles)\b", re.I), "SUSE Linux", "Linux"),
    (re.compile(r"\bgentoo\b", re.I), "Gentoo", "Linux"),
    (re.compile(r"\balpine\b", re.I), "Alpine Linux", "Linux"),
    (re.compile(r"\bwin(?:32|64)\b|\bwindows\b", re.I), "Windows", "Windows"),
    (re.compile(r"\bfreebsd\b", re.I), "FreeBSD", "BSD"),
    (re.compile(r"\bopenbsd\b", re.I), "OpenBSD", "BSD"),
    (re.compile(r"\bnetbsd\b", re.I), "NetBSD", "BSD"),
    (re.compile(r"\bdarwin\b", re.I), "macOS", "macOS"),
    (re.compile(r"\bunix\b", re.I), "Unix", "Unix"),
]

def _clean_version(value: Optional[str]) -> Optional[str]:
    """Pull a dotted numeric version out of arbitrary text, trimming stray punctuation."""
    if not value:
        return None
    match = re.search(r"\d+(?:\.\d+){0,3}", str(value))
    return match.group(0).rstrip(".-") if match else None


def _merge_tech(items: List[Dict], entry: Dict) -> None:
    """Insert entry into a category list, de-duplicating by name and filling in a version."""
    for existing in items:
        if existing["name"].lower() == entry["name"].lower():
            if entry.get("version") and not existing.get("version"):
                existing["version"] = entry["version"]
            return
    items.append({k: v for k, v in entry.items() if v is not None})


def _lib_from_segment(segment: str) -> Optional[str]:
    """Canonical library name for a path/filename segment, or None."""
    return _LIB_ALIASES.get(segment.lower().strip())


def _asset_urls(html: str) -> List[str]:
    """All ``src=``/``href=`` URLs in the HTML (attribute-order agnostic)."""
    if not html:
        return []
    return re.findall(r"""(?:src|href)\s*=\s*["']([^"'>\s]+)["']""", html, re.I)


def extract_asset_versions(html: str) -> List[Dict]:
    """
    Derive library names and versions from <script src>/<link href> URLs.

    Handles ``name-1.2.3.min.js`` filenames, ``?ver=1.2.3`` query strings,
    ``pkg@1.2.3`` CDN path segments and ``/lib/1.2.3/lib.min.js`` (cdnjs) layouts.
    """
    results: Dict[str, Dict] = {}
    for raw in _asset_urls(html):
        url = raw.strip()
        parsed = urlparse(url)
        path = parsed.path or url
        segments = [s for s in path.split("/") if s]
        filename = segments[-1] if segments else ""
        stem = re.sub(r"\.(min|bundle|slim|pack)\.(js|css|mjs)$", "", filename, flags=re.I)
        stem = re.sub(r"\.(js|css|mjs)$", "", stem, flags=re.I)

        query = parse_qs(parsed.query)
        qver = None
        for key in ("ver", "v", "version"):
            values = query.get(key)
            if values:
                qver = _clean_version(values[0])
                if qver:
                    break

        candidates: List[tuple] = []

        name_ver = re.match(
            rf"^(?P<name>[a-zA-Z][\w.\-]*?)[-.@](?P<ver>{_VERSION_RE})$", stem
        )
        if name_ver:
            lib = _lib_from_segment(name_ver.group("name")) or _lib_from_segment(
                name_ver.group("name").split(".")[0]
            )
            if lib:
                candidates.append((lib, _clean_version(name_ver.group("ver")), url))

        for index, seg in enumerate(segments):
            at_ver = re.match(
                rf"^(?P<name>@?[a-zA-Z][\w.\-/]*?)@(?P<ver>{_VERSION_RE})$", seg
            )
            if at_ver:
                name = at_ver.group("name")
                # ``/npm/@popperjs/core@2.11.8/`` splits into "@popperjs" and
                # "core@2.11.8" — rejoin the scope so scoped aliases resolve.
                if (
                    "/" not in name
                    and index > 0
                    and segments[index - 1].startswith("@")
                ):
                    name = f"{segments[index - 1]}/{name}"
                lib = _lib_from_segment(name)
                if lib:
                    candidates.append((lib, _clean_version(at_ver.group("ver")), url))
            elif re.fullmatch(_VERSION_RE, seg) and index > 0:
                prev = segments[index - 1]
                scoped = (
                    f"{segments[index - 2]}/{prev}"
                    if index > 1 and segments[index - 2].startswith("@")
                    else None
                )
                lib = (
                    (_lib_from_segment(scoped) if scoped else None)
                    or _lib_from_segment(prev)
                    or _lib_from_segment(re.split(r"[.\-@]", prev)[0])
                )
                if lib:
                    candidates.append((lib, _clean_version(seg), url))

        if not candidates:
            lib = _lib_from_segment(re.split(r"[-.@]", stem)[0])
            if lib:
                candidates.append((lib, qver, url))

        for lib, ver, evidence in candidates:
            ver = ver or qver
            existing = results.get(lib)
            if existing is None or (existing.get("version") is None and ver):
                results[lib] = {"name": lib, "version": ver, "evidence": evidence}

    return list(results.values())


def detect_os(response) -> Optional[Dict]:
    """Infer the server operating system from response headers (best effort)."""
    for header_name in ("Server", "X-Powered-By", "X-Generator", "X-AspNet-Version"):
        value = response.headers.get(header_name)
        if not value:
            continue
        value = str(value)
        for pattern, name, family in _OS_MARKERS:
            if pattern.search(value):
                version_match = re.search(
                    rf"{re.escape(name)}[\s/]?(\d+(?:\.\d+){{1,2}})", value, re.I
                )
                return {
                    "name": name,
                    "family": family,
                    "version": version_match.group(1) if version_match else None,
                    "confidence": "medium",
                    "evidence": f"{header_name}: {value}",
                }

    server = str(response.headers.get("Server", ""))
    if re.search(r"microsoft-iis|asp\.net", server, re.I) or response.headers.get(
        "X-AspNet-Version"
    ):
        return {
            "name": "Windows Server",
            "family": "Windows",
            "version": None,
            "confidence": "low",
            "evidence": f"Server: {server}" if server else "X-AspNet-Version header present",
        }
    return None


def _apply_generator_headers(response, tech: Dict, sources: Dict) -> None:
    """Fold ``X-Generator`` / ``X-AspNet-Version`` into the detected-tech buckets."""
    generator = str(response.headers.get("X-Generator", ""))
    if generator:
        match = re.match(
            r"\s*(Drupal|Joomla!?|TYPO3|WordPress|Concrete5|SilverStripe)"
            r"\s*[-!]?\s*v?(\d+(?:\.\d+){0,3})?",
            generator,
            re.I,
        )
        if match:
            raw_name = match.group(1).rstrip("!")
            canonical = {"joomla": "Joomla", "typo3": "TYPO3"}.get(
                raw_name.lower(), raw_name
            )
            entry = {"name": canonical}
            version = _clean_version(match.group(2))
            if version:
                entry["version"] = version
            _merge_tech(tech["frameworks"], entry)
            sources[("frameworks", canonical.lower())] = "header"

    aspnet = response.headers.get("X-AspNet-Version")
    if aspnet:
        _merge_tech(tech["languages"], {"name": "ASP.NET", "version": _clean_version(aspnet)})
        sources[("languages", "asp.net")] = "header"


def _build_technologies(tech: Dict, sources: Dict) -> List[Dict]:
    """Flatten the category breakdown into a list carrying source + confidence."""
    out = []
    for category, items in tech.items():
        for item in items:
            source = sources.get((category, item["name"].lower()), "body")
            version = item.get("version")
            strong = source in ("header", "meta", "asset")
            if version and strong:
                confidence = "high"
            elif strong or source == "cookie":
                confidence = "medium"
            else:
                confidence = "low"
            out.append(
                {
                    "name": item["name"],
                    "version": version,
                    "category": category,
                    "source": source,
                    "confidence": confidence,
                    "evidence": item.get("evidence", ""),
                }
            )
    return out


def fingerprint_technologies(response) -> Dict:
    """
    Perform comprehensive technology fingerprinting on HTTP response.

    Args:
        response: requests.Response object

    Returns:
        Dictionary of detected technologies with versions where available. In
        addition to the legacy flattened keys and ``_detailed`` breakdown, the
        result carries ``os`` (best-effort operating system) and
        ``technologies`` (a structured list with per-entry source/confidence).
    """
    tech = {
        "frameworks": [],
        "servers": [],
        "cdn": [],
        "languages": [],
        "analytics": [],
        "databases": [],
        "js_libraries": [],
        "other": [],
    }
    # (category, name.lower()) -> detection source, used to score confidence.
    sources: Dict[tuple, str] = {}

    body = response.text.lower() if response.text else ""
    normalized_headers = {k.lower(): v for k, v in response.headers.items()}

    # Check each technology category
    for category, technologies in TECH_SIGNATURES.items():
        for tech_name, signatures in technologies.items():
            detected = False
            version = None
            source = None

            if "body_patterns" in signatures:
                found, ver = check_body_patterns(body, signatures["body_patterns"])
                if found:
                    detected = True
                    version = _clean_version(ver)
                    source = "body"

            if (not detected or version is None) and "headers" in signatures:
                found, ver = check_headers(
                    normalized_headers,
                    {k.lower(): v for k, v in signatures["headers"].items()},
                )
                if found:
                    detected = True
                    version = version or _clean_version(ver)
                    source = "header" if source is None else source

            if not detected and "cookies" in signatures:
                if check_cookies(response.headers, signatures["cookies"]):
                    detected = True
                    source = "cookie"

            if (not detected or version is None) and "meta" in signatures:
                found, ver = check_body_patterns(body, signatures["meta"])
                if found:
                    detected = True
                    version = version or _clean_version(ver)
                    source = "meta" if source in (None, "body") else source

            if detected:
                tech_item = {"name": tech_name}
                if version:
                    tech_item["version"] = version
                tech[category].append(tech_item)
                sources[(category, tech_name.lower())] = source or "body"

    # Structured header parsing (generator/runtime headers) + OS inference
    _apply_generator_headers(response, tech, sources)
    os_info = detect_os(response)

    # Library versions from asset URLs override lossy body-pattern captures.
    for asset in extract_asset_versions(response.text or ""):
        _merge_tech(tech["js_libraries"], asset)
        for lib in tech["js_libraries"]:
            if lib["name"] == asset["name"] and asset.get("version"):
                lib["version"] = asset["version"]
                lib.setdefault("evidence", asset.get("evidence", ""))
        sources[("js_libraries", asset["name"].lower())] = "asset"

    # Normalise every captured version string once.
    for items in tech.values():
        for item in items:
            if item.get("version"):
                cleaned = _clean_version(item["version"])
                if cleaned:
                    item["version"] = cleaned
                else:
                    item.pop("version", None)

    # Additional simple checks
    server = response.headers.get("Server", "")
    if server and not any(s["name"] in str(server) for s in tech["servers"]):
        tech["other"].append({"name": server})

    powered_by = response.headers.get("X-Powered-By", "")
    if powered_by:
        tech["other"].append({"name": powered_by})

    # Flatten for backward compatibility
    flattened = {}
    for category, items in tech.items():
        if items:
            if category == "frameworks" and items:
                flattened["framework"] = items[0]["name"]
                if "version" in items[0]:
                    flattened["framework_version"] = items[0]["version"]
            elif category == "servers" and items:
                flattened["server"] = items[0]["name"]
            elif category == "languages" and items:
                flattened["language"] = items[0]["name"]
            elif category == "cdn" and items:
                flattened["cdn"] = items[0]["name"]
            elif category == "analytics" and items:
                flattened["analytics"] = items[0]["name"]

    if os_info:
        flattened["os"] = os_info
        flattened["os_family"] = os_info["family"]

    flattened["_detailed"] = tech
    flattened["technologies"] = _build_technologies(tech, sources)

    return flattened


def get_technology_summary(tech: Dict) -> str:
    """Generate human-readable technology summary."""
    parts = []
    
    if "framework" in tech:
        fw = tech["framework"]
        ver = tech.get("framework_version", "")
        parts.append(f"Framework: {fw} {ver}".strip())

    if "server" in tech:
        parts.append(f"Server: {tech['server']}")

    if tech.get("os"):
        os_info = tech["os"]
        label = os_info.get("name", "")
        if os_info.get("version"):
            label = f"{label} {os_info['version']}"
        if label:
            parts.append(f"OS: {label}")
    
    if "language" in tech:
        parts.append(f"Language: {tech['language']}")
    
    if "cdn" in tech:
        parts.append(f"CDN: {tech['cdn']}")
    
    if "_detailed" in tech:
        detailed = tech["_detailed"]
        if detailed.get("js_libraries"):
            libs = [lib["name"] for lib in detailed["js_libraries"][:3]]
            parts.append(f"JS Libraries: {', '.join(libs)}")
    
    return " | ".join(parts) if parts else "No technologies detected"


# Backward compatibility
if __name__ == "__main__":
    import requests
    
    # Test fingerprinting
    test_urls = [
        "https://wordpress.com",
        "https://github.com",
    ]
    
    for url in test_urls:
        try:
            resp = requests.get(url, timeout=10)
            tech = fingerprint_technologies(resp)
            print(f"\n{url}:")
            print(get_technology_summary(tech))
            print(f"Detailed: {tech.get('_detailed', {})}")
        except Exception as e:
            print(f"\n{url}: Error - {e}")
