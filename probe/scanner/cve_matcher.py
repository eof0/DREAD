"""
Enhanced CVE Matching with CPE parsing and semantic versioning.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple
from packaging.version import InvalidVersion, Version


def parse_cpe(cpe_string: str) -> Optional[Dict]:
    """
    Parse CPE 2.3 format: cpe:2.3:part:vendor:product:version:update:edition:lang:...
    Returns dict with vendor, product, version, etc.
    """
    if not cpe_string or not cpe_string.startswith("cpe:"):
        return None
    
    parts = cpe_string.split(":")
    if len(parts) < 6:
        return None
    
    # cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    return {
        "part": parts[2] if len(parts) > 2 else "a",  # a=app, o=os, h=hardware
        "vendor": parts[3] if len(parts) > 3 else "",
        "product": parts[4] if len(parts) > 4 else "",
        "version": parts[5] if len(parts) > 5 else "",
        "update": parts[6] if len(parts) > 6 else "",
        "edition": parts[7] if len(parts) > 7 else "",
    }


def normalize_product_name(name: str) -> str:
    """Normalize product name for matching."""
    name = name.lower().strip()
    # Remove common suffixes/prefixes
    name = re.sub(r'\s+(web\s+)?server$', '', name)
    name = re.sub(r'^apache\s+', 'apache_', name)
    return name


# Known product aliases mapping detected technology names → CPE product names.
# Each detected name maps to one or more CPE product identifiers that represent
# the same software. Only exact matches within these alias lists are used.
PRODUCT_ALIASES: Dict[str, List[str]] = {
    "wordpress": ["wordpress", "wp"],
    "apache": ["apache", "apache_http_server", "httpd", "apache_httpd"],
    "nginx": ["nginx", "nginx_proxy", "nginx_plus"],
    "mysql": ["mysql", "oracle_mysql", "mariadb"],
    "mariadb": ["mariadb", "mysql"],
    "postgresql": ["postgresql", "postgres"],
    "mongodb": ["mongodb", "mongo_db"],
    "redis": ["redis", "redis_server"],
    "laravel": ["laravel"],
    "django": ["django"],
    "rails": ["rails", "ruby_on_rails"],
    "nodejs": ["nodejs", "node.js", "node_js"],
    "php": ["php", "php_fpm", "php_cli"],
    "python": ["python"],
    "java": ["java", "oracle_java", "openjdk", "jdk", "jre"],
}


def _get_cpe_names(detected_name: str) -> List[str]:
    """Return all known CPE product names that map to this detected technology."""
    normalized = normalize_product_name(detected_name)
    return PRODUCT_ALIASES.get(normalized, [normalized])


# Known CPE vendor for each detected technology.
# When set, query_cves uses it to filter out CVEs from unrelated vendors
# (e.g. "astro" web framework has vendor "astro", not "saxum2003").
PRODUCT_VENDORS: Dict[str, str] = {
    "wordpress": "wordpress",
    "apache": "apache",
    "nginx": "nginx",
    "mysql": "mysql",
    "mariadb": "mariadb",
    "postgresql": "postgresql",
    "mongodb": "mongodb",
    "redis": "redis",
    "laravel": "laravel",
    "django": "django",
    "rails": "rails",
    "nodejs": "nodejs",
    "php": "php",
    "python": "python",
    "java": "java",
    "astro": "astro",
}


def _get_expected_vendor(detected_name: str) -> Optional[str]:
    """Return the expected CPE vendor for a detected technology, if known."""
    normalized = normalize_product_name(detected_name)
    return PRODUCT_VENDORS.get(normalized)


def product_names_match(detected: str, cve_product: str) -> bool:
    """Check if detected product matches CVE product name."""
    detected_aliases = _get_cpe_names(detected)
    cve_aliases = _get_cpe_names(cve_product)
    return any(d == c for d in detected_aliases for c in cve_aliases)


def parse_version_range(cpe: Dict) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract version range from CPE data.
    Returns (min_version, max_version) where None means unbounded.
    """
    version = cpe.get("version", "")
    
    # Handle special version strings
    if version in ["*", "-", "any", ""]:
        return (None, None)
    
    # Check for range patterns in update field
    update = cpe.get("update", "")
    
    # before/after patterns
    if update.startswith("before_"):
        return (None, update.replace("before_", ""))
    if update.startswith("after_"):
        return (update.replace("after_", ""), None)
    
    return (version, version)


def _coerce_version(value: str) -> Optional[Version]:
    """
    Parse a version string leniently.

    Real-world banner/package versions are frequently not valid PEP 440
    (e.g. Debian/Ubuntu suffixes like "2.4.41-1ubuntu1" or
    "5.7.31-0ubuntu0.18.04.1"), which Version() rejects outright. Fall
    back to the leading dotted-numeric prefix so those versions can
    still be compared; return None only if no numeric version can be
    recovered at all.
    """
    try:
        return Version(value)
    except InvalidVersion:
        pass
    match = re.match(r"[0-9]+(?:\.[0-9]+)*", value)
    if not match:
        return None
    try:
        return Version(match.group(0))
    except InvalidVersion:
        return None


def version_in_range(
    detected: Optional[str],
    min_ver: Optional[str],
    max_ver: Optional[str],
    min_inclusive: bool = True,
    max_inclusive: bool = True,
) -> bool:
    """Check if detected version falls within [min_ver, max_ver].

    min_inclusive/max_inclusive control whether each bound is inclusive
    (versionStartIncluding/versionEndIncluding in NVD terms) or exclusive
    (versionStartExcluding/versionEndExcluding).
    """
    if not detected:
        # No version detected - can't determine vulnerability
        # Only match if CVE affects all versions (no version constraints)
        return min_ver is None and max_ver is None

    if min_ver is None and max_ver is None:
        return True

    detected_v = _coerce_version(detected)
    if detected_v is None:
        # Can't parse the detected version at all - don't claim a match
        # against a bounded range; that would flood results with false
        # positives for every technology we can't version-compare.
        return False

    if min_ver is not None:
        min_v = _coerce_version(min_ver)
        if min_v is None:
            # A bound is declared but unparseable - don't silently treat
            # it as unbounded (that would let out-of-range versions
            # through); decline the match instead.
            return False
        if min_inclusive:
            if detected_v < min_v:
                return False
        elif detected_v <= min_v:
            return False

    if max_ver is not None:
        max_v = _coerce_version(max_ver)
        if max_v is None:
            return False
        if max_inclusive:
            if detected_v > max_v:
                return False
        elif detected_v >= max_v:
            return False

    return True


def extract_cve_info(cve_entry: Dict) -> List[Dict]:
    """
    Extract product and version info from CVE entry.
    Returns list of affected products with version ranges.
    """
    products = []
    raw = cve_entry.get("raw", [])
    
    for config in raw:
        nodes = config.get("nodes", [])
        for node in nodes:
            matches = node.get("cpeMatch", [])
            for match in matches:
                if not match.get("vulnerable", False):
                    continue
                
                criteria = match.get("criteria", "")
                cpe = parse_cpe(criteria)
                if not cpe:
                    continue
                
                # Check for version range in versionStart/EndIncluding/Excluding.
                # Including and Excluding are mutually exclusive per NVD's
                # schema; track which one applied so callers can honor the
                # correct boundary (an Excluding bound means that version
                # itself is already patched).
                min_ver = match.get("versionStartIncluding")
                min_inclusive = True
                if min_ver is None:
                    min_ver = match.get("versionStartExcluding")
                    min_inclusive = False

                max_ver = match.get("versionEndIncluding")
                max_inclusive = True
                if max_ver is None:
                    max_ver = match.get("versionEndExcluding")
                    max_inclusive = False

                if min_ver is None and max_ver is None:
                    min_ver, max_ver = parse_version_range(cpe)
                    min_inclusive = True
                    max_inclusive = True
                
                products.append({
                    "vendor": cpe.get("vendor", ""),
                    "product": cpe.get("product", ""),
                    "min_version": min_ver,
                    "max_version": max_ver,
                    "min_inclusive": min_inclusive,
                    "max_inclusive": max_inclusive,
                    "version": cpe.get("version"),
                })
    
    return products


def match_technology_to_cve(tech_name: str, tech_version: Optional[str], cve_entry: Dict) -> Optional[Dict]:
    """
    Match a detected technology to a CVE entry.
    Returns match details if vulnerable, None if not.
    """
    affected_products = extract_cve_info(cve_entry)
    
    for product in affected_products:
        if product_names_match(tech_name, product["product"]):
            # Product matches, check version
            if version_in_range(
                tech_version,
                product["min_version"],
                product["max_version"],
                min_inclusive=product.get("min_inclusive", True),
                max_inclusive=product.get("max_inclusive", True),
            ):
                # "confirmed" means a detected version was checked against
                # an actual bounded range; "low" means either no version
                # was detected, or the CVE record has no version bound at
                # all (matched on product name alone).
                confidence = (
                    "confirmed"
                    if tech_version and (product["min_version"] or product["max_version"])
                    else "low"
                )
                return {
                    "matched_product": product["product"],
                    "detected_version": tech_version,
                    "affected_versions": f"{product['min_version'] or 'any'} - {product['max_version'] or 'any'}",
                    "confidence": confidence,
                }
    
    return None


def calculate_severity(cvss_score: Optional[float], cve_id: str = "") -> str:
    """Calculate severity from CVSS score or CVE ID patterns."""
    if cvss_score is not None:
        if cvss_score >= 9.0:
            return "critical"
        elif cvss_score >= 7.0:
            return "high"
        elif cvss_score >= 4.0:
            return "medium"
        else:
            return "low"
    
    # Try to extract year from CVE ID for prioritization
    if cve_id.startswith("CVE-"):
        try:
            year = int(cve_id.split("-")[1])
            # Older CVEs are more likely to have exploits
            if year < 2015:
                return "high"  # Assume high for old CVEs without score
            elif year < 2020:
                return "medium"
            else:
                return "low"
        except:
            pass
    
    return "medium"


# Export for use in plugins
__all__ = [
    "parse_cpe",
    "normalize_product_name",
    "product_names_match",
    "PRODUCT_ALIASES",
    "PRODUCT_VENDORS",
    "_get_cpe_names",
    "_get_expected_vendor",
    "version_in_range",
    "extract_cve_info",
    "match_technology_to_cve",
    "calculate_severity",
]
