"""
WordPress deep-enumeration plugin.

Inventories core / plugins / themes / users via ``scanner.cms.wordpress`` and
correlates the concrete versions it finds against the local CVE store. Runs
once, at crawl root, and only when the target actually looks like WordPress.
"""

from __future__ import annotations

from typing import Dict, List

from plugins.base_plugin import BasePlugin, Finding
from scanner.cms.wordpress import enumerate_wordpress, is_wordpress

try:
    from scanner.cve_db import sqlite_cve_db_available
    from scanner.cve_db_manager import query_cves
    from scanner.cve_matcher import calculate_severity
except ImportError:  # pragma: no cover - optional CVE store
    sqlite_cve_db_available = lambda: False  # noqa: E731
    query_cves = None  # type: ignore
    calculate_severity = None  # type: ignore

_MAX_CVES_PER_COMPONENT = 10


class WordPressScanPlugin(BasePlugin):
    def get_name(self) -> str:
        return "wordpress_scan"

    def get_description(self) -> str:
        return "Enumerates WordPress core, plugins, themes and users, then correlates CVEs"

    def scan(self, url_info: Dict, request_handler) -> List[Finding]:
        """Enumerate + CVE-correlate WordPress at crawl root; [] for non-WP targets."""
        if url_info.get("depth", 0) > 0:
            return []

        url = url_info["url"]
        response = url_info.get("response") or request_handler.get(url)
        if response is None:
            return []

        homepage = response.text or ""
        if not is_wordpress(homepage, dict(response.headers)):
            return []

        report = enumerate_wordpress(request_handler, url, homepage_text=homepage)
        if not report.is_wordpress:
            return []

        findings: List[Finding] = []
        findings.extend(self._inventory_findings(url, report))
        findings.extend(self._cve_findings(url, report))
        return findings

    # -- inventory (informational) -------------------------------------------------

    def _inventory_findings(self, url: str, report) -> List[Finding]:
        """Informational findings: core version, component inventory, users, exposures."""
        findings: List[Finding] = []

        if report.core_version:
            findings.append(
                Finding(
                    plugin_name=self.get_name(),
                    severity="info",
                    title=f"WordPress core {report.core_version}",
                    description=(
                        "WordPress core version identified via "
                        f"{report.core_version_source}."
                    ),
                    url=url,
                    evidence={
                        "version": report.core_version,
                        "source": report.core_version_source,
                    },
                    remediation="Keep WordPress core on the latest maintenance release.",
                )
            )

        for label, components in (("plugin", report.plugins), ("theme", report.themes)):
            if not components:
                continue
            inventory = {
                slug: info.get("version") or "unknown"
                for slug, info in sorted(components.items())
            }
            versioned = sum(1 for v in inventory.values() if v != "unknown")
            findings.append(
                Finding(
                    plugin_name=self.get_name(),
                    severity="info",
                    title=f"WordPress {label}s detected ({len(inventory)})",
                    description=(
                        f"{len(inventory)} {label}(s) referenced by the site; "
                        f"{versioned} with an identifiable version."
                    ),
                    url=url,
                    evidence={"components": inventory},
                    remediation=(
                        f"Remove unused {label}s and keep the rest updated; "
                        "unmaintained components are the most common WordPress entry point."
                    ),
                )
            )

        if report.users:
            names = [u.get("slug") or u.get("name") for u in report.users if u.get("slug") or u.get("name")]
            findings.append(
                Finding(
                    plugin_name=self.get_name(),
                    severity="low",
                    title="WordPress user enumeration exposed",
                    description=(
                        "Valid usernames can be harvested without authentication "
                        f"({len(names)} found), which enables targeted password attacks."
                    ),
                    url=url,
                    evidence={"users": report.users},
                    remediation=(
                        "Disable the REST users route for unauthenticated requests, "
                        "block ?author= scans, and align display names with logins."
                    ),
                )
            )

        for exposure in report.exposures:
            findings.append(
                Finding(
                    plugin_name=self.get_name(),
                    severity=exposure.get("severity", "low"),
                    title=exposure["name"],
                    description=exposure.get("detail", ""),
                    url=url,
                    evidence={"check": exposure["name"]},
                    remediation=exposure.get("remediation", "Restrict or disable this endpoint."),
                )
            )

        return findings

    # -- CVE correlation ---------------------------------------------------------

    def _cve_findings(self, url: str, report) -> List[Finding]:
        """Correlate discovered core/plugin/theme versions against the CVE store."""
        if not (sqlite_cve_db_available() and query_cves and calculate_severity):
            return []

        findings: List[Finding] = []

        # Core: only when the passive fingerprinter would have missed it, to
        # avoid duplicating cve_correlation's WordPress-core findings.
        if report.core_version and not report.homepage_has_generator:
            findings.extend(
                self._query("WordPress core", "wordpress", report.core_version, url)
            )

        for slug, info in sorted(report.plugins.items()):
            if info.get("version"):
                findings.extend(
                    self._query(f"WordPress plugin {slug}", slug, info["version"], url)
                )
        for slug, info in sorted(report.themes.items()):
            if info.get("version"):
                findings.extend(
                    self._query(f"WordPress theme {slug}", slug, info["version"], url)
                )

        return findings

    def _query(self, label: str, product: str, version: str, url: str) -> List[Finding]:
        """Query the CVE store for one product/version and build capped findings."""
        try:
            rows = query_cves(product, version=version)
        except Exception:
            return []

        rows = sorted(rows, key=lambda r: r.get("cvss_score") or 0, reverse=True)
        findings: List[Finding] = []
        for row in rows[:_MAX_CVES_PER_COMPONENT]:
            cve_id = row.get("cve_id", "UNKNOWN")
            cvss = row.get("cvss_score")
            severity = calculate_severity(cvss, cve_id)
            if row.get("kev"):
                severity = "critical"
            findings.append(
                Finding(
                    plugin_name=self.get_name(),
                    severity=severity,
                    title=f"{cve_id}: {label} {version}",
                    description=row.get("description") or "No description available.",
                    url=url,
                    evidence={
                        "component": label,
                        "detected_version": version,
                        "cve_id": cve_id,
                        "cvss_score": cvss,
                        "kev": bool(row.get("kev")),
                        "epss_score": row.get("epss_score"),
                        "references": (row.get("references") or [])[:3],
                        "confidence": "medium",
                    },
                    remediation=f"Upgrade {label} past {version} to a patched release.",
                )
            )
        return findings
