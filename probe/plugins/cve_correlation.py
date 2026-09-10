"""
Enhanced CVE Correlation Plugin

Correlates detected technologies with CVEs using:
- CPE parsing for accurate product matching
- Semantic versioning for version ranges
- Multiple product name aliases
"""

from plugins.base_plugin import BasePlugin, Finding
from typing import Dict, List

from scanner.cve_db import load_cve_db, sqlite_cve_db_available
from scanner.fingerprints import fingerprint_technologies
from scanner.cve_matcher import (
    match_technology_to_cve,
    calculate_severity,
)

try:
    from scanner.cve_db_manager import query_cves
except ImportError:
    query_cves = None  # type: ignore


def _epss_note(score, percentile):
    if score is None:
        return ""
    if score >= 0.5:
        band = "high probability of exploitation in the next 30 days"
    elif score >= 0.1:
        band = "elevated probability of exploitation in the next 30 days"
    else:
        band = "low probability of exploitation in the next 30 days"
    pct = f", {round(percentile * 100)}th percentile" if percentile is not None else ""
    return f" EPSS {score:.2f}{pct}: {band}."


class CVECorrelationPlugin(BasePlugin):

    def get_name(self) -> str:
        return "cve_correlation"

    def get_description(self) -> str:
        return "Correlates detected technologies with CVEs using CPE matching"

    def _extract_all_technologies(self, tech: Dict) -> List[Dict]:
        """Extract all detected technologies with their versions."""
        technologies = []
        
        # Get detailed breakdown
        detailed = tech.get("_detailed", {})
        
        for category, items in detailed.items():
            for item in items:
                tech_entry = {
                    "name": item["name"],
                    "category": category,
                    "version": item.get("version"),
                }
                technologies.append(tech_entry)
        
        # Also add flattened versions
        if "framework" in tech:
            technologies.append({
                "name": tech["framework"],
                "category": "framework",
                "version": tech.get("framework_version"),
            })
        
        if "server" in tech:
            technologies.append({
                "name": tech["server"],
                "category": "server",
                "version": None,
            })
        
        if "language" in tech:
            technologies.append({
                "name": tech["language"],
                "category": "language",
                "version": None,
            })

        # Operating system: only correlate when a concrete version was seen.
        # Name-only OS matching floods results with irrelevant kernel/distro
        # CVEs, so it is deliberately skipped here.
        os_info = tech.get("os") or {}
        if os_info.get("version"):
            technologies.append({
                "name": os_info.get("name"),
                "category": "os",
                "version": os_info.get("version"),
            })

        return technologies

    def _generate_contextual_guidance(self, tech_name: str, cve_id: str) -> Dict[str, str]:
        """Generate attack/defense/mitigation specific to the technology."""
        
        tech_lower = tech_name.lower()
        
        # Database-specific guidance
        if any(db in tech_lower for db in ["mysql", "postgres", "mongodb", "redis", "mariadb"]):
            return {
                "attack": (
                    f"Attackers can exploit {tech_name} vulnerabilities to extract, modify, or "
                    f"delete database contents. Common attacks include SQL injection, authentication "
                    f"bypass, and remote code execution through database features."
                ),
                "defense": (
                    "Implement network segmentation with databases in private subnets. Use VPN or "
                    "bastion hosts for administrative access. Enable query logging and intrusion "
                    "detection. Regularly patch and upgrade database software."
                ),
                "mitigation": (
                    "1. Identify all database instances and their versions\n"
                    "2. Check vendor security advisories for this CVE\n"
                    "3. Test patches in staging environment\n"
                    "4. Apply updates during maintenance window\n"
                    "5. Verify remediation through re-scanning"
                ),
            }
        
        # Web framework guidance
        if any(fw in tech_lower for fw in ["wordpress", "laravel", "django", "rails", "drupal", "joomla"]):
            return {
                "attack": (
                    f"Web framework vulnerabilities can lead to remote code execution, privilege "
                    f"escalation, or data breaches. Attackers may exploit plugin/addon vulnerabilities "
                    f"or core framework weaknesses."
                ),
                "defense": (
                    "Keep frameworks and all plugins/themes updated. Use Web Application Firewall (WAF) "
                    "rules specific to the framework. Implement proper input validation and output "
                    "encoding. Enable security headers and CSRF protection."
                ),
                "mitigation": (
                    "1. Inventory all framework plugins/extensions\n"
                    "2. Remove unused plugins\n"
                    "3. Enable automatic security updates if available\n"
                    "4. Implement WAF rules\n"
                    "5. Schedule regular security scans"
                ),
            }
        
        # Server software guidance
        if any(srv in tech_lower for srv in ["apache", "nginx", "iis", "tomcat"]):
            return {
                "attack": (
                    f"Web server vulnerabilities can allow attackers to bypass access controls, "
                    f"execute arbitrary code, or cause denial of service. Misconfigurations are "
                    f"commonly exploited alongside software vulnerabilities."
                ),
                "defense": (
                    "Follow server hardening guides. Remove default pages and unnecessary modules. "
                    "Implement proper access controls and logging. Use mod_security or equivalent "
                    "for additional protection."
                ),
                "mitigation": (
                    "1. Review server configuration against CIS benchmarks\n"
                    "2. Apply security patches\n"
                    "3. Remove unnecessary modules/extensions\n"
                    "4. Enable comprehensive logging\n"
                    "5. Configure fail2ban for brute force protection"
                ),
            }
        
        # Language/runtime guidance
        if any(lang in tech_lower for lang in ["php", "python", "nodejs", "ruby", "java"]):
            return {
                "attack": (
                    f"Runtime vulnerabilities can lead to code execution, memory corruption, or "
                    f"denial of service. Applications running on vulnerable runtimes are at risk "
                    f"regardless of application code quality."
                ),
                "defense": (
                    "Use current supported versions of languages/runtimes. Implement application "
                    "sandboxing and resource limits. Monitor for unusual process behavior. Use "
                    "dependency scanning for known vulnerable libraries."
                ),
                "mitigation": (
                    "1. Inventory all applications using this runtime\n"
                    "2. Plan runtime version upgrades\n"
                    "3. Test application compatibility\n"
                    "4. Deploy updates\n"
                    "5. Implement runtime monitoring"
                ),
            }
        
        # Default guidance
        return {
            "attack": (
                f"This vulnerability in {tech_name} could allow attackers to compromise system "
                f"confidentiality, integrity, or availability. Review the CVE details for specific "
                f"attack vectors."
            ),
            "defense": (
                "Apply defense in depth principles. Restrict network exposure. Monitor for "
                "suspicious activity. Maintain regular backups."
            ),
            "mitigation": (
                "1. Identify affected systems\n"
                "2. Review vendor security advisories\n"
                "3. Test patches in non-production\n"
                "4. Deploy fixes\n"
                "5. Verify remediation"
            ),
        }

    def _append_cve_finding(
        self,
        findings: List[Finding],
        url: str,
        tech_name: str,
        tech_version: str | None,
        cve_id: str,
        severity: str,
        cvss: float | None,
        match: Dict,
        description: str,
        references: List | None = None,
    ) -> None:
        guidance = self._generate_contextual_guidance(tech_name, cve_id)
        refs = references or []
        confidence = match.get("confidence", "low")
        kev = bool(match.get("kev"))
        kev_date_added = match.get("kev_date_added")
        epss_score = match.get("epss_score")
        epss_percentile = match.get("epss_percentile")

        # CISA KEV means this CVE is confirmed exploited in the wild right
        # now — that outweighs a CVSS-bucket severity computed in the
        # abstract, so it overrides rather than just adding to it.
        if kev:
            severity = "critical"

        remediation = (
            f"Upgrade {tech_name} to a patched version. "
            "See CVE details for specific fixed versions."
        )
        if kev:
            remediation = (
                "CISA's Known Exploited Vulnerabilities catalog lists this CVE as "
                "actively exploited in the wild"
                + (f" (added {kev_date_added})" if kev_date_added else "")
                + f". Treat as critical and patch {tech_name} immediately, "
                "regardless of match confidence below. "
            ) + remediation
        if confidence != "confirmed":
            remediation += (
                " Confidence: low — this was matched on product name without a "
                "version-range check (either no version was fingerprinted, or the "
                "CVE record itself carries no version bound), so verify manually "
                "before treating it as a confirmed finding. Note that vendor-patched "
                "or distro-packaged builds can carry a backported fix while still "
                "reporting an older upstream version string."
            )
        remediation += _epss_note(epss_score, epss_percentile)

        findings.append(
            Finding(
                plugin_name=self.get_name(),
                severity=severity,
                title=f"CVE-{cve_id}: {tech_name} vulnerability",
                description=description or "No description available.",
                url=url,
                evidence={
                    "technology": tech_name,
                    "detected_version": tech_version,
                    "cve_id": cve_id,
                    "cvss_score": cvss,
                    "affected_versions": match.get("affected_versions", ""),
                    "confidence": confidence,
                    "kev": kev,
                    "kev_date_added": kev_date_added,
                    "epss_score": epss_score,
                    "epss_percentile": epss_percentile,
                    "references": refs[:3],
                },
                remediation=remediation,
                attack_scenario=guidance["attack"],
                defense_strategy=guidance["defense"],
                mitigation_plan=guidance["mitigation"],
            )
        )

    def scan(self, url_info: Dict, request_handler) -> List[Finding]:
        findings: List[Finding] = []

        if url_info.get("depth", 0) > 0:
            return findings

        url = url_info["url"]
        response = request_handler.get(url)
        if response is None:
            return findings

        tech = fingerprint_technologies(response)
        if not tech:
            return findings

        detected_techs = self._extract_all_technologies(tech)
        found_cves = set()
        cves_per_tech: Dict[str, int] = {}
        MAX_CVES_PER_TECH = 10

        use_sqlite = sqlite_cve_db_available() and query_cves is not None
        entries = []
        if not use_sqlite:
            try:
                db = load_cve_db()
            except Exception:
                return findings
            entries = db.get("entries", [])
            if not entries:
                return findings
            entries = sorted(
                entries,
                key=lambda e: e.get("cvss") or 0,
                reverse=True,
            )

        for tech_entry in detected_techs:
            tech_name = tech_entry["name"]
            tech_version = tech_entry.get("version")

            if tech_name not in cves_per_tech:
                cves_per_tech[tech_name] = 0

            if use_sqlite:
                try:
                    matched = query_cves(tech_name, version=tech_version)
                except Exception:
                    continue
                matched = sorted(
                    matched,
                    key=lambda e: e.get("cvss_score") or 0,
                    reverse=True,
                )
                for cve_row in matched:
                    cve_id = cve_row.get("cve_id", "UNKNOWN")
                    cache_key = f"{tech_name}:{cve_id}"
                    if cache_key in found_cves:
                        continue
                    if cves_per_tech[tech_name] >= MAX_CVES_PER_TECH:
                        break
                    found_cves.add(cache_key)
                    cves_per_tech[tech_name] += 1
                    cvss = cve_row.get("cvss_score")
                    severity = calculate_severity(cvss, cve_id)
                    match = {
                        "matched_product": tech_name,
                        "detected_version": tech_version,
                        "affected_versions": "see NVD advisory",
                        "confidence": cve_row.get("confidence", "low"),
                        "kev": cve_row.get("kev", False),
                        "kev_date_added": cve_row.get("kev_date_added"),
                        "epss_score": cve_row.get("epss_score"),
                        "epss_percentile": cve_row.get("epss_percentile"),
                    }
                    self._append_cve_finding(
                        findings,
                        url,
                        tech_name,
                        tech_version,
                        cve_id,
                        severity,
                        cvss,
                        match,
                        cve_row.get("description", ""),
                        cve_row.get("references"),
                    )
                continue

            for cve_entry in entries:
                cve_id = cve_entry.get("cve_id", "UNKNOWN")

                cache_key = f"{tech_name}:{cve_id}"
                if cache_key in found_cves:
                    continue

                if cves_per_tech[tech_name] >= MAX_CVES_PER_TECH:
                    break

                match = match_technology_to_cve(tech_name, tech_version, cve_entry)
                if not match:
                    continue

                found_cves.add(cache_key)
                cves_per_tech[tech_name] += 1

                cvss = cve_entry.get("cvss")
                severity = calculate_severity(cvss, cve_id)
                self._append_cve_finding(
                    findings,
                    url,
                    tech_name,
                    tech_version,
                    cve_id,
                    severity,
                    cvss,
                    match,
                    cve_entry.get("summary", ""),
                    cve_entry.get("references"),
                )

        return findings
