"""
Executive Summary Report Generator

Generates business-focused security summaries suitable for:
- C-level executives
- Board reports
- Compliance documentation
- Risk management teams
"""

import json
from typing import Dict, List
from datetime import datetime


class ExecutiveSummaryGenerator:
    """Generate business-focused executive summaries."""
    
    def __init__(self, report_data: Dict):
        self.report_data = report_data
        self.stats = report_data.get("statistics", {})
        self.risk = self.stats.get("risk", {})
        self.findings = report_data.get("findings", [])
    
    def _get_risk_color(self, level: str) -> str:
        """Get color code for risk level."""
        colors = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "⚪",
        }
        return colors.get(level.lower(), "⚪")
    
    def _count_by_severity(self, severity: str) -> int:
        """Count findings by severity."""
        return self.stats.get("findings_by_severity", {}).get(severity, 0)
    
    def _get_top_risks(self, count: int = 5) -> List[Dict]:
        """Get top risks sorted by severity."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        
        sorted_findings = sorted(
            self.findings,
            key=lambda f: (severity_order.get(f.get("severity", "info"), 99), -(f.get("risk_score", 0) or 0))
        )
        
        return sorted_findings[:count]
    
    def _calculate_business_impact(self) -> Dict:
        """Calculate potential business impact."""
        impact = {
            "data_breach_risk": False,
            "compliance_issues": [],
            "reputation_risk": False,
            "service_disruption": False,
        }
        
        for finding in self.findings:
            title = finding.get("title", "").lower()
            
            # Check for data breach risks
            if any(term in title for term in ["sql", "database", "exposed", "backup", "dump"]):
                impact["data_breach_risk"] = True
            
            # Check for compliance issues
            if "tls" in title or "ssl" in title or "certificate" in title:
                impact["compliance_issues"].append("Data Encryption (PCI DSS, GDPR)")
            
            # Reputation risk
            if finding.get("severity") in ["critical", "high"]:
                impact["reputation_risk"] = True
            
            # Service disruption
            if any(term in title for term in ["dos", "denial", "crash", "infinite"]):
                impact["service_disruption"] = True
        
        # Remove duplicates
        impact["compliance_issues"] = list(set(impact["compliance_issues"]))
        
        return impact
    
    def generate_text(self) -> str:
        """Generate plain text executive summary."""
        lines = []
        
        # Header
        lines.append("=" * 70)
        lines.append("EXECUTIVE SECURITY SUMMARY")
        lines.append("=" * 70)
        lines.append(f"Target: {self.report_data.get('target', 'Unknown')}")
        lines.append(f"Date: {self.report_data.get('timestamp', datetime.now().isoformat())}")
        lines.append(f"Scan ID: {self.report_data.get('scan_id', 'N/A')}")
        lines.append("")
        
        # Overall Risk
        risk_level = self.risk.get("level", "unknown")
        risk_score = self.risk.get("normalized_score", 0)
        risk_emoji = self._get_risk_color(risk_level)
        
        lines.append("OVERALL SECURITY POSTURE")
        lines.append("-" * 40)
        lines.append(f"{risk_emoji} Risk Level: {risk_level.upper()}")
        lines.append(f"📊 Risk Score: {risk_score}/100")
        lines.append("")
        
        # Quick Stats
        lines.append("FINDINGS SUMMARY")
        lines.append("-" * 40)
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = self._count_by_severity(sev)
            emoji = self._get_risk_color(sev)
            lines.append(f"{emoji} {sev.upper()}: {count}")
        lines.append(f"\n📋 Total Issues: {len(self.findings)}")
        lines.append("")
        
        # Business Impact
        impact = self._calculate_business_impact()
        lines.append("BUSINESS IMPACT ASSESSMENT")
        lines.append("-" * 40)
        
        if impact["data_breach_risk"]:
            lines.append("⚠️  DATA BREACH RISK DETECTED")
            lines.append("   - Vulnerabilities could lead to unauthorized data access")
        
        if impact["reputation_risk"]:
            lines.append("⚠️  REPUTATION RISK")
            lines.append("   - Critical/High issues could damage brand if exploited")
        
        if impact["service_disruption"]:
            lines.append("⚠️  SERVICE DISRUPTION RISK")
            lines.append("   - Availability-threatening vulnerabilities detected")
        
        if impact["compliance_issues"]:
            lines.append("⚠️  COMPLIANCE IMPLICATIONS")
            for issue in impact["compliance_issues"]:
                lines.append(f"   - {issue}")
        
        if not any(impact.values()):
            lines.append("✅ No immediate business risks identified")
        
        lines.append("")
        
        # Top Risks
        top_risks = self._get_top_risks(3)
        if top_risks:
            lines.append("TOP PRIORITY ISSUES")
            lines.append("-" * 40)
            for i, finding in enumerate(top_risks, 1):
                sev = finding.get("severity", "unknown").upper()
                title = finding.get("title", "Unknown")
                lines.append(f"{i}. [{sev}] {title}")
            lines.append("")
        
        # Recommendations
        lines.append("EXECUTIVE RECOMMENDATIONS")
        lines.append("-" * 40)
        
        if self._count_by_severity("critical") > 0:
            lines.append("🔴 CRITICAL: Address immediately (within 24 hours)")
            lines.append("   - Schedule emergency maintenance window")
            lines.append("   - Consider taking affected systems offline if necessary")
        
        if self._count_by_severity("high") > 0:
            lines.append("🟠 HIGH: Address within 1 week")
            lines.append("   - Prioritize based on business impact")
            lines.append("   - Assign dedicated remediation resources")
        
        if self._count_by_severity("medium") > 5:
            lines.append("🟡 MEDIUM: Address within 1 month")
            lines.append("   - Include in next sprint/release cycle")
        
        lines.append("")
        lines.append("COMPLIANCE & GOVERNANCE")
        lines.append("-" * 40)
        lines.append("• Document all findings in risk register")
        lines.append("• Assign risk owners for each critical/high finding")
        lines.append("• Schedule follow-up scan to verify remediation")
        lines.append("• Update security policies based on findings")
        
        return "\n".join(lines)
    
    def generate_json(self) -> Dict:
        """Generate JSON format for programmatic use."""
        impact = self._calculate_business_impact()
        
        return {
            "report_type": "executive_summary",
            "target": self.report_data.get("target"),
            "scan_date": self.report_data.get("timestamp"),
            "scan_id": self.report_data.get("scan_id"),
            "executive_summary": {
                "risk_level": self.risk.get("level"),
                "risk_score": self.risk.get("normalized_score"),
                "findings_count": {
                    "critical": self._count_by_severity("critical"),
                    "high": self._count_by_severity("high"),
                    "medium": self._count_by_severity("medium"),
                    "low": self._count_by_severity("low"),
                    "info": self._count_by_severity("info"),
                    "total": len(self.findings),
                },
            },
            "business_impact": impact,
            "top_priorities": [
                {
                    "severity": f.get("severity"),
                    "title": f.get("title"),
                    "url": f.get("url"),
                }
                for f in self._get_top_risks(5)
            ],
            "recommendations": self._generate_recommendations(),
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Generate actionable recommendations."""
        recs = []
        
        if self._count_by_severity("critical") > 0:
            recs.append("Immediate action required: Address critical vulnerabilities")
        
        if self._count_by_severity("high") > 0:
            recs.append("High priority: Schedule remediation within 1 week")
        
        if len(self.findings) > 20:
            recs.append("Consider implementing automated security scanning in CI/CD pipeline")
        
        recs.append("Schedule follow-up scan in 30 days to verify remediation")
        
        return recs
    
    def export_to_file(self, output_path: str, format: str = "text") -> str:
        """Export to file."""
        if format == "json":
            content = json.dumps(self.generate_json(), indent=2)
        else:
            content = self.generate_text()
        
        with open(output_path, 'w') as f:
            f.write(content)
        
        return output_path


def generate_executive_summary(report_data: Dict, output_path: str, format: str = "text") -> str:
    """Convenience function."""
    generator = ExecutiveSummaryGenerator(report_data)
    return generator.export_to_file(output_path, format)
