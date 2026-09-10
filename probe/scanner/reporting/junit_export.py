"""
JUnit XML Export for CI/CD Integration

Generates JUnit-compatible XML for integration with:
- Jenkins
- GitLab CI
- GitHub Actions
- Azure DevOps
- And other CI/CD tools
"""

import xml.etree.ElementTree as ET
from xml.dom import minidom
from typing import Dict, List
from datetime import datetime


class JUnitExporter:
    """Export scan results to JUnit XML format."""
    
    def __init__(self, report_data: Dict):
        self.report_data = report_data
    
    def _severity_to_status(self, severity: str) -> str:
        """Convert severity to test status."""
        if severity.lower() in ["critical", "high"]:
            return "failure"
        elif severity.lower() == "medium":
            return "failure"  # Or could be "warning" depending on policy
        else:
            return "skipped"  # low/info treated as skipped/pass
    
    def _escape_for_xml(self, text: str) -> str:
        """Escape special characters for XML."""
        if not text:
            return ""
        return (text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&apos;"))
    
    def _format_finding_message(self, finding: Dict) -> str:
        """Format finding as test failure message."""
        lines = []
        lines.append(f"[{finding.get('severity', 'UNKNOWN').upper()}] {finding.get('title', 'Finding')}")
        lines.append("")
        lines.append(f"Description: {finding.get('description', 'N/A')}")
        lines.append(f"URL: {finding.get('url', 'N/A')}")
        lines.append("")
        lines.append(f"Remediation: {finding.get('remediation', 'N/A')}")
        
        # Add evidence summary
        evidence = finding.get("evidence", {})
        if evidence:
            lines.append("")
            lines.append("Evidence:")
            for key, value in evidence.items():
                if isinstance(value, (str, int, float, bool)):
                    lines.append(f"  {key}: {value}")
        
        return "\n".join(lines)
    
    def export(self) -> ET.Element:
        """Generate JUnit XML test suite."""
        # Create root testsuites element
        testsuites = ET.Element("testsuites")
        testsuites.set("name", "Probe Security Scan")
        testsuites.set("tests", str(len(self.report_data.get("findings", []))))
        
        # Create single testsuite for the target
        testsuite = ET.SubElement(testsuites, "testsuite")
        testsuite.set("name", f"Security Scan: {self.report_data.get('target', 'Unknown')}")
        testsuite.set("timestamp", self.report_data.get("timestamp", datetime.now().isoformat()))
        testsuite.set("scan_id", self.report_data.get("scan_id", "unknown"))
        
        findings = self.report_data.get("findings", [])
        testsuite.set("tests", str(len(findings)))
        
        # Count failures (critical/high/medium)
        failures = sum(1 for f in findings if f.get("severity", "").lower() in ["critical", "high", "medium"])
        testsuite.set("failures", str(failures))
        testsuite.set("errors", "0")
        
        # Count skipped (low/info)
        skipped = sum(1 for f in findings if f.get("severity", "").lower() in ["low", "info"])
        testsuite.set("skipped", str(skipped))
        
        # Add each finding as a test case
        for finding in findings:
            testcase = ET.SubElement(testsuite, "testcase")
            
            # Test name is the finding title
            testcase.set("name", finding.get("title", "Unknown Finding"))
            testcase.set("classname", f"security.{finding.get('plugin_name', 'general')}")
            testcase.set("time", "0")  # Scans don't have individual timing
            
            # Add URL as system-out for reference
            system_out = ET.SubElement(testcase, "system-out")
            system_out.text = self._escape_for_xml(f"URL: {finding.get('url', 'N/A')}")
            
            # Add severity as property
            properties = ET.SubElement(testcase, "properties")
            severity_prop = ET.SubElement(properties, "property")
            severity_prop.set("name", "severity")
            severity_prop.set("value", finding.get("severity", "unknown"))
            
            # Add risk score if available
            risk_score = finding.get("risk_score")
            if risk_score:
                risk_prop = ET.SubElement(properties, "property")
                risk_prop.set("name", "risk_score")
                risk_prop.set("value", str(risk_score))
            
            # Add failure/skip based on severity
            status = self._severity_to_status(finding.get("severity", "info"))
            
            if status == "failure":
                failure = ET.SubElement(testcase, "failure")
                failure.set("type", finding.get("severity", "unknown").upper())
                failure.set("message", self._escape_for_xml(finding.get("title", "Security Finding")))
                failure.text = self._escape_for_xml(self._format_finding_message(finding))
            
            elif status == "skipped":
                skipped_elem = ET.SubElement(testcase, "skipped")
                skipped_elem.set("message", "Low severity / Informational")
                skipped_elem.text = self._escape_for_xml(finding.get("description", ""))
        
        # Add summary as properties
        stats = self.report_data.get("statistics", {})
        suite_props = ET.SubElement(testsuite, "properties")
        
        props_to_add = [
            ("target", self.report_data.get("target", "unknown")),
            ("total_findings", str(stats.get("total_findings", 0))),
            ("critical_count", str(stats.get("findings_by_severity", {}).get("critical", 0))),
            ("high_count", str(stats.get("findings_by_severity", {}).get("high", 0))),
            ("medium_count", str(stats.get("findings_by_severity", {}).get("medium", 0))),
            ("low_count", str(stats.get("findings_by_severity", {}).get("low", 0))),
            ("info_count", str(stats.get("findings_by_severity", {}).get("info", 0))),
            ("risk_level", stats.get("risk", {}).get("level", "unknown")),
            ("risk_score", str(stats.get("risk", {}).get("normalized_score", 0))),
        ]
        
        for name, value in props_to_add:
            prop = ET.SubElement(suite_props, "property")
            prop.set("name", name)
            prop.set("value", value)
        
        return testsuites
    
    def export_to_string(self) -> str:
        """Export as formatted XML string."""
        root = self.export()
        
        # Convert to string
        rough_string = ET.tostring(root, encoding="unicode")
        
        # Pretty print
        reparsed = minidom.parseString(rough_string)
        return reparsed.toprettyxml(indent="  ")
    
    def export_to_file(self, output_path: str) -> str:
        """Export to file."""
        xml_string = self.export_to_string()
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(xml_string)
        return output_path


def export_to_junit(report_data: Dict, output_path: str) -> str:
    """Convenience function to export to JUnit XML."""
    exporter = JUnitExporter(report_data)
    return exporter.export_to_file(output_path)
