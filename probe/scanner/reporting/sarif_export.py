"""
SARIF (Static Analysis Results Interchange Format) Export

Generates SARIF v2.1.0 compatible output for integration with:
- GitHub Advanced Security
- Azure DevOps
- Other SARIF-compatible tools
"""

import json
from typing import Dict, List, Any
from datetime import datetime


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


class SARIFExporter:
    """Export scan results to SARIF format."""
    
    def __init__(self, report_data: Dict):
        self.report_data = report_data
        self.rules = {}  # RuleId -> Rule definition
        self.results = []  # SARIF results
    
    def _severity_to_sarif_level(self, severity: str) -> str:
        """Convert Probe severity to SARIF level."""
        mapping = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note",
        }
        return mapping.get(severity.lower(), "warning")
    
    def _severity_to_rank(self, severity: str) -> float:
        """Convert severity to SARIF rank (0-100)."""
        mapping = {
            "critical": 95.0,
            "high": 75.0,
            "medium": 50.0,
            "low": 25.0,
            "info": 10.0,
        }
        return mapping.get(severity.lower(), 50.0)
    
    def _generate_rule_id(self, finding: Dict) -> str:
        """Generate unique rule ID for finding type."""
        plugin = finding.get("plugin_name", "unknown")
        title = finding.get("title", "finding")
        
        # Create rule ID from plugin and first few words of title
        title_part = "_".join(title.lower().split()[:3])
        title_part = "".join(c if c.isalnum() else "_" for c in title_part)
        
        return f"PROBE_{plugin.upper()}_{title_part.upper()}"
    
    def _create_rule(self, rule_id: str, finding: Dict) -> Dict:
        """Create SARIF rule definition."""
        severity = finding.get("severity", "medium")
        
        rule = {
            "id": rule_id,
            "name": finding.get("title", "Finding"),
            "shortDescription": {
                "text": finding.get("title", "Security Finding")
            },
            "fullDescription": {
                "text": finding.get("description", "No description provided.")
            },
            "defaultConfiguration": {
                "level": self._severity_to_sarif_level(severity),
                "rank": self._severity_to_rank(severity),
            },
            "help": {
                "text": finding.get("remediation", "No remediation guidance provided."),
                "markdown": self._generate_help_markdown(finding),
            },
            "properties": {
                "tags": [
                    "security",
                    finding.get("plugin_name", "general"),
                    severity,
                ],
                "precision": "high",
            }
        }
        
        # Add CWE if available (you'd need to map findings to CWEs)
        # rule["relationships"] = [{"target": {"id": "CWE-XX", ...}}]
        
        return rule
    
    def _generate_help_markdown(self, finding: Dict) -> str:
        """Generate help content in Markdown."""
        lines = []
        lines.append(f"## {finding.get('title', 'Finding')}")
        lines.append("")
        lines.append(f"**Severity:** {finding.get('severity', 'unknown').upper()}")
        lines.append("")
        lines.append("### Description")
        lines.append(finding.get("description", "No description available."))
        lines.append("")
        
        if finding.get("attack_scenario"):
            lines.append("### Attack Scenario")
            lines.append(finding["attack_scenario"])
            lines.append("")
        
        if finding.get("defense_strategy"):
            lines.append("### Defense Strategy")
            lines.append(finding["defense_strategy"])
            lines.append("")
        
        lines.append("### Remediation")
        lines.append(finding.get("remediation", "No remediation guidance available."))
        
        return "\n".join(lines)
    
    def _create_result(self, finding: Dict, rule_id: str) -> Dict:
        """Create SARIF result entry."""
        severity = finding.get("severity", "medium")
        url = finding.get("url", "")
        
        result = {
            "ruleId": rule_id,
            "ruleIndex": list(self.rules.keys()).index(rule_id),
            "level": self._severity_to_sarif_level(severity),
            "message": {
                "text": finding.get("description", "Security issue detected."),
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": url,
                            "description": {
                                "text": "Affected URL"
                            }
                        },
                    }
                }
            ],
            "properties": {
                "rank": self._severity_to_rank(severity),
            }
        }
        
        # Add evidence as additional properties
        evidence = finding.get("evidence", {})
        if evidence:
            result["properties"]["evidence"] = evidence
        
        # Add fingerprint for deduplication
        result["partialFingerprints"] = {
            "primaryLocationLineHash": self._generate_fingerprint(finding),
        }
        
        return result
    
    def _generate_fingerprint(self, finding: Dict) -> str:
        """Generate fingerprint for result deduplication."""
        import hashlib
        data = f"{finding.get('plugin_name')}:{finding.get('title')}:{finding.get('url')}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    def export(self) -> Dict:
        """Generate complete SARIF document."""
        # Process all findings
        for finding in self.report_data.get("findings", []):
            rule_id = self._generate_rule_id(finding)
            
            # Add rule if not exists
            if rule_id not in self.rules:
                self.rules[rule_id] = self._create_rule(rule_id, finding)
            
            # Add result
            self.results.append(self._create_result(finding, rule_id))
        
        # Build SARIF document
        sarif = {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Probe",
                            "informationUri": "https://github.com/eof0/DREAD",
                            "version": "1.0.0",
                            "rules": list(self.rules.values()),
                        }
                    },
                    "results": self.results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": self.report_data.get("timestamp", datetime.now().isoformat()),
                        }
                    ],
                    "properties": {
                        "target": self.report_data.get("target"),
                        "scanId": self.report_data.get("scan_id"),
                        "statistics": self.report_data.get("statistics", {}),
                    }
                }
            ]
        }
        
        return sarif
    
    def export_to_file(self, output_path: str):
        """Export SARIF to file."""
        sarif_data = self.export()
        with open(output_path, 'w') as f:
            json.dump(sarif_data, f, indent=2)
        return output_path


def export_to_sarif(report_data: Dict, output_path: str) -> str:
    """Convenience function to export report to SARIF."""
    exporter = SARIFExporter(report_data)
    return exporter.export_to_file(output_path)
