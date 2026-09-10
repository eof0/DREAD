"""
Baseline Comparison Module

Compares current scan results against a baseline to identify:
- NEW issues (not in baseline)
- RESOLVED issues (in baseline but not current)
- CHANGED issues (same finding but different severity/details)
"""

import json
import hashlib
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from pathlib import Path


class FindingHasher:
    """Creates stable hashes for findings to enable comparison."""
    
    @staticmethod
    def hash_finding(finding: Dict) -> str:
        """
        Create a stable hash for a finding based on key identifying fields.
        This allows us to track the same finding across scans.
        """
        # Use fields that identify the specific issue
        key_parts = [
            finding.get("plugin_name", ""),
            finding.get("title", ""),
            finding.get("url", ""),
            finding.get("severity", ""),
        ]
        
        # Include evidence keys that identify this specific issue
        evidence = finding.get("evidence", {})
        if "port" in evidence:
            key_parts.append(f"port:{evidence['port']}")
        if "path" in evidence:
            key_parts.append(f"path:{evidence['path']}")
        if "cve_id" in evidence:
            key_parts.append(f"cve:{evidence['cve_id']}")
        if "technology" in evidence:
            key_parts.append(f"tech:{evidence['technology']}")
        
        key_string = "|".join(key_parts)
        return hashlib.md5(key_string.encode()).hexdigest()


class BaselineComparator:
    """Compares scan results against a baseline."""
    
    def __init__(self, baseline_path: Optional[str] = None):
        self.baseline_path = baseline_path
        self.baseline_data = self._load_baseline()
    
    def _load_baseline(self) -> Optional[Dict]:
        """Load baseline scan data from file."""
        if not self.baseline_path:
            return None
        
        path = Path(self.baseline_path)
        if not path.exists():
            return None
        
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except Exception:
            return None
    
    def _extract_findings(self, scan_data: Dict) -> Dict[str, Dict]:
        """Extract findings keyed by their hash."""
        findings = {}
        for finding in scan_data.get("findings", []):
            finding_hash = FindingHasher.hash_finding(finding)
            findings[finding_hash] = finding
        return findings
    
    def compare(self, current_scan: Dict) -> Dict:
        """
        Compare current scan against baseline.
        
        Returns:
            Dict with:
            - new_findings: List of findings not in baseline
            - resolved_findings: List of findings in baseline but not current
            - unchanged_findings: List of findings present in both
            - changed_findings: List of findings with modifications
        """
        if not self.baseline_data:
            # No baseline - everything is new
            return {
                "new_findings": current_scan.get("findings", []),
                "resolved_findings": [],
                "unchanged_findings": [],
                "changed_findings": [],
                "baseline_date": None,
                "comparison_date": datetime.now().isoformat(),
            }
        
        baseline_findings = self._extract_findings(self.baseline_data)
        current_findings = self._extract_findings(current_scan)
        
        new_findings = []
        resolved_findings = []
        unchanged_findings = []
        changed_findings = []
        
        # Find new and changed findings
        for finding_hash, finding in current_findings.items():
            if finding_hash not in baseline_findings:
                new_findings.append(finding)
            else:
                # Check if details changed
                baseline_finding = baseline_findings[finding_hash]
                if self._finding_changed(baseline_finding, finding):
                    changed_findings.append({
                        "previous": baseline_finding,
                        "current": finding,
                        "changes": self._get_changes(baseline_finding, finding),
                    })
                else:
                    unchanged_findings.append(finding)
        
        # Find resolved findings (in baseline but not current)
        for finding_hash, finding in baseline_findings.items():
            if finding_hash not in current_findings:
                resolved_findings.append(finding)
        
        return {
            "new_findings": new_findings,
            "resolved_findings": resolved_findings,
            "unchanged_findings": unchanged_findings,
            "changed_findings": changed_findings,
            "baseline_date": self.baseline_data.get("timestamp"),
            "comparison_date": datetime.now().isoformat(),
            "baseline_scan_id": self.baseline_data.get("scan_id"),
            "current_scan_id": current_scan.get("scan_id"),
        }
    
    def _finding_changed(self, baseline: Dict, current: Dict) -> bool:
        """Check if a finding has changed between scans."""
        # Compare severity
        if baseline.get("severity") != current.get("severity"):
            return True
        
        # Compare risk score
        baseline_score = baseline.get("risk_score") or baseline.get("evidence", {}).get("cvss")
        current_score = current.get("risk_score") or current.get("evidence", {}).get("cvss")
        if baseline_score != current_score:
            return True
        
        return False
    
    def _get_changes(self, baseline: Dict, current: Dict) -> List[str]:
        """Get list of specific changes between findings."""
        changes = []
        
        if baseline.get("severity") != current.get("severity"):
            changes.append(f"Severity: {baseline['severity']} → {current['severity']}")
        
        baseline_score = baseline.get("risk_score")
        current_score = current.get("risk_score")
        if baseline_score != current_score:
            changes.append(f"Risk Score: {baseline_score} → {current_score}")
        
        return changes
    
    def save_baseline(self, scan_data: Dict, output_path: str):
        """Save current scan as new baseline."""
        baseline = {
            "scan_id": scan_data.get("scan_id"),
            "timestamp": datetime.now().isoformat(),
            "target": scan_data.get("target"),
            "findings": scan_data.get("findings", []),
            "statistics": scan_data.get("statistics", {}),
        }
        
        with open(output_path, 'w') as f:
            json.dump(baseline, f, indent=2)
        
        return output_path


def format_comparison_report(comparison: Dict) -> str:
    """Format comparison results as human-readable text."""
    lines = []
    
    lines.append("=" * 60)
    lines.append("BASELINE COMPARISON REPORT")
    lines.append("=" * 60)
    lines.append(f"Baseline Date: {comparison.get('baseline_date', 'N/A')}")
    lines.append(f"Comparison Date: {comparison['comparison_date']}")
    lines.append("")
    
    # Summary
    new_count = len(comparison.get("new_findings", []))
    resolved_count = len(comparison.get("resolved_findings", []))
    changed_count = len(comparison.get("changed_findings", []))
    unchanged_count = len(comparison.get("unchanged_findings", []))
    
    lines.append("SUMMARY")
    lines.append("-" * 40)
    lines.append(f"New Findings: {new_count}")
    lines.append(f"Resolved Findings: {resolved_count}")
    lines.append(f"Changed Findings: {changed_count}")
    lines.append(f"Unchanged Findings: {unchanged_count}")
    lines.append("")
    
    # New findings (most important)
    if new_count > 0:
        lines.append("🆕 NEW FINDINGS (Require Attention)")
        lines.append("-" * 40)
        for finding in comparison["new_findings"]:
            severity = finding.get("severity", "unknown").upper()
            title = finding.get("title", "Unknown")
            lines.append(f"  [{severity}] {title}")
        lines.append("")
    
    # Resolved findings (good news)
    if resolved_count > 0:
        lines.append("✅ RESOLVED FINDINGS (Fixed)")
        lines.append("-" * 40)
        for finding in comparison["resolved_findings"]:
            title = finding.get("title", "Unknown")
            lines.append(f"  ✓ {title}")
        lines.append("")
    
    # Changed findings
    if changed_count > 0:
        lines.append("⚠️  CHANGED FINDINGS")
        lines.append("-" * 40)
        for change in comparison["changed_findings"]:
            current = change["current"]
            title = current.get("title", "Unknown")
            changes = ", ".join(change["changes"])
            lines.append(f"  {title}")
            lines.append(f"    Changes: {changes}")
        lines.append("")
    
    return "\n".join(lines)


# CLI integration helper
def add_baseline_arguments(parser):
    """Add baseline comparison arguments to CLI parser."""
    parser.add_argument(
        "--baseline",
        metavar="PATH",
        help="Path to baseline scan JSON for comparison",
    )
    parser.add_argument(
        "--save-baseline",
        metavar="PATH",
        help="Save current scan as new baseline to PATH",
    )
    parser.add_argument(
        "--baseline-report",
        action="store_true",
        help="Generate baseline comparison report",
    )
