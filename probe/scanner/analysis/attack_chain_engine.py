# scanner/analysis/attack_chain_engine.py

from typing import List, Dict
from .attack_chains import ATTACK_CHAINS


def build_attack_chains(findings: List) -> List[Dict]:
    """
    Takes all findings and groups them into high-level attack chains
    based on keyword presence.
    """
    results = []

    for chain in ATTACK_CHAINS:
        matched_findings = []

        for finding in findings:
            finding_data = finding if isinstance(finding, dict) else finding.to_dict()
            text = (
                finding_data["title"] + " " + finding_data["description"]
            ).lower()

            if any(keyword.lower() in text for keyword in chain["indicator_keywords"]):
                matched_findings.append(finding_data)

        if matched_findings:
            results.append({
                "id": chain["id"],
                "title": chain["title"],
                "kill_chain_stage": chain["kill_chain_stage"],
                "business_impact": chain["business_impact"],
                "related_findings": matched_findings
            })

    return results
