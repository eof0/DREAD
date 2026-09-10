from typing import List, Dict, Any

EDGE_REDUCTION_FACTOR = 0.2  # 20% weight if edge infrastructure


def prioritize_findings(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Calculates raw and adjusted risk scores.
    Raw = full score (assume findings are real)
    Adjusted = reduced score for edge-only findings
    """

    raw_total = 0.0
    adjusted_total = 0.0

    prioritized = []

    for finding in findings:
        risk = finding.get("risk_score", 0.0)

        metadata = finding.get("metadata", {}) or {}
        evidence = finding.get("evidence", {}) or {}
        is_edge = metadata.get("edge_infrastructure", evidence.get("edge_infrastructure", False))

        raw_total += risk

        if is_edge:
            adjusted_risk = risk * EDGE_REDUCTION_FACTOR
        else:
            adjusted_risk = risk

        adjusted_total += adjusted_risk

        finding_copy = finding.copy()
        finding_copy["edge_infrastructure"] = is_edge
        finding_copy["raw_risk_score"] = risk
        finding_copy["adjusted_risk_score"] = round(adjusted_risk, 2)

        prioritized.append(finding_copy)

    return {
        "raw_risk_score": round(raw_total, 2),
        "adjusted_risk_score": round(adjusted_total, 2),
        "findings": prioritized,
    }
