from typing import Any, Dict, List


SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def group_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    groups = {}
    for finding in findings:
        key = tuple(
            finding.get(field, "")
            for field in (
                "plugin_name",
                "title",
                "severity",
                "description",
                "remediation",
            )
        )
        groups.setdefault(key, []).append(finding)

    grouped = []
    for matches in groups.values():
        endpoints = sorted({item.get("url", "") for item in matches if item.get("url")})
        first = min(matches, key=lambda item: item.get("url", "")).copy()
        first["affected_endpoints"] = endpoints
        first["endpoint_count"] = len(endpoints)
        if endpoints:
            first["url"] = endpoints[0]
        grouped.append(first)

    return sorted(
        grouped,
        key=lambda finding: (
            SEVERITY_ORDER.get(finding.get("severity", ""), len(SEVERITY_ORDER)),
            finding.get("title", "").lower(),
            finding.get("url", ""),
        ),
    )
