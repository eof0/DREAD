import re
from typing import Any

from plugins.base_plugin import Finding


SQL_ERRORS = [
    re.compile(pattern, re.I)
    for pattern in (
        r"you have an error in your sql syntax",
        r"warning.*mysql",
        r"postgresql.*error",
        r"sqlite(?:3)?(?:.|\s)*error",
        r"unclosed quotation mark after the character string",
        r"quoted string not properly terminated",
        r"ora-\d{5}",
    )
]


def original_value(value: Any) -> str:
    return str(value[0] if isinstance(value, list) else value)


def finding(
    title: str,
    severity: str,
    endpoint: str,
    parameter: str,
    payload: str,
    reason: str,
    response,
    evidence_payload: str | None = None,
) -> Finding:
    return Finding(
        plugin_name="web_vulnerabilities",
        severity=severity,
        title=f"{title} in parameter '{parameter}'",
        description=f"The GET parameter '{parameter}' is vulnerable to {title.lower()}.",
        url=endpoint,
        evidence={
            "method": "GET",
            "parameter": parameter,
            "payload": evidence_payload or payload,
            "status_code": response.status_code,
            "reason": reason[:500],
        },
        remediation=(
            "Validate input against an allowlist, use context-appropriate output encoding, "
            "and use parameterized APIs instead of constructing commands or queries."
        ),
    )


def mutated(params: dict, parameter: str, payload: str) -> dict:
    result = params.copy()
    result[parameter] = payload
    return result
