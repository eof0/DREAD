from typing import Dict


SEVERITY_TO_IMPACT = {
    "info": 1,
    "low": 2,
    "medium": 4,
    "high": 7,
    "critical": 10,
}

SEVERITY_TO_LIKELIHOOD = {
    "info": 1,
    "low": 2,
    "medium": 4,
    "high": 6,
    "critical": 8,
}


def calculate_risk(
    severity: str,
    exposure: float = 1.0,
) -> Dict[str, float]:
    """
    Calculate risk score using:
      risk = impact × likelihood × exposure
    """

    severity = severity.lower()

    impact = SEVERITY_TO_IMPACT.get(severity, 4)
    likelihood = SEVERITY_TO_LIKELIHOOD.get(severity, 4)

    risk = round(impact * likelihood * exposure, 2)

    return {
        "impact": impact,
        "likelihood": likelihood,
        "exposure": exposure,
        "risk_score": risk,
    }
