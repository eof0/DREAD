from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional


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

MAX_RAW_RISK = 10 * 8
RISK_SCALE_FACTOR = 100 / MAX_RAW_RISK


class Finding:
    def __init__(
        self,
        plugin_name: str,
        severity: str,
        title: str,
        description: str,
        url: str,
        evidence: Optional[Dict[str, Any]] = None,
        remediation: Optional[str] = None,
        attack_scenario: Optional[str] = None,
        defense_strategy: Optional[str] = None,
        mitigation_plan: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.plugin_name = plugin_name
        self.severity = (severity or "medium").lower()
        self.title = title
        self.description = description
        self.url = url
        self.evidence = evidence or {}
        self.remediation = remediation or ""
        self.attack_scenario = attack_scenario or ""
        self.defense_strategy = defense_strategy or ""
        self.mitigation_plan = mitigation_plan or ""
        self.metadata = metadata or {}

    def computed_risk_score(self, exposure: float = 1.0) -> float:
        impact = SEVERITY_TO_IMPACT.get(self.severity, 4)
        likelihood = SEVERITY_TO_LIKELIHOOD.get(self.severity, 4)
        raw = impact * likelihood * exposure
        score = raw * RISK_SCALE_FACTOR
        return round(min(score, 100.0), 2)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plugin_name": self.plugin_name,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "url": self.url,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "attack_scenario": self.attack_scenario,
            "defense_strategy": self.defense_strategy,
            "mitigation_plan": self.mitigation_plan,
            "metadata": self.metadata,
            "risk_score": self.computed_risk_score(),
        }


class BasePlugin(ABC):
    version = "1.0.0"

    @abstractmethod
    def get_name(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def get_description(self) -> str:
        raise NotImplementedError

    def get_version(self) -> str:
        return self.version

    @abstractmethod
    def scan(self, url_info: Dict[str, Any], request_handler) -> List[Finding]:
        raise NotImplementedError
