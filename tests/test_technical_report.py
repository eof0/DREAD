"""Technical report: vulnerabilities vs. observations, remediation + evidence, methodology, JSON companion."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPORTS = Path(__file__).resolve().parent.parent / "reports"


@pytest.fixture(autouse=True)
def _reports_path() -> None:
    s = str(REPORTS)
    if s not in sys.path:
        sys.path.insert(0, s)
    yield
    try:
        sys.path.remove(s)
    except ValueError:
        pass


def _report():
    return {
        "reports_schema_version": "1.0",
        "title": "Recon/Vuln Analysis - Report Findings - September 11, 2026",
        "target": "https://ryanwilson.io",
        "run_id": "run-1",
        "generated_at": "2026-09-11T05:00:00+00:00",
        "checks_performed": ["security_headers", "web_vulnerabilities", "tls_analysis"],
        "sources": {"probe": {"included": True, "scans": [{"target": "https://ryanwilson.io", "finding_count": 2}]},
                    "scope": {"included": False, "summary": None}},
        "rollups": {
            "total_findings": 2,
            "vulnerability_count": 1,
            "observation_count": 1,
            "vulnerabilities_by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0},
            "findings_by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 1},
            "overall_risk": "high",
        },
        "findings": [
            {"severity": "high", "classification": "vulnerability", "title": "SQL Injection Error in parameter 'id'",
             "plugin_name": "web_vulnerabilities", "url": "https://ryanwilson.io/i?id=1",
             "description": "d", "remediation": "Use parameterized queries.",
             "evidence": {"parameter": "id", "payload": "id' ", "status_code": 500},
             "affected_endpoints": ["https://ryanwilson.io/i?id=1"]},
            {"severity": "info", "classification": "observation", "title": "Technology Fingerprinting",
             "plugin_name": "fingerprinting", "url": "https://ryanwilson.io", "description": "d",
             "remediation": "", "evidence": {}, "affected_endpoints": []},
        ],
    }


def test_html_separates_vulnerabilities_from_observations(tmp_path):
    from writers.html_writer import write_suite_html

    doc = write_suite_html(_report(), tmp_path, "technical_report").read_text()

    assert "1 vulnerability" in doc or "Vulnerabilities (1)" in doc
    # The heading and the vuln appear before the observations section.
    assert doc.index("SQL Injection") < doc.index("Technology Fingerprinting")
    assert "Observations" in doc
    assert "Total Issues" not in doc


def test_html_shows_remediation_and_evidence_for_the_it_reader(tmp_path):
    from writers.html_writer import write_suite_html

    doc = write_suite_html(_report(), tmp_path, "technical_report").read_text()

    assert "Use parameterized queries." in doc
    assert "id&#x27; " in doc or "id' " in doc  # payload shown (possibly HTML-escaped)


def test_html_lists_checks_performed(tmp_path):
    from writers.html_writer import write_suite_html

    doc = write_suite_html(_report(), tmp_path, "technical_report").read_text()

    assert "security_headers" in doc and "web_vulnerabilities" in doc


def test_technical_json_omits_raw_embed_and_suite_key(tmp_path):
    from writers.json_writer import write_technical_json

    full = {**_report(), "suite": "DREAD", "raw_embed": {"probe": [{"big": "x"}]}}
    p = write_technical_json(full, tmp_path, "technical_report")
    data = json.loads(p.read_text())

    assert "raw_embed" not in data
    assert "suite" not in data
    assert data["findings"][0]["remediation"] == "Use parameterized queries."
