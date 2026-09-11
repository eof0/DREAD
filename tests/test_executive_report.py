"""Executive summary: plain-language, vulnerabilities first, observations summarized, no internal names, no JSON."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPORTS = Path(__file__).resolve().parent.parent / "reports"

INTERNAL_NAMES = ("DREAD", "Probe", "Scope", "probe_01", "product suite", "web_vulnerabilities",
                  "plugin", "cve_correlation", "s3_buckets")


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


def _report(vulns=(), observations=0, overall_risk="none"):
    findings = list(vulns) + [
        {"severity": "info", "classification": "observation", "title": f"Obs {i}",
         "plugin_name": "network_scanner", "url": f"u{i}"}
        for i in range(observations)
    ]
    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vulns:
        by_sev[v["severity"]] = by_sev.get(v["severity"], 0) + 1
    return {
        "reports_schema_version": "1.0",
        "title": "Recon/Vuln Analysis - Report Findings - September 11, 2026",
        "target": "https://ryanwilson.io",
        "run_id": "run-1",
        "generated_at": "2026-09-11T05:00:00+00:00",
        "checks_performed": ["security_headers", "web_vulnerabilities", "tls_analysis"],
        "sources": {"probe": {"included": True, "scans": [{"target": "https://ryanwilson.io"}]},
                    "scope": {"included": True, "summary": {"subdomain_count": 2, "cloud_bucket_counts": {}}}},
        "rollups": {
            "total_findings": len(findings),
            "vulnerability_count": len(vulns),
            "observation_count": observations,
            "vulnerabilities_by_severity": by_sev,
            "overall_risk": overall_risk,
            "findings_by_severity": {**by_sev, "info": observations},
        },
        "findings": findings,
    }


def test_clean_scan_reads_reassuring_and_summarizes_observations(tmp_path):
    from writers.executive import write_executive_html

    doc = write_executive_html(_report(observations=9), tmp_path, "executive_summary").read_text()

    assert "No vulnerabilities were found" in doc
    assert "9" in doc  # observations summarized as a count
    assert "Obs 0" not in doc  # individual observations NOT listed one by one
    for name in INTERNAL_NAMES:
        assert name not in doc, name


def test_vulnerabilities_are_explained_in_plain_language_with_urgency(tmp_path):
    from writers.executive import write_executive_html

    vuln = {"severity": "critical", "classification": "vulnerability",
            "title": "SQL Injection Error in parameter 'id'", "plugin_name": "web_vulnerabilities",
            "url": "https://ryanwilson.io/item?id=1"}
    doc = write_executive_html(_report(vulns=[vuln], overall_risk="critical"), tmp_path, "e").read_text()

    assert "database" in doc.lower()          # plain-language explanation, not the raw title
    assert "Fix immediately" in doc           # urgency for critical
    assert "SELECT" not in doc                 # no payloads/technical detail in the exec summary
    for name in INTERNAL_NAMES:
        assert name not in doc, name


def test_executive_pdf_renders(tmp_path):
    from writers.executive import write_executive_pdf

    vuln = {"severity": "high", "classification": "vulnerability",
            "title": "Reflected XSS in parameter 'q'", "plugin_name": "web_vulnerabilities",
            "url": "https://ryanwilson.io/s?q=1"}
    p = write_executive_pdf(_report(vulns=[vuln], observations=3, overall_risk="high"), tmp_path, "e")

    assert p.is_file() and p.stat().st_size > 800
