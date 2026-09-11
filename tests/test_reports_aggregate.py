"""Reports aggregation logic (reports/ uses flat imports; path shim for tests)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
REPORTS = REPO / "reports"


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


def test_build_unified_report_probe_only() -> None:
    from aggregate import build_unified_report

    bp = (
        "scan_a",
        {
            "scan_id": "s1",
            "target": "https://a.example",
            "findings": [
                {
                    "severity": "high",
                    "title": "X",
                    "url": "",
                    "plugin_name": "p",
                    "description": "",
                }
            ],
            "statistics": {},
        },
    )
    r = build_unified_report(
        reports_schema_version="1.0",
        run_id="r-test",
        title="T",
        probe_reports=[bp],
        scope_report=None,
        include_probe=True,
        include_scope=False,
    )
    assert r["report_type"] == "unified_suite"
    assert len(r["findings"]) == 1
    assert r["rollups"]["total_findings"] == 1
    assert r["rollups"]["findings_by_severity"]["high"] == 1
    summed = sum(
        v
        for v in r["rollups"]["findings_by_severity"].values()
        if isinstance(v, int)
    )
    assert summed == len(r["findings"])


def test_build_unified_report_empty_excluded() -> None:
    from aggregate import build_unified_report

    r = build_unified_report(
        reports_schema_version="1.0",
        run_id="r-empty",
        title="T",
        probe_reports=[],
        scope_report=None,
        include_probe=False,
        include_scope=False,
    )
    assert r["findings"] == []
    assert r["rollups"]["total_findings"] == 0


def _probe_payload(target: str) -> tuple[str, dict]:
    return ("probe_01_x", {"scan_id": "s1", "target": target, "findings": [], "statistics": {}})


def test_default_title_is_customer_facing_with_local_date(monkeypatch) -> None:
    import time

    import aggregate

    monkeypatch.setenv("TZ", "UTC")
    time.tzset()
    monkeypatch.setattr(aggregate, "_utc_now_iso", lambda: "2026-09-11T15:00:00+00:00")

    r = aggregate.build_unified_report(
        reports_schema_version="1.0",
        run_id="r",
        title="",
        probe_reports=[_probe_payload("https://ryanwilson.io")],
        scope_report=None,
        include_probe=True,
        include_scope=False,
    )
    assert r["title"] == "Recon/Vuln Analysis - Report Findings - September 11, 2026"
    assert r["target"] == "https://ryanwilson.io"


def test_explicit_title_wins_and_target_falls_back_to_scope_domain() -> None:
    from aggregate import build_unified_report

    r = build_unified_report(
        reports_schema_version="1.0",
        run_id="r",
        title="Custom",
        probe_reports=[],
        scope_report={"domain": "example.com", "discovery": {}},
        include_probe=False,
        include_scope=True,
    )
    assert r["title"] == "Custom"
    assert r["target"] == "example.com"


def test_identical_findings_from_overlapping_scans_are_reported_once() -> None:
    from aggregate import build_unified_report

    finding = {"severity": "info", "title": "TLS on 443", "url": "a.example:443", "plugin_name": "tls"}
    other = {**finding, "url": "a.example:8443"}
    scan_1 = ("probe_01", {"scan_id": "s1", "target": "https://a.example", "findings": [finding, other]})
    scan_2 = ("probe_02", {"scan_id": "s2", "target": "a.example", "findings": [dict(finding)]})

    r = build_unified_report(
        reports_schema_version="1.0",
        run_id="r",
        title="T",
        probe_reports=[scan_1, scan_2],
        scope_report=None,
        include_probe=True,
        include_scope=False,
    )
    assert [f["url"] for f in r["findings"]] == ["a.example:443", "a.example:8443"]
    assert r["rollups"]["total_findings"] == 2
    assert r["rollups"]["findings_by_severity"]["info"] == 2
    assert r["rollups"]["findings_by_plugin"] == {"tls": 2}


def _build(probe_reports):
    from aggregate import build_unified_report

    return build_unified_report(
        reports_schema_version="1.0",
        run_id="r",
        title="T",
        probe_reports=probe_reports,
        scope_report=None,
        include_probe=True,
        include_scope=False,
    )


def test_findings_are_classified_with_the_engine_rule() -> None:
    findings = [
        {"severity": "high", "title": "SQLi", "url": "u1", "plugin_name": "web_vulnerabilities"},
        {"severity": "medium", "title": "Weak TLS", "url": "u2", "plugin_name": "tls",
         "metadata": {"classification": "warning"}},
        {"severity": "info", "title": "Cloudflare 443", "url": "u3", "plugin_name": "net",
         "edge_infrastructure": True},
        {"severity": "info", "title": "Fingerprint", "url": "u4", "plugin_name": "fp"},
        {"severity": "low", "title": "Edge low", "url": "u5", "plugin_name": "net",
         "edge_infrastructure": True},
    ]
    r = _build([("p1", {"scan_id": "s1", "target": "https://a.example", "findings": findings})])

    by_title = {f["title"]: f["classification"] for f in r["findings"]}
    assert by_title == {
        "SQLi": "vulnerability",
        "Weak TLS": "observation",
        "Cloudflare 443": "observation",
        "Fingerprint": "observation",
        "Edge low": "observation",
    }
    roll = r["rollups"]
    assert roll["vulnerability_count"] == 1
    assert roll["observation_count"] == 4
    assert roll["vulnerabilities_by_severity"] == {"critical": 0, "high": 1, "medium": 0, "low": 0}
    assert roll["total_findings"] == 5


def test_remediation_evidence_and_endpoints_are_carried_through() -> None:
    finding = {
        "severity": "high",
        "title": "CVE-2024-1: jQuery vulnerability",
        "url": "https://a.example",
        "plugin_name": "cve_correlation",
        "description": "d",
        "remediation": "Upgrade jQuery to 3.5.0+",
        "evidence": {"cve_id": "2024-1", "cvss_score": 7.5},
        "affected_endpoints": ["https://a.example/", "https://a.example/app"],
        "attack_scenario": "attack",
        "defense_strategy": "defense",
        "mitigation_plan": "plan",
        "adjusted_risk_score": 42.0,
    }
    r = _build([("p1", {"scan_id": "s1", "target": "https://a.example", "findings": [finding]})])

    nf = r["findings"][0]
    assert nf["remediation"] == "Upgrade jQuery to 3.5.0+"
    assert nf["evidence"] == {"cve_id": "2024-1", "cvss_score": 7.5}
    assert nf["affected_endpoints"] == ["https://a.example/", "https://a.example/app"]
    assert (nf["attack_scenario"], nf["defense_strategy"], nf["mitigation_plan"]) == (
        "attack",
        "defense",
        "plan",
    )
    assert nf["adjusted_risk_score"] == 42.0


def test_overall_risk_is_the_worst_scan_level() -> None:
    def scan(scan_id, level):
        return (scan_id, {"scan_id": scan_id, "target": f"https://{scan_id}.example",
                          "findings": [], "statistics": {"risk": {"level": level}}})

    assert _build([scan("a", "low"), scan("b", "high"), scan("c", "none")])["rollups"]["overall_risk"] == "high"
    assert _build([scan("a", "none")])["rollups"]["overall_risk"] == "none"
    assert _build([])["rollups"]["overall_risk"] == "none"


def test_checks_performed_is_the_ordered_union_across_scans() -> None:
    def scan(scan_id, checks):
        return (scan_id, {"scan_id": scan_id, "target": f"https://{scan_id}.example", "findings": [],
                          "statistics": {"checks_performed": checks}})

    r = _build([scan("a", ["tls_analysis", "security_headers"]), scan("b", ["security_headers", "cve_correlation"])])
    assert r["checks_performed"] == ["tls_analysis", "security_headers", "cve_correlation"]
    assert _build([("old", {"scan_id": "o", "target": "t", "findings": []})])["checks_performed"] == []


def test_scope_subdomain_takeovers_become_vulnerability_findings() -> None:
    from aggregate import build_unified_report

    scope = {
        "domain": "example.com",
        "discovery": {
            "subdomains": {"all_unique": ["a.example.com", "gone.example.com"]},
            "subdomain_takeover": [
                {"subdomain": "gone.example.com", "cname": "orphan.github.io",
                 "service": "GitHub Pages", "severity": "high",
                 "detail": "dangling CNAME"},
            ],
        },
    }
    r = build_unified_report(
        reports_schema_version="1.0", run_id="r", title="T",
        probe_reports=[], scope_report=scope, include_probe=False, include_scope=True,
    )

    takeover = [f for f in r["findings"] if "takeover" in f["title"].lower()]
    assert len(takeover) == 1
    assert takeover[0]["classification"] == "vulnerability"
    assert takeover[0]["severity"] == "high"
    assert "gone.example.com" in takeover[0]["url"] or "gone.example.com" in takeover[0]["description"]
    assert r["rollups"]["vulnerability_count"] == 1
