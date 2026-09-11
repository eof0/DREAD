"""Plain-language templates for the executive summary (reports/plain_language.py)."""

from __future__ import annotations

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


@pytest.mark.parametrize(
    ("plugin", "title", "category"),
    [
        ("web_vulnerabilities", "SQL Injection Error in parameter 'id'", "sql_injection"),
        ("web_vulnerabilities", "Reflected XSS in parameter 'q'", "cross_site_scripting"),
        ("web_vulnerabilities", "DOM-based XSS", "cross_site_scripting"),
        ("web_vulnerabilities", "Open Redirect in parameter 'next'", "open_redirect"),
        ("web_vulnerabilities", "Command Injection in parameter 'host'", "command_injection"),
        ("web_vulnerabilities", "Server-Side Template Injection in parameter 'n'", "template_injection"),
        ("web_vulnerabilities", "Path Traversal in parameter 'file'", "file_access"),
        ("web_vulnerabilities", "Local File Inclusion in parameter 'page'", "file_access"),
        ("access_control", "IDOR / broken object-level authorization", "broken_access_control"),
        ("cve_correlation", "CVE-2020-11022: jquery vulnerability", "known_vulnerable_software"),
        ("wordpress_scan", "CVE-2023-1234: plugin contact-form-7 5.1", "known_vulnerable_software"),
        ("wordpress_scan", "WordPress user enumeration exposed", "wordpress_exposure"),
        ("sensitive_files", "Exposed Sensitive File: .env", "exposed_sensitive_file"),
        ("origin_detection", "ORIGIN LEAKED: HTTPS exposed through CDN", "origin_exposed"),
        ("network_scanner", "EXPOSED: MySQL on port 3306", "exposed_service"),
        ("tls_analysis", "TLS Configuration on Port 443", "weak_encryption"),
        ("security_headers", "Missing Content-Security-Policy Header", "missing_browser_protections"),
        ("fingerprinting", "Server Banner Exposed", "information_disclosure"),
    ],
)
def test_findings_map_to_plain_categories(plugin: str, title: str, category: str) -> None:
    from plain_language import explain

    assert explain({"plugin_name": plugin, "title": title}).category == category


def test_unknown_findings_get_a_generic_explanation_without_internal_names() -> None:
    from plain_language import explain

    e = explain({"plugin_name": "some_new_plugin", "title": "Weird thing on port 9"})

    assert e.category == "general"
    text = " ".join((e.headline, e.what_it_means, e.why_it_matters, e.what_to_do))
    assert "some_new_plugin" not in text


def test_known_exploited_cve_says_so_in_plain_words() -> None:
    from plain_language import explain

    finding = {
        "plugin_name": "cve_correlation",
        "title": "CVE-2021-44228: log4j vulnerability",
        "evidence": {"technology": "log4j", "kev": True},
    }
    e = explain(finding)

    assert "log4j" in e.headline
    assert "actively" in e.why_it_matters.lower()


def test_urgency_by_severity() -> None:
    from plain_language import urgency

    assert urgency("critical") == "Fix immediately"
    assert urgency("high") == "Fix within 7 days"
    assert urgency("medium") == "Fix within 30 days"
    assert urgency("low") == "Fix when convenient"


def test_risk_statement_for_clean_and_risky_results() -> None:
    from plain_language import risk_statement

    label, sentence = risk_statement("none", 0)
    assert label == "Low"
    assert "no vulnerabilities" in sentence.lower()

    label, sentence = risk_statement("high", 3)
    assert label == "High"
    assert "3 vulnerabilities" in sentence
