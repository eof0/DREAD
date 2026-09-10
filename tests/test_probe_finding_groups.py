from plugins.base_plugin import Finding
from scanner.analysis.attack_chain_engine import build_attack_chains
from scanner.analysis.findings import group_findings
from scanner.config import ScanConfig
from scanner.engine import ScanEngine


def finding(title, severity, url, plugin="security_headers"):
    return {
        "plugin_name": plugin,
        "title": title,
        "severity": severity,
        "description": f"{title} description",
        "remediation": f"Fix {title}",
        "url": url,
        "evidence": {},
        "metadata": {},
        "risk_score": 20,
    }


def test_group_findings_collapses_duplicates_and_sorts_endpoints():
    grouped = group_findings(
        [
            finding("Missing X-Frame-Options", "medium", "https://example.test/z"),
            finding("Missing X-Frame-Options", "medium", "https://example.test/a"),
        ]
    )

    assert grouped == [
        {
            **finding(
                "Missing X-Frame-Options",
                "medium",
                "https://example.test/a",
            ),
            "affected_endpoints": [
                "https://example.test/a",
                "https://example.test/z",
            ],
            "endpoint_count": 2,
        }
    ]


def test_group_findings_orders_by_severity_title_and_endpoint():
    grouped = group_findings(
        [
            finding("Z low", "low", "https://example.test/z"),
            finding("B high", "high", "https://example.test/b"),
            finding("A high", "high", "https://example.test/z"),
            finding("A high", "high", "https://example.test/a"),
            finding("Info", "info", "https://example.test/i"),
        ]
    )

    assert [(item["severity"], item["title"], item["url"]) for item in grouped] == [
        ("high", "A high", "https://example.test/a"),
        ("high", "B high", "https://example.test/b"),
        ("low", "Z low", "https://example.test/z"),
        ("info", "Info", "https://example.test/i"),
    ]


def test_report_counts_and_scores_grouped_vulnerability_once():
    engine = ScanEngine(ScanConfig("https://example.test"))
    engine.crawler.visited_urls = {
        "https://example.test/a",
        "https://example.test/z",
    }
    engine.findings = [
        Finding(
            plugin_name="security_headers",
            severity="medium",
            title="Missing X-Frame-Options",
            description="Header is missing",
            url=url,
            remediation="Set the header",
        )
        for url in sorted(engine.crawler.visited_urls)
    ]

    report = engine._generate_report(1.0, [])

    assert report["statistics"]["total_findings"] == 1
    assert report["statistics"]["findings_by_severity"]["medium"] == 1
    assert report["statistics"]["risk"]["raw_score"] == 20
    assert report["findings"][0]["endpoint_count"] == 2


def test_warnings_are_reported_but_excluded_from_vulnerability_totals():
    engine = ScanEngine(ScanConfig("https://example.test"))
    engine.findings = [
        Finding(
            plugin_name="tls_analysis",
            severity="info",
            title="TLS Configuration on Port 443",
            description="Healthy configuration observation, not a vulnerability.",
            url="example.test:443",
            metadata={"classification": "warning"},
        )
    ]

    report = engine._generate_report(1.0, [])

    assert report["statistics"]["total_findings"] == 0
    assert report["statistics"]["warning_findings"] == 1
    assert report["findings"][0]["metadata"]["classification"] == "warning"


def test_attack_chains_reference_grouped_findings():
    grouped = group_findings(
        [
            finding("Known vulnerable software", "high", "https://example.test/z"),
            finding("Known vulnerable software", "high", "https://example.test/a"),
        ]
    )

    chains = build_attack_chains(grouped)

    related = next(
        chain["related_findings"]
        for chain in chains
        if chain["id"] == "chain_cve_exploit"
    )
    assert len(related) == 1
    assert related[0]["affected_endpoints"] == [
        "https://example.test/a",
        "https://example.test/z",
    ]
