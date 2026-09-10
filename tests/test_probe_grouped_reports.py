from pathlib import Path

from scanner.reporting.markdown_report import MarkdownReportGenerator
from scanner.reporting import pdf_report


def grouped_report():
    return {
        "scan_id": "scan_1",
        "target": "https://example.test",
        "timestamp": "2026-08-31T12:00:00",
        "statistics": {
            "findings_by_severity": {"high": 0, "medium": 1},
            "total_findings": 1,
            "edge_infrastructure_findings": 0,
            "urls_scanned": 2,
            "duration_seconds": 1,
            "risk": {"level": "medium", "raw_score": 20, "normalized_score": 20},
        },
        "findings": [
            {
                "plugin_name": "security_headers",
                "title": "Missing X-Frame-Options",
                "severity": "medium",
                "description": "Header is missing",
                "remediation": "Set the header",
                "url": "https://example.test/a",
                "affected_endpoints": [
                    "https://example.test/a",
                    "https://example.test/z",
                ],
                "endpoint_count": 2,
                "evidence": {},
                "risk_score": 20,
                "raw_risk_score": 20,
                "adjusted_risk_score": 20,
            }
        ],
    }


def test_markdown_lists_grouped_endpoints_once(tmp_path):
    path = MarkdownReportGenerator(
        grouped_report(),
        str(tmp_path),
        "client",
        "report",
    ).generate()
    text = Path(path).read_text()

    assert text.count("### 1. Missing X-Frame-Options") == 1
    assert "**Affected Endpoints (2):**" in text
    assert "- https://example.test/a" in text
    assert "- https://example.test/z" in text


def test_pdf_story_lists_grouped_endpoints(tmp_path, monkeypatch):
    captured = []

    class Document:
        def __init__(self, path, **_kwargs):
            self.path = path

        def build(self, elements):
            captured.extend(elements)
            Path(self.path).touch()

    monkeypatch.setattr(pdf_report, "SimpleDocTemplate", Document)

    pdf_report.PDFReportGenerator(
        grouped_report(),
        str(tmp_path),
        "client",
        "report",
    ).generate()

    paragraphs = [getattr(element, "text", "") for element in captured]
    assert "Affected Endpoints (2):" in paragraphs
    assert "https://example.test/a" in paragraphs
    assert "https://example.test/z" in paragraphs
