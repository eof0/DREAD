"""Customer-facing report output: title, target subtitle, no internal product names."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPORTS = Path(__file__).resolve().parent.parent / "reports"

TITLE = "Recon/Vuln Analysis - Report Findings - September 11, 2026"
INTERNAL_NAMES = ("DREAD", "Probe", "Scope", "probe_01", "product suite", "s3_buckets")


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


def _report() -> dict:
    return {
        "reports_schema_version": "1.0",
        "title": TITLE,
        "target": "https://ryanwilson.io",
        "run_id": "run-1",
        "generated_at": "2026-09-11T05:00:00+00:00",
        "sources": {
            "probe": {
                "included": True,
                "scans": [{"artifact": "probe_01_x", "target": "https://ryanwilson.io", "finding_count": 1}],
            },
            "scope": {"included": True, "summary": {"subdomain_count": 2, "cloud_bucket_counts": {"s3_buckets": 0, "gcs": 0}}},
        },
        "rollups": {"total_findings": 1, "findings_by_severity": {"low": 1}},
        "findings": [{"severity": "low", "title": "Missing header", "plugin_name": "security_headers"}],
    }


def test_html_has_title_target_subtitle_and_no_internal_names(tmp_path: Path) -> None:
    from writers.html_writer import write_suite_html

    doc = write_suite_html(_report(), tmp_path, "r").read_text(encoding="utf-8")

    assert f"<h1>{TITLE}</h1>" in doc
    assert '<p class="subtitle">https://ryanwilson.io</p>' in doc
    assert "Amazon S3, Google Cloud Storage" in doc
    for name in INTERNAL_NAMES:
        assert name not in doc, name


def test_pdf_has_title_target_subtitle_and_no_internal_names(monkeypatch, tmp_path: Path) -> None:
    import writers.pdf_writer as pdf_writer

    texts: list[str] = []
    real_paragraph = pdf_writer.Paragraph

    def recording_paragraph(text, style, *args, **kwargs):
        texts.append(text)
        return real_paragraph(text, style, *args, **kwargs)

    monkeypatch.setattr(pdf_writer, "Paragraph", recording_paragraph)
    pdf_writer.write_suite_pdf(_report(), tmp_path, "r")

    assert texts[0] == TITLE
    assert texts[1] == "https://ryanwilson.io"
    joined = "\n".join(texts)
    assert "Amazon S3, Google Cloud Storage" in joined
    for name in INTERNAL_NAMES:
        assert name not in joined, name
