"""run_build emits both audience deliverables plus the internal JSON."""

from __future__ import annotations

import json
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


def _probe_json(tmp_path: Path) -> Path:
    payload = {
        "scan_id": "s1",
        "target": "https://ryanwilson.io",
        "findings": [
            {"severity": "high", "title": "SQL Injection Error in parameter 'id'",
             "plugin_name": "web_vulnerabilities", "url": "https://ryanwilson.io/i?id=1",
             "description": "d", "remediation": "Use parameterized queries.",
             "evidence": {"parameter": "id"}},
            {"severity": "info", "title": "Technology Fingerprinting",
             "plugin_name": "fingerprinting", "url": "https://ryanwilson.io",
             "metadata": {"classification": "warning"}},
        ],
        "statistics": {"risk": {"level": "high"}, "checks_performed": ["web_vulnerabilities", "fingerprinting"]},
    }
    p = tmp_path / "probe_01.json"
    p.write_text(json.dumps(payload))
    return p


def test_run_build_writes_executive_technical_and_internal(tmp_path: Path) -> None:
    from suite_build import run_build

    out = tmp_path / "out"
    messages, errors = run_build(
        output_dir=out,
        base_name="dread_suite_report",
        title="",
        probe_paths=[_probe_json(tmp_path)],
        scope_path=None,
        include=frozenset({"probe"}),
        formats=frozenset({"json", "html", "pdf"}),
        dashboard_src=REPORTS / "dashboard",
        try_npm_build=False,
    )

    assert errors == []
    # Customer deliverables
    assert (out / "executive_summary.html").is_file()
    assert (out / "executive_summary.pdf").is_file()
    assert (out / "technical_report.html").is_file()
    assert (out / "technical_report.pdf").is_file()
    assert (out / "technical_report.json").is_file()
    # Internal artifact the dashboard/history/DreadAI still read
    assert (out / "dread_suite_report.json").is_file()

    internal = json.loads((out / "dread_suite_report.json").read_text())
    assert "raw_embed" in internal  # full internal copy
    technical = json.loads((out / "technical_report.json").read_text())
    assert "raw_embed" not in technical  # slimmed customer copy
    assert technical["rollups"]["vulnerability_count"] == 1
    assert technical["rollups"]["observation_count"] == 1

    exec_html = (out / "executive_summary.html").read_text()
    assert "database" in exec_html.lower()  # plain-language SQLi explanation
    assert "web_vulnerabilities" not in exec_html
