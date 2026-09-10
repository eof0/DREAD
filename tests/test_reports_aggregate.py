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
