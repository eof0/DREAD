"""Smoke the reports CLI version string (uses repo root on sys.path)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import products

REPO = Path(__file__).resolve().parent.parent
REPORTS = REPO / "reports" / "reports.py"


def test_reports_version_includes_suite_version() -> None:
    r = subprocess.run(
        [sys.executable, str(REPORTS), "version"],
        cwd=str(REPO),
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr
    assert products.SUITE_VERSION in r.stdout
    assert "schema" in r.stdout
