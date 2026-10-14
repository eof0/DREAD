"""CLI regression: an unreachable target must fail and still leave its report."""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_unreachable_target_exits_nonzero_and_keeps_report(tmp_path):
    env = os.environ.copy()
    env["DREAD_SKIP_CVE_UPDATE"] = "1"
    env["DREAD_ASN_PRECHECKED"] = "1"
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "probe" / "probe.py"),
            "scan",
            "http://127.0.0.1:1",
            "--profile",
            "quick",
            "--plugins",
            "security_headers",
            "--format",
            "json",
            "--output-dir",
            str(tmp_path),
            "--depth",
            "0",
            "--max-urls",
            "1",
            "--rate-limit",
            "0",
        ],
        cwd=ROOT / "probe",
        env=env,
        capture_output=True,
        text=True,
        timeout=90,
    )

    assert proc.returncode != 0, proc.stdout + proc.stderr
    reports = list(tmp_path.glob("*.json"))
    assert len(reports) == 1
    stats = json.loads(reports[0].read_text(encoding="utf-8"))["statistics"]
    assert stats["status"] == "failed"
    assert stats["partial"] is True
    assert stats["risk"]["level"] == "unknown"
    assert stats["risk"]["normalized_score"] is None
    assert stats["checks"]["successful"] == 0
