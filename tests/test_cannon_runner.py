from __future__ import annotations

import sys
from pathlib import Path

_CANNON = Path(__file__).resolve().parents[1] / "cannon"
if str(_CANNON) not in sys.path:
    sys.path.insert(0, str(_CANNON))

from runner import ToolResult, detect, run, which


def test_run_captures_output_and_returncode():
    result = run(
        "probe",
        [sys.executable, "-c", "import sys; print('out'); sys.stderr.write('err'); sys.exit(3)"],
    )
    assert isinstance(result, ToolResult)
    assert result.returncode == 3
    assert "out" in result.stdout
    assert "err" in result.stderr
    assert result.timed_out is False
    assert result.duration >= 0


def test_run_flags_timeout():
    result = run(
        "sleeper",
        [sys.executable, "-c", "import time; time.sleep(5)"],
        timeout=0.2,
    )
    assert result.timed_out is True
    assert result.returncode != 0


def test_which_finds_the_interpreter():
    assert which("python") or which("python3") or which(sys.executable)


def test_detect_reports_presence(monkeypatch):
    monkeypatch.setattr(
        "runner.which",
        lambda b: "/usr/bin/nmap" if b == "nmap" else None,
    )
    found = detect(["nmap", "definitely-not-a-real-binary"])
    assert found["nmap"] == "/usr/bin/nmap"
    assert found["definitely-not-a-real-binary"] is None


def test_run_missing_binary_returns_result_not_exception():
    # A binary that vanished after detection (TOCTOU) or a non-executable PATH
    # entry must surface as a failed ToolResult, not an uncaught exception that
    # would abort a whole kaboom plan mid-flight.
    result = run("ghost", ["/nonexistent/cannon/binary/zzz", "target"])
    assert isinstance(result, ToolResult)
    assert result.returncode != 0
    assert result.timed_out is False
    assert result.stderr
