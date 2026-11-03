from __future__ import annotations

import io
from contextlib import redirect_stderr

from scanner.progress import task_progress


def test_task_progress_rewrites_one_line_without_rich(monkeypatch):
    monkeypatch.setattr("scanner.progress._RICH", False)
    buf = io.StringIO()
    with redirect_stderr(buf):
        with task_progress(description="Plugin scans", total=4, console=None) as advance:
            advance(0, "web_vulns (3s elapsed)")
            advance(2)
            advance(2)
    output = buf.getvalue()
    assert "Still running" not in output
    assert "4/4" in output.splitlines()[-1]
