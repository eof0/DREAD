"""Misconfiguration checks: directory listing, verbose errors, unrestricted upload forms."""

from __future__ import annotations

import sys
from pathlib import Path

from requests import Response

_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))

from plugins.misconfiguration import (
    MisconfigurationPlugin,
    detect_directory_listing,
    detect_stack_trace,
)


def _resp(body, status=200, ctype="text/html"):
    r = Response()
    r.status_code = status
    r._content = body.encode()
    r.encoding = "utf-8"
    r.headers = {"Content-Type": ctype}
    return r


class Handler:
    def __init__(self, body="<html></html>", ctype="text/html", status=200):
        self._resp = _resp(body, status, ctype)

    def get(self, url, **kwargs):
        return self._resp


def test_detect_directory_listing():
    assert detect_directory_listing('<title>Index of /uploads</title><a href="../">')
    assert detect_directory_listing("<h1>Directory listing for /files/</h1>")
    assert not detect_directory_listing("<html><body>Welcome</body></html>")


def test_detect_stack_trace_multiple_languages():
    assert detect_stack_trace("Traceback (most recent call last):\n  File \"app.py\"")
    assert detect_stack_trace("java.lang.NullPointerException\n\tat com.app.Main")
    assert detect_stack_trace("PHP Fatal error:  Uncaught Error in /var/www/x.php:12")
    assert not detect_stack_trace("Everything is fine")


def test_plugin_flags_directory_listing():
    findings = MisconfigurationPlugin().scan(
        {"url": "https://example.test/uploads/", "depth": 1},
        Handler("<title>Index of /uploads</title>"),
    )
    assert any("Directory listing" in f.title for f in findings)


def test_plugin_flags_stack_trace():
    findings = MisconfigurationPlugin().scan(
        {"url": "https://example.test/x", "depth": 0},
        Handler("Traceback (most recent call last): File x", status=500),
    )
    assert any("stack trace" in f.title.lower() or "error" in f.title.lower() for f in findings)


def test_plugin_flags_file_upload_form_as_warning():
    html = '<form method="post" enctype="multipart/form-data"><input type="file" name="doc"></form>'
    findings = MisconfigurationPlugin().scan(
        {"url": "https://example.test/", "depth": 0}, Handler(html)
    )
    upload = [f for f in findings if "upload" in f.title.lower()]
    assert upload
    assert upload[0].metadata.get("classification") == "warning"


def test_clean_page_has_no_findings():
    findings = MisconfigurationPlugin().scan(
        {"url": "https://example.test/", "depth": 0},
        Handler("<html><body>All good</body></html>"),
    )
    assert findings == []
