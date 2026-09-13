"""SSRF active check: fires only when the server fetches internal metadata for us."""

from __future__ import annotations

import sys
from pathlib import Path

_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))

from scanner.active_checks import ssrf


class _Resp:
    def __init__(self, text="", status=200):
        self.text = text
        self.status_code = status
        self.headers = {"Content-Type": "text/html"}


class _Ctx:
    """Minimal ActiveScanContext stand-in."""
    def __init__(self, params, responder, baseline_text=""):
        self.endpoint = "https://app.test/fetch"
        self.params = params
        self.baseline = _Resp(baseline_text)
        self._responder = responder

    def probe(self, params, *, module):
        return self._responder(params)


def test_ssrf_detected_when_metadata_is_reflected():
    def responder(params):
        if "169.254.169.254" in params["url"]:
            return _Resp("ami-id: ami-0abc\ninstance-id: i-123\niam/security-credentials/role")
        return _Resp("nothing")

    findings = ssrf.check(_Ctx({"url": "https://good.example/img"}, responder), "url")
    assert len(findings) == 1
    assert "SSRF" in findings[0].title


def test_no_ssrf_when_marker_already_in_baseline():
    # If the page always contains "meta-data" text, reflecting it isn't proof of a fetch.
    def responder(params):
        return _Resp("meta-data/ shown here")

    findings = ssrf.check(
        _Ctx({"url": "https://x/y"}, responder, baseline_text="meta-data/ shown here"),
        "url")
    assert findings == []


def test_non_urlish_parameter_is_skipped():
    called = []

    def responder(params):
        called.append(1)
        return _Resp("ami-id")

    findings = ssrf.check(_Ctx({"comment": "hello world"}, responder), "comment")
    assert findings == []
    assert called == []          # never probed a non-URL parameter


def test_urlish_by_value_even_if_name_is_generic():
    def responder(params):
        if "169.254" in params["q"]:
            return _Resp("computeMetadata\ninstance-id")
        return _Resp("x")

    findings = ssrf.check(_Ctx({"q": "https://example.com/a"}, responder), "q")
    assert len(findings) == 1
