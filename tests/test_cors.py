"""CORS misconfiguration check: reflected Origin with credentials is the dangerous case."""

from __future__ import annotations

import sys
from pathlib import Path

from requests import Response

_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))

from plugins.cors_check import CORSCheckPlugin, evaluate_cors


def _headers(acao=None, acac=None):
    h = {}
    if acao is not None:
        h["Access-Control-Allow-Origin"] = acao
    if acac is not None:
        h["Access-Control-Allow-Credentials"] = acac
    return h


def test_reflected_origin_with_credentials_is_high_severity():
    verdict = evaluate_cors("https://evil.example", _headers("https://evil.example", "true"))
    assert verdict is not None
    assert verdict["severity"] == "high"


def test_wildcard_origin_without_credentials_is_low_or_info():
    verdict = evaluate_cors("https://evil.example", _headers("*", None))
    assert verdict is not None
    assert verdict["severity"] in ("info", "low")


def test_null_origin_allowed_is_flagged():
    verdict = evaluate_cors("null", _headers("null", "true"))
    assert verdict is not None
    assert verdict["severity"] == "high"


def test_properly_scoped_cors_is_not_flagged():
    # Server echoes only its own origin, ignoring the attacker origin -> safe.
    assert evaluate_cors("https://evil.example", _headers("https://app.example", "true")) is None
    assert evaluate_cors("https://evil.example", _headers(None, None)) is None


class _Handler:
    def __init__(self, headers):
        self._headers = headers

    def get(self, url, **kwargs):
        r = Response()
        r.status_code = 200
        r._content = b"{}"
        sent_origin = (kwargs.get("headers") or {}).get("Origin")
        # Vulnerable server reflects whatever Origin it is sent.
        r.headers = {"Access-Control-Allow-Origin": sent_origin or "",
                     "Access-Control-Allow-Credentials": "true"}
        return r


def test_plugin_only_scans_root_and_reports_reflection():
    plugin = CORSCheckPlugin()
    findings = plugin.scan({"url": "https://app.example/", "depth": 0}, _Handler(None))
    assert any("CORS" in f.title for f in findings)

    # Non-root pages are skipped to avoid duplicate findings.
    assert plugin.scan({"url": "https://app.example/page", "depth": 1}, _Handler(None)) == []
