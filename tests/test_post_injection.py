"""Active checks reach POST form fields, not just GET query parameters."""

from __future__ import annotations

import sys
from pathlib import Path

from requests import Response

_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))

from plugins.web_vulnerabilities import WebVulnerabilitiesPlugin, discover_post_targets
from scanner.active_checks.context import ActiveScanContext


def _response(body="<html></html>", status=200, headers=None):
    r = Response()
    r.status_code = status
    r._content = body.encode()
    r.encoding = "utf-8"
    r.headers = {"Content-Type": "text/html", **(headers or {})}
    return r


def test_discover_post_targets_returns_same_origin_post_forms():
    html = """
    <form action="/cart/add" method="post">
      <input name="product_id" value="1">
      <input name="quantity" value="1">
    </form>
    <form action="https://evil.test/steal" method="post"><input name="x"></form>
    <form action="/search" method="get"><input name="q"></form>
    """

    targets = discover_post_targets("https://example.test/shop", html)

    assert targets == [
        ("https://example.test/cart/add", {"product_id": "1", "quantity": "1"})
    ]


def test_context_delivers_via_post_body_when_configured():
    sent = {}

    def send(method="GET", **kwargs):
        sent["method"] = method
        sent["kwargs"] = kwargs
        return _response()

    ctx = ActiveScanContext(
        "https://example.test/cart/add",
        ("https", "example.test", 443),
        _response(),
        {"quantity": "1"},
        send,
        method="POST",
        location="form",
    )
    ctx.probe({"quantity": "-1"}, module="logic")

    assert sent["method"] == "POST"
    assert sent["kwargs"]["data"] == {"quantity": "-1"}
    assert "params" not in sent["kwargs"]


def test_get_context_still_delivers_via_query():
    sent = {}

    def send(method="GET", **kwargs):
        sent.update(kwargs, method=method)
        return _response()

    ctx = ActiveScanContext(
        "https://example.test/s",
        ("https", "example.test", 443),
        _response(),
        {"q": "x"},
        send,
    )
    ctx.probe({"q": "y"}, module="xss")

    assert sent["method"] == "GET"
    assert sent["params"] == {"q": "y"}


def test_plugin_injects_into_post_form_fields():
    # The server is vulnerable to reflected XSS via the POSTed 'name' field.
    class Handler:
        def __init__(self):
            self.calls = []

        def get(self, url, **kwargs):
            if kwargs.get("params") is None and kwargs.get("data") is None:
                return _response(
                    '<form action="/comment" method="post"><input name="name" value="x"></form>'
                )
            # GET baseline for the POST endpoint
            return _response("baseline")

        def post(self, url, **kwargs):
            self.calls.append(kwargs)
            value = (kwargs.get("data") or {}).get("name", "")
            return _response(f"<html>{value}</html>")

    findings = WebVulnerabilitiesPlugin().scan(
        {"url": "https://example.test/page", "depth": 0}, Handler()
    )

    assert any("XSS" in f.title for f in findings)
