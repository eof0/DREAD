"""Expanded active checks: encoded/advanced traversal, blind SQLi, attribute XSS,
multi-engine SSTI, prototype pollution."""

from __future__ import annotations

import sys
from html import escape
from pathlib import Path

from requests import Response

_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))

from plugins.web_vulnerabilities import WebVulnerabilitiesPlugin


def response(body="<html></html>", status=200, headers=None):
    r = Response()
    r.status_code = status
    r._content = body.encode()
    r.encoding = "utf-8"
    r.headers = {"Content-Type": "text/html", **(headers or {})}
    return r


class Handler:
    def __init__(self, responder, page_html="<html></html>"):
        self.responder = responder
        self.page_html = page_html

    def get(self, url, **kwargs):
        params = kwargs.get("params")
        if params is None:
            return response(self.page_html)
        return self.responder(params)

    def post(self, url, **kwargs):
        return self.responder(kwargs.get("data") or {})


def scan(parameter, responder, value="safe"):
    return WebVulnerabilitiesPlugin().scan(
        {"url": f"https://example.test/x?{parameter}={value}", "depth": 0},
        Handler(responder),
    )


def _titles(findings):
    return [f.title for f in findings]


def test_encoded_path_traversal_is_detected():
    def responder(params):
        p = params["file"]
        if isinstance(p, list):
            p = p[0]
        # Server decodes percent-encoding and serves the file.
        if "%2f" in p.lower() or "%2e" in p.lower() or "%252" in p.lower():
            return response("root:x:0:0:root:/root:/bin/bash")
        return response("safe")

    findings = scan("file", responder)
    assert any("Path Traversal" in t for t in _titles(findings))


def test_boolean_blind_sqli_is_detected():
    baseline = "<html><body>" + ("product listing " * 50) + "</body></html>"

    def responder(params):
        v = params["id"]
        if isinstance(v, list):
            v = v[0]
        if "1=1" in v or "'1'='1" in v or '"1"="1' in v:
            return response(baseline)          # TRUE -> normal page
        if "1=2" in v or "'1'='2" in v or '"1"="2' in v:
            return response("<html><body>no results</body></html>")  # FALSE -> different
        return response(baseline)

    plugin_findings = WebVulnerabilitiesPlugin().scan(
        {"url": "https://example.test/x?id=5", "depth": 0},
        Handler(responder, page_html=baseline),
    )
    assert any("boolean-based" in t for t in _titles(plugin_findings))


def test_attribute_context_xss_is_detected():
    def responder(params):
        v = params["q"]
        if isinstance(v, list):
            v = v[0]
        # Reflected inside an attribute value, unescaped.
        return response(f'<input type="text" value="{v}">')

    findings = scan("q", responder)
    assert any("attribute context" in t for t in _titles(findings))


def test_multi_engine_ssti_erb_is_detected():
    import re

    def responder(params):
        v = params["name"]
        if isinstance(v, list):
            v = v[0]
        m = re.fullmatch(r"<%= (\d+)\*(\d+) %>", v)
        return response(str(int(m.group(1)) * int(m.group(2))) if m else "hello")

    findings = scan("name", responder)
    assert any("Template Injection" in t for t in _titles(findings))


def test_prototype_pollution_reflected_is_detected():
    def responder(params):
        # A merge endpoint reflects injected proto keys back into its JSON echo.
        proto_key = next((k for k in params if "__proto__" in k or "prototype" in k), None)
        if proto_key:
            val = params[proto_key]
            return response(f'{{"{proto_key}":"{val}"}}')
        return response("{}")

    findings = scan("q", responder)
    assert any("Prototype pollution" in t for t in _titles(findings))


def test_no_false_positives_on_escaping_server():
    def responder(params):
        v = params.get("q") or next(iter(params.values()), "")
        if isinstance(v, list):
            v = v[0]
        return response(f"<html><body>{escape(str(v))}</body></html>")

    findings = scan("q", responder)
    # A properly-escaping server that returns 200 for everything yields no injection findings.
    assert not any(
        any(k in t for k in ("XSS", "Traversal", "Template", "Prototype", "SQL"))
        for t in _titles(findings)
    )


def test_css_injection_into_style_block_is_detected():
    def responder(params):
        v = params["theme"]
        if isinstance(v, list):
            v = v[0]
        # Input reflected inside a <style> block.
        return response(f"<html><head><style>body{{color:{v}}}</style></head></html>")

    findings = scan("theme", responder)
    assert any("CSS Injection" in t for t in _titles(findings))


def test_css_marker_in_plain_html_is_not_css_injection():
    def responder(params):
        v = params["theme"]
        if isinstance(v, list):
            v = v[0]
        return response(f"<html><body>{v}</body></html>")  # reflected in text, not <style>

    findings = scan("theme", responder)
    assert not any("CSS Injection" in t for t in _titles(findings))




def test_open_redirect_via_meta_refresh_is_detected():
    def responder(params):
        v = params["url"]
        if isinstance(v, list):
            v = v[0]
        if v.startswith("https://example.com/qa-redirect-"):
            # DreadCTF-style: external URL returns 200 with a meta-refresh, not a 302.
            return response(f'<html><head><meta http-equiv="refresh" content="2;url={v}">'
                            f'</head><body>Redirecting to {v}</body></html>')
        return response("<html>ok</html>")

    findings = scan("url", responder)
    assert any("Open Redirect" in t for t in _titles(findings))


def test_open_redirect_via_javascript_location_is_detected():
    def responder(params):
        v = params["next"]
        if isinstance(v, list):
            v = v[0]
        if v.startswith("https://example.com/qa-redirect-"):
            return response(f'<html><body><script>location.href = "{v}"</script></body></html>')
        return response("<html>ok</html>")

    findings = scan("next", responder)
    assert any("Open Redirect" in t for t in _titles(findings))


def test_reflected_destination_without_redirect_is_not_flagged():
    # The payload merely appearing in the page (e.g. echoed) is NOT an open redirect.
    def responder(params):
        v = params["url"]
        if isinstance(v, list):
            v = v[0]
        return response(f"<html><body>You searched for {v}</body></html>")

    findings = scan("url", responder)
    assert not any("Open Redirect" in t for t in _titles(findings))
