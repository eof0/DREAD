"""Access-control bypass plugin: a 401/403 path that a trivial mutation turns into 200."""

from __future__ import annotations

import sys
from pathlib import Path

_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))

from plugins.auth_bypass import AuthBypassPlugin


class _Resp:
    def __init__(self, status, body=""):
        self.status_code = status
        self.text = body
        self.headers = {"Content-Type": "text/html"}


class _Handler:
    def __init__(self, routes, header_opens=None):
        self.routes = routes                       # url -> (status, body)
        self.header_opens = header_opens or {}     # header-name -> opens the base url

    def get(self, url, **kwargs):
        headers = kwargs.get("headers") or {}
        for name in headers:
            if name in self.header_opens and url == self.header_opens[name]:
                return _Resp(200, "<h1>Admin Dashboard</h1>" + "x" * 300)
        status, body = self.routes.get(url, (404, ""))
        return _Resp(status, body)


CONTENT = "<h1>Admin Dashboard</h1>" + "x" * 400


def test_trailing_slash_bypass_is_flagged():
    routes = {
        "https://app.test/admin": (403, "Forbidden"),
        "https://app.test/admin/": (200, CONTENT),
    }
    url_info = {"url": "https://app.test/admin", "response": _Resp(403, "Forbidden"), "depth": 1}
    findings = AuthBypassPlugin().scan(url_info, _Handler(routes))
    assert len(findings) == 1
    assert "bypass" in findings[0].title.lower()


def test_header_bypass_is_flagged():
    url = "https://app.test/admin"
    handler = _Handler({url: (403, "Forbidden")},
                       header_opens={"X-Original-URL": url, "X-Forwarded-For": url})
    url_info = {"url": url, "response": _Resp(403, "Forbidden"), "depth": 1}
    findings = AuthBypassPlugin().scan(url_info, handler)
    assert len(findings) == 1


def test_no_finding_when_base_is_not_access_controlled():
    url_info = {"url": "https://app.test/", "response": _Resp(200, "home"), "depth": 0}
    assert AuthBypassPlugin().scan(url_info, _Handler({})) == []


def test_no_finding_when_nothing_bypasses():
    url = "https://app.test/admin"
    routes = {url: (403, "Forbidden")}          # every variant 404s
    url_info = {"url": url, "response": _Resp(403, "Forbidden"), "depth": 1}
    assert AuthBypassPlugin().scan(url_info, _Handler(routes)) == []


def test_login_page_200_is_not_a_bypass():
    # A variant returning a login page (200 but an auth challenge) must not count.
    routes = {
        "https://app.test/admin": (403, "Forbidden"),
        "https://app.test/admin/": (200, "<form>Please sign in to continue</form>"),
    }
    url_info = {"url": "https://app.test/admin", "response": _Resp(403), "depth": 1}
    assert AuthBypassPlugin().scan(url_info, _Handler(routes)) == []
