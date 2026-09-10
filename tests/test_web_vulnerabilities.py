from html import escape
from urllib.parse import urlparse

from requests import Response

from plugins.web_vulnerabilities import (
    WebVulnerabilitiesPlugin,
    discover_get_targets,
    discover_json_targets,
)
from scanner.crawler import Crawler
from plugins.base_plugin import Finding


def response(body="<html></html>", status=200, headers=None):
    result = Response()
    result.status_code = status
    result._content = body.encode()
    result.encoding = "utf-8"
    result.headers = {"Content-Type": "text/html", **(headers or {})}
    return result


class Handler:
    def __init__(self, responder=None, page_html="<html></html>", page_headers=None):
        self.responder = responder or (lambda _params: response())
        self.page_html = page_html
        self.page_headers = page_headers
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        params = kwargs.get("params")
        if params is None:
            return response(self.page_html, headers=self.page_headers)
        return self.responder(params)


def scan(parameter, responder, page_html="<html></html>", value="safe", page_headers=None):
    handler = Handler(responder, page_html, page_headers)
    findings = WebVulnerabilitiesPlugin().scan(
        {"url": f"https://example.test/search?{parameter}={value}", "depth": 0},
        handler,
    )
    return findings, handler


def test_runs_dom_check_for_html_pages(monkeypatch):
    finding = Finding(
        "web_vulnerabilities", "high", "DOM-based XSS", "", "https://example.test/"
    )
    monkeypatch.setattr(
        "plugins.web_vulnerabilities.dom_xss.scan_dom",
        lambda url: [finding],
    )

    findings, _ = scan("q", lambda _params: response())

    assert findings == [finding]


def test_discovers_json_get_parameters_without_body_keys():
    assert discover_json_targets(
        "https://example.test/api?query=ok",
        '{"query":"ok","nested":{"secret":"x"}}',
    ) == [("https://example.test/api", {"query": "ok"})]


def test_discovers_query_parameters_and_same_origin_get_forms():
    html = """
    <form action="/lookup" method="get">
      <input name="q" value="pears">
      <select name="category"><option value="fruit" selected>Fruit</option></select>
    </form>
    <form action="https://evil.test/collect" method="get"><input name="x"></form>
    <form action="/change" method="post"><input name="name"></form>
    """

    targets = discover_get_targets(
        "https://example.test/page?id=7",
        html,
    )

    assert targets == [
        ("https://example.test/page", {"id": "7"}),
        (
            "https://example.test/lookup",
            {"q": "pears", "category": "fruit"},
        ),
    ]


def test_active_plugin_rejects_request_preparation_origin_bypass():
    redirected = response(
        '<form action="https://evil.test\\@example.test/steal" method="get">'
        '<input name="q" value="safe"></form>'
    )
    redirected.url = "https://example.test/page"
    handler = Handler()

    findings = WebVulnerabilitiesPlugin().scan(
        {
            "url": "https://example.test/start",
            "depth": 0,
            "response": redirected,
        },
        handler,
    )

    assert findings == []
    assert handler.calls == []


def test_discovery_ignores_form_actions_with_malformed_ports():
    targets = discover_get_targets(
        "https://example.test/page",
        '<form action="https://example.test:notaport/search" method="get">'
        '<input name="q"></form>',
    )

    assert targets == []


def test_discovery_normalizes_equivalent_ipv6_hosts():
    targets = discover_get_targets(
        "https://[::1]/page",
        '<form action="https://[0:0:0:0:0:0:0:1]/search" method="get">'
        '<input name="q"></form>',
    )

    assert targets == [
        ("https://[0:0:0:0:0:0:0:1]/search", {"q": ""})
    ]


def test_get_forms_submit_only_successful_controls_and_keep_repeated_values():
    html = """
    <form action="/filter" method="get">
      <fieldset disabled>
        <input name="delete" value="1">
      </fieldset>
      <input type="radio" name="scope" value="private">
      <input type="radio" name="scope" value="public" checked>
      <input type="checkbox" name="tag" value="one" checked>
      <input type="checkbox" name="tag" value="two" checked>
      <select name="region" multiple>
        <option value="us" selected>US</option>
        <option value="eu" selected>EU</option>
      </select>
    </form>
    """

    assert discover_get_targets("https://example.test/", html) == [
        (
            "https://example.test/filter",
            {
                "scope": "public",
                "tag": ["one", "two"],
                "region": ["us", "eu"],
            },
        )
    ]


def test_detects_reflected_xss_only_when_payload_becomes_markup():
    def responder(params):
        value = params["q"]
        if "dread-probe" in value:
            return response(f"<html>{value}</html>")
        return response()

    findings, _ = scan("q", responder)

    assert [finding.title for finding in findings] == ["Reflected XSS in parameter 'q'"]
    assert findings[0].evidence["parameter"] == "q"


def test_escaped_reflection_is_not_reported_as_xss():
    def responder(params):
        value = params["q"]
        return response(f"<html>{escape(value)}</html>")

    findings, _ = scan("q", responder)

    assert all("XSS" not in finding.title for finding in findings)


def test_json_endpoint_is_actively_checked():
    def responder(params):
        if params["query"].startswith("../../"):
            return response('{"error":"root:x:0:0"}', headers={"Content-Type": "application/json"})
        return response('{"query":"ok"}', headers={"Content-Type": "application/json"})

    findings, _ = scan(
        "query",
        responder,
        page_html='{"query":"ok"}',
        page_headers={"Content-Type": "application/json"},
    )

    assert any("Path Traversal" in finding.title for finding in findings)


def test_non_html_reflection_is_not_reported_as_xss():
    def responder(params):
        value = params["q"]
        return response(value, headers={"Content-Type": "application/json"})

    findings, _ = scan("q", responder)

    assert all("XSS" not in finding.title for finding in findings)


def test_detects_new_sql_error_signature_without_leaking_original_value():
    def responder(params):
        if params["id"].endswith("'"):
            return response("You have an error in your SQL syntax")
        return response("record 7")

    findings, _ = scan("id", responder, value="secret-token")

    assert [finding.title for finding in findings] == [
        "SQL Injection Error in parameter 'id'"
    ]
    assert "secret-token" not in findings[0].evidence["payload"]


def test_detects_command_injection_marker():
    def responder(params):
        if "dread-cmd-" in params["cmd"]:
            return response(params["cmd"])
        return response("safe")

    findings, _ = scan("cmd", responder)

    assert [finding.title for finding in findings] == [
        "Command Injection in parameter 'cmd'"
    ]


def test_detects_template_expression_evaluation():
    def responder(params):
        if params["template"] == "{{7*7}}":
            return response("49")
        return response("safe")

    findings, _ = scan("template", responder)

    assert [finding.title for finding in findings] == [
        "Server-Side Template Injection in parameter 'template'"
    ]


def test_detects_local_file_inclusion_signature():
    def responder(params):
        if params["file"].startswith("php://filter"):
            return response("cm9vdDp4")
        return response("safe")

    findings, _ = scan("file", responder)

    assert any("Local File Inclusion" in finding.title for finding in findings)


def test_existing_sql_error_is_not_reported():
    def responder(_params):
        return response("You have an error in your SQL syntax")

    findings, _ = scan("id", responder)

    assert all("SQL Injection" not in finding.title for finding in findings)


def test_detects_unix_path_traversal_signature():
    def responder(params):
        if params["file"].startswith("../"):
            return response("root:x:0:0:root:/root:/bin/bash")
        return response()

    findings, _ = scan("file", responder)

    assert [finding.title for finding in findings] == [
        "Path Traversal in parameter 'file'"
    ]


def test_detects_windows_path_traversal_signature():
    def responder(params):
        if "windows\\win.ini" in params["file"].lower():
            return response("[fonts]\n[extensions]")
        return response()

    findings, _ = scan("file", responder)

    assert [finding.title for finding in findings] == [
        "Path Traversal in parameter 'file'"
    ]


def test_detects_exact_open_redirect_without_following_it():
    def responder(params):
        destination = params["next"]
        if destination.startswith("https://example.com/dread-redirect-"):
            return response("", 302, {"Location": destination})
        return response()

    findings, handler = scan("next", responder)

    assert [finding.title for finding in findings] == [
        "Open Redirect in parameter 'next'"
    ]
    redirect_calls = [
        kwargs
        for _url, kwargs in handler.calls
        if (kwargs.get("params") or {}).get("next", "").startswith(
            "https://example.com/dread-redirect-"
        )
    ]
    assert redirect_calls[0]["allow_redirects"] is False


def test_limits_each_page_to_six_parameters():
    query = "&".join(f"p{i}=safe" for i in range(8))
    handler = Handler()

    WebVulnerabilitiesPlugin().scan(
        {"url": f"https://example.test/?{query}", "depth": 0},
        handler,
    )

    mutated = {
        key
        for _url, kwargs in handler.calls
        for key, value in (kwargs.get("params") or {}).items()
        if value != "safe"
    }
    assert mutated == {f"p{i}" for i in range(6)}


def test_discovered_targets_never_leave_the_origin():
    targets = discover_get_targets(
        "https://example.test/page",
        '<form action="//evil.test/search" method="get"><input name="q"></form>',
    )

    assert all(urlparse(url).netloc == "example.test" for url, _params in targets)


def test_crawler_retains_response_for_plugins():
    cached = response('<html><a href="/next">next</a></html>')

    class CachedHandler:
        def get(self, _url):
            return cached

    crawled = Crawler(
        "https://example.test/",
        max_depth=0,
        max_urls=1,
    ).crawl(CachedHandler())

    assert crawled[0]["response"] is cached


def test_active_plugin_reuses_crawler_response():
    cached = response("<html></html>")
    handler = Handler()

    WebVulnerabilitiesPlugin().scan(
        {
            "url": "https://example.test/?q=safe",
            "depth": 0,
            "response": cached,
        },
        handler,
    )

    assert all(kwargs.get("params") is not None for _url, kwargs in handler.calls)


def test_active_plugin_rejects_cross_origin_redirect_responses():
    redirected = response(
        '<form action="/danger" method="get"><input name="delete" value="1"></form>'
    )
    redirected.url = "https://evil.test/page"
    handler = Handler()

    findings = WebVulnerabilitiesPlugin().scan(
        {
            "url": "https://example.test/start",
            "depth": 0,
            "response": redirected,
        },
        handler,
    )

    assert findings == []
    assert handler.calls == []


def test_active_plugin_allows_explicit_default_port_redirects():
    redirected = response("<html></html>")
    redirected.url = "https://example.test:443/search?q=safe"
    handler = Handler()

    WebVulnerabilitiesPlugin().scan(
        {
            "url": "https://example.test/start",
            "depth": 0,
            "response": redirected,
        },
        handler,
    )

    assert handler.calls
    assert {url for url, _kwargs in handler.calls} == {
        "https://example.test:443/search"
    }


def test_active_plugin_normalizes_idna_redirect_hosts():
    redirected = response("<html></html>")
    redirected.url = "https://xn--bcher-kva.test/search?q=safe"
    handler = Handler()

    WebVulnerabilitiesPlugin().scan(
        {
            "url": "https://bücher.test/start",
            "depth": 0,
            "response": redirected,
        },
        handler,
    )

    assert handler.calls


def test_active_plugin_resolves_forms_from_same_origin_final_url():
    redirected = response(
        '<form action="danger" method="get"><input name="q" value="safe"></form>'
    )
    redirected.url = "https://example.test/redirected/page"
    handler = Handler()

    WebVulnerabilitiesPlugin().scan(
        {
            "url": "https://example.test/start",
            "depth": 0,
            "response": redirected,
        },
        handler,
    )

    assert handler.calls
    assert {url for url, _kwargs in handler.calls} == {
        "https://example.test/redirected/danger"
    }
