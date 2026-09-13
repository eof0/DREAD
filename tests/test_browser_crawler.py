"""Browser crawler: capturing real fetch/XHR and turning them into fuzz targets (pure parts)."""

from __future__ import annotations

import sys
from pathlib import Path

_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))

from scanner.browser_crawler import (
    CapturedRequest,
    captured_to_fuzz_targets,
    dedupe_requests,
    form_fill_value,
)

ALLOWED = {"app.test", "www.app.test"}


def test_get_with_query_becomes_a_query_target():
    reqs = [CapturedRequest("GET", "https://app.test/api/search?q=hi&page=2", None, None, "xhr")]
    targets = captured_to_fuzz_targets(reqs, ALLOWED)
    assert targets == [{
        "endpoint": "https://app.test/api/search",
        "params": {"q": "hi", "page": "2"},
        "method": "GET",
        "location": "query",
    }]


def test_json_post_becomes_a_json_target():
    reqs = [CapturedRequest("POST", "https://app.test/api/login",
                            '{"username":"neo","password":"x"}', "application/json", "fetch")]
    targets = captured_to_fuzz_targets(reqs, ALLOWED)
    assert targets[0]["method"] == "POST"
    assert targets[0]["location"] == "json"
    assert targets[0]["params"] == {"username": "neo", "password": "x"}


def test_form_post_becomes_a_form_target():
    reqs = [CapturedRequest("POST", "https://app.test/comment", "name=bob&body=hello",
                            "application/x-www-form-urlencoded", "fetch")]
    targets = captured_to_fuzz_targets(reqs, ALLOWED)
    assert targets[0]["location"] == "form"
    assert targets[0]["params"] == {"name": "bob", "body": "hello"}


def test_offsite_and_asset_requests_are_dropped():
    reqs = [
        CapturedRequest("GET", "https://cdn.other.test/app.js?v=1", None, None, "script"),
        CapturedRequest("GET", "https://app.test/logo.png?x=1", None, None, "image"),
        CapturedRequest("GET", "https://app.test/api/data?id=1", None, None, "xhr"),
    ]
    targets = captured_to_fuzz_targets(reqs, ALLOWED)
    assert [t["endpoint"] for t in targets] == ["https://app.test/api/data"]


def test_paramless_requests_are_dropped():
    # Nothing to fuzz if there are no parameters.
    reqs = [CapturedRequest("GET", "https://app.test/api/ping", None, None, "xhr")]
    assert captured_to_fuzz_targets(reqs, ALLOWED) == []


def test_dedupe_collapses_same_shape_requests():
    reqs = [
        CapturedRequest("GET", "https://app.test/api/x?id=1", None, None, "xhr"),
        CapturedRequest("GET", "https://app.test/api/x?id=2", None, None, "xhr"),  # same shape
        CapturedRequest("POST", "https://app.test/api/x", '{"id":1}', "application/json", "fetch"),
    ]
    deduped = dedupe_requests(reqs)
    assert len(deduped) == 2  # one GET shape + one POST shape


def test_form_fill_value_is_type_appropriate():
    assert "@" in form_fill_value("email")
    assert form_fill_value("password").isascii() and len(form_fill_value("password")) >= 8
    assert form_fill_value("age").isdigit()
    assert form_fill_value("website").startswith("http")
    assert form_fill_value("comment")  # non-empty generic


def test_crawler_queues_captured_endpoints_and_hands_targets_to_plugin(monkeypatch):
    import scanner.browser_crawler as bc
    from scanner.crawler import Crawler

    monkeypatch.setattr(bc, "crawl_interactive", lambda url, allowed, **kw: bc.BrowserResult(
        rendered=True,
        requests=[
            bc.CapturedRequest("GET", "https://app.test/api/me", None, None, "xhr"),
            bc.CapturedRequest("GET", "https://app.test/api/search?q=x", None, None, "fetch"),
            bc.CapturedRequest("POST", "https://app.test/api/login",
                               '{"user":"a"}', "application/json", "fetch"),
        ],
    ))

    class RH:
        class session:
            cookies = []
            headers = {}

    crawler = Crawler("https://app.test/", render_js=True)
    crawler.visited_urls.add("https://app.test/")
    crawler.urls_to_scan.append({"url": "https://app.test/", "depth": 0})
    crawler._browser_capture(RH())

    # /api/me (no params) still queued for CORS/other plugins.
    queued = {u["url"] for u in crawler.urls_to_scan if u.get("captured")}
    assert "https://app.test/api/me" in queued
    assert any(u.startswith("https://app.test/api/search?") for u in queued)
    # The entry-point url_info carries every captured target (incl the POST/JSON) for fuzzing.
    methods = {t["method"] for t in crawler.urls_to_scan[0]["captured_targets"]}
    assert methods == {"GET", "POST"}
