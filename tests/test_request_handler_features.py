"""RequestHandler: per-scan GET cache, dead-host circuit breaker, proxy rotation."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import requests

_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))

from scanner.request_handler import RequestHandler


class _FakeResp:
    def __init__(self, status=200):
        self.status_code = status
        self.headers = {"Content-Type": "text/html"}
        self.text = "ok"
        self.url = ""


# --- per-scan GET response cache ------------------------------------------------------

def test_identical_get_is_served_from_cache(monkeypatch):
    h = RequestHandler(rate_limit=0)
    calls = []
    monkeypatch.setattr(h.session, "request",
                        lambda m, u, **k: calls.append((m, u)) or _FakeResp())

    r1 = h.get("http://x.test/page")
    r2 = h.get("http://x.test/page")
    assert r1 is r2                 # same object returned
    assert len(calls) == 1          # second call served from cache, no network


def test_no_cache_bypass_forces_a_fresh_fetch(monkeypatch):
    h = RequestHandler(rate_limit=0)
    calls = []
    monkeypatch.setattr(h.session, "request",
                        lambda m, u, **k: calls.append(u) or _FakeResp())

    h.get("http://x.test/page")
    h.get("http://x.test/page", no_cache=True)
    assert len(calls) == 2          # bypass ignores the cache


def test_cache_key_varies_by_origin_header(monkeypatch):
    # cors_check sends a distinct Origin — it must not collide with the plain fetch.
    h = RequestHandler(rate_limit=0)
    calls = []
    monkeypatch.setattr(h.session, "request",
                        lambda m, u, **k: calls.append(k.get("headers")) or _FakeResp())

    h.get("http://x.test/api")
    h.get("http://x.test/api", headers={"Origin": "https://evil.example"})
    assert len(calls) == 2          # different headers -> different cache entry


def test_post_is_never_cached(monkeypatch):
    h = RequestHandler(rate_limit=0)
    calls = []
    monkeypatch.setattr(h.session, "request",
                        lambda m, u, **k: calls.append(m) or _FakeResp())

    h.post("http://x.test/submit", data={"a": "1"})
    h.post("http://x.test/submit", data={"a": "1"})
    assert calls == ["POST", "POST"]   # POST always hits the network


# --- dead-host circuit breaker --------------------------------------------------------

def test_dead_host_short_circuits_after_threshold(monkeypatch):
    h = RequestHandler(rate_limit=0, max_host_failures=3)
    calls = []

    def boom(m, u, **k):
        calls.append(u)
        raise requests.exceptions.ConnectionError("Name or service not known")

    monkeypatch.setattr(h.session, "request", boom)

    for _ in range(6):
        assert h.get("http://dead.test/") is None
    assert len(calls) == 3            # stops after 3 failures; rest short-circuit
    assert h.is_host_down("dead.test")


def test_success_resets_failure_count(monkeypatch):
    h = RequestHandler(rate_limit=0, max_host_failures=3)
    state = {"fail": True}

    def flaky(m, u, **k):
        if state["fail"]:
            raise requests.exceptions.ConnectionError("blip")
        return _FakeResp()

    monkeypatch.setattr(h.session, "request", flaky)
    h.get("http://host.test/a", no_cache=True)   # 1 failure
    state["fail"] = False
    h.get("http://host.test/b", no_cache=True)   # success resets
    state["fail"] = True
    for _ in range(2):
        h.get("http://host.test/c", no_cache=True)
    assert not h.is_host_down("host.test")       # never reached 3 consecutive


# --- proxy rotation -------------------------------------------------------------------

def test_proxies_rotate_round_robin(monkeypatch):
    h = RequestHandler(rate_limit=0, proxies=["http://p1:8080", "http://p2:8080"])
    seen = []
    monkeypatch.setattr(h.session, "request",
                        lambda m, u, **k: seen.append(k.get("proxies")) or _FakeResp())

    for i in range(3):
        h.get(f"http://x.test/{i}", no_cache=True)
    servers = [p["http"] for p in seen]
    assert servers == ["http://p1:8080", "http://p2:8080", "http://p1:8080"]


def test_no_proxies_sends_none(monkeypatch):
    h = RequestHandler(rate_limit=0)
    seen = []
    monkeypatch.setattr(h.session, "request",
                        lambda m, u, **k: seen.append("proxies" in k) or _FakeResp())
    h.get("http://x.test/", no_cache=True)
    assert seen == [False]


def test_abort_makes_all_requests_return_none(monkeypatch):
    h = RequestHandler(rate_limit=0)
    calls = []
    monkeypatch.setattr(h.session, "request",
                        lambda m, u, **k: calls.append(u) or _FakeResp())
    h.abort()
    assert h.get("http://x.test/", no_cache=True) is None
    assert h.post("http://x.test/submit", data={}) is None
    assert calls == []          # no network at all once aborted
    assert h.aborted


# --- proxy wiring: config + Playwright shape + CLI collection -------------------------

def test_scanconfig_stores_proxies_and_defaults_empty():
    from scanner.config import ScanConfig

    assert ScanConfig("http://x.test").proxies == []
    cfg = ScanConfig("http://x.test", proxies=["http://p:8080", " ", "http://p:8080 "])
    assert cfg.proxies == ["http://p:8080", "http://p:8080"]  # blanks dropped, trimmed


def test_playwright_proxy_parses_scheme_host_port_and_auth():
    from scanner.browser_crawler import playwright_proxy

    assert playwright_proxy(None) is None
    assert playwright_proxy("http://127.0.0.1:8080") == {"server": "http://127.0.0.1:8080"}
    assert playwright_proxy("socks5://user:pass@host:1080") == {
        "server": "socks5://host:1080", "username": "user", "password": "pass"}


def test_collect_proxies_merges_flag_and_file(tmp_path):
    import importlib, sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "probe"))
    probe = importlib.import_module("probe")

    pf = tmp_path / "proxies.txt"
    pf.write_text("# comment\nhttp://p2:8080\n\nhttp://p3:8080\n")
    got = probe._collect_proxies("http://p1:8080,http://p2:8080", str(pf))
    assert got == ["http://p1:8080", "http://p2:8080", "http://p3:8080"]  # deduped, ordered
