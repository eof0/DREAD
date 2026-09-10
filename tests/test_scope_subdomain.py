from __future__ import annotations

import json
import threading
import time

import requests

from scope.discovery import subdomain as subdomain_mod
from scope.discovery.subdomain import SubdomainDiscovery, normalize_target_hostname


class _FakeResponse:
    def __init__(self, chunks):
        self._chunks = chunks

    def raise_for_status(self):
        pass

    def iter_content(self, chunk_size=65536):
        yield from self._chunks

    def close(self):
        pass


def test_from_crtsh_parses_and_filters(monkeypatch) -> None:
    sd = SubdomainDiscovery()
    payload = json.dumps(
        [
            {"name_value": "www.example.com\n*.example.com"},
            {"name_value": "api.example.com"},
            {"name_value": "unrelated.org"},
        ]
    ).encode()
    monkeypatch.setattr(sd.session, "get", lambda *a, **k: _FakeResponse([payload]))
    assert sd._from_crtsh("example.com") == ["api.example.com", "example.com", "www.example.com"]


def test_from_crtsh_skips_on_timeout(monkeypatch) -> None:
    sd = SubdomainDiscovery()

    def _timeout(*a, **k):
        raise requests.Timeout("crt.sh slow")

    monkeypatch.setattr(sd.session, "get", _timeout)
    # A failed source returns nothing, never a raised error or an "Error:" pseudo-subdomain.
    assert sd._from_crtsh("example.com") == []


def test_from_crtsh_aborts_past_deadline(monkeypatch) -> None:
    sd = SubdomainDiscovery()

    class _SlowResponse:
        def raise_for_status(self):
            pass

        def iter_content(self, chunk_size=65536):
            while True:
                time.sleep(0.01)
                yield b"x"

        def close(self):
            pass

    monkeypatch.setattr(sd.session, "get", lambda *a, **k: _SlowResponse())
    monkeypatch.setattr(subdomain_mod, "CRTSH_DEADLINE", 0.1)
    started = time.monotonic()
    assert sd._from_crtsh("example.com") == []
    assert time.monotonic() - started < 3


def test_discover_normalizes_url_target(monkeypatch) -> None:
    sd = SubdomainDiscovery()

    def _fake_crt(domain: str):
        assert domain == "example.com"
        return ["www.example.com"]

    monkeypatch.setattr(sd, "_from_crtsh", _fake_crt)
    monkeypatch.setattr(sd, "_common_subdomains", lambda d: [])
    monkeypatch.setattr(sd, "_from_ssl_cert", lambda d: [])

    out = sd.discover("https://example.com/path?q=1")
    assert out["all_unique"] == ["www.example.com"]


def test_common_subdomains_filters_and_orders_correctly(monkeypatch) -> None:
    sd = SubdomainDiscovery()

    resolvable = {"www.example.com", "api.example.com"}

    def _fake_resolvable(hostname: str) -> bool:
        return hostname in resolvable

    monkeypatch.setattr(sd, "_is_resolvable", _fake_resolvable)

    found = sd._common_subdomains("example.com")
    assert found == ["api.example.com", "www.example.com"]


def test_common_subdomains_actually_runs_checks_concurrently(monkeypatch) -> None:
    # Prove genuine parallelism, not just correct-looking output, by
    # tracking how many _is_resolvable calls are in flight at once. A
    # sequential implementation can never have more than 1 in flight.
    sd = SubdomainDiscovery()
    lock = threading.Lock()
    state = {"current": 0, "peak": 0}

    def _fake_resolvable(hostname: str) -> bool:
        with lock:
            state["current"] += 1
            state["peak"] = max(state["peak"], state["current"])
        time.sleep(0.05)
        with lock:
            state["current"] -= 1
        return False

    monkeypatch.setattr(sd, "_is_resolvable", _fake_resolvable)

    sd._common_subdomains("example.com")

    assert state["peak"] > 1, "checks should overlap when run through a thread pool"


def test_normalize_target_hostname_strips_url_and_path() -> None:
    assert normalize_target_hostname("HTTPS://Example.COM/path") == "example.com"
    assert normalize_target_hostname("  ") == ""


def test_discover_empty_input_returns_empty_collections() -> None:
    sd = SubdomainDiscovery()
    out = sd.discover("   ")
    assert out == {
        "certificate_transparency": [],
        "common_wordlist": [],
        "ssl_certificate": [],
        "all_unique": [],
    }
