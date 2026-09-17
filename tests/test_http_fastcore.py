"""Concurrent HTTP fast-core: Rust/Go-accelerated bulk GET with a pure-Python fallback.

Both compiled binaries can be genuinely present on a dev machine (built on demand by
an earlier run), so every test here explicitly pins *both* `_rust_binary` and
`_go_binary` — never leaving one to fall through to a real on-disk build, which would
make these tests slow, network-dependent, and order-sensitive.
"""

from __future__ import annotations

import sys
from pathlib import Path

_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))

from scanner.engines import http as fastcore


class _Resp:
    def __init__(self, status, text="", headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}


def _no_compiled_engines(monkeypatch):
    """Force both compiled engines off so bulk_get() must use the Python fallback."""
    monkeypatch.setattr(fastcore, "_rust_binary", lambda: None)
    monkeypatch.setattr(fastcore, "_go_binary", lambda: None)


def test_empty_input_returns_empty():
    assert fastcore.bulk_get([]) == []


def test_python_fallback_returns_normalized_results(monkeypatch):
    _no_compiled_engines(monkeypatch)
    seen = {}

    def fake_get(url, **kwargs):
        seen[url] = kwargs
        return _Resp(200 if url.endswith("/ok") else 404, "body", {"Server": "x"})

    monkeypatch.setattr(fastcore.requests, "get", fake_get)

    results = fastcore.bulk_get(
        ["https://t.test/ok", "https://t.test/missing"],
        cookies={"session": "abc"}, headers={"X-Test": "1"})
    by_url = {r["url"]: r for r in results}
    assert by_url["https://t.test/ok"]["status"] == 200
    assert by_url["https://t.test/missing"]["status"] == 404
    # cookies became a Cookie header, and custom + UA headers were sent
    assert seen["https://t.test/ok"]["headers"]["Cookie"] == "session=abc"
    assert seen["https://t.test/ok"]["headers"]["X-Test"] == "1"
    assert "User-Agent" in seen["https://t.test/ok"]["headers"]


def test_python_fallback_reports_errors_per_url(monkeypatch):
    _no_compiled_engines(monkeypatch)

    def boom(url, **kwargs):
        raise OSError("dns fail")

    monkeypatch.setattr(fastcore.requests, "get", boom)
    results = fastcore.bulk_get(["https://dead.test/"])
    assert results[0]["status"] == 0
    assert "dns fail" in results[0]["error"]


def test_rust_preferred_when_both_compiled_engines_are_available(monkeypatch):
    calls = []
    monkeypatch.setattr(fastcore, "_rust_binary", lambda: Path("/fake/http-fetch-rs"))
    monkeypatch.setattr(fastcore, "_go_binary", lambda: Path("/fake/http_fetch"))

    def fake_run(binary, payload):
        calls.append(binary)
        return [{"url": u, "status": 200, "headers": {}, "body": "", "error": ""}
                for u in payload["urls"]]

    monkeypatch.setattr(fastcore, "_run_binary", fake_run)
    results = fastcore.bulk_get(["https://t.test/a"])

    assert results[0]["status"] == 200
    assert calls == [Path("/fake/http-fetch-rs")]   # Rust tried first, Go never touched


def test_uses_go_binary_when_rust_is_unavailable(monkeypatch):
    monkeypatch.setattr(fastcore, "_rust_binary", lambda: None)
    monkeypatch.setattr(fastcore, "_go_binary", lambda: Path("/fake/http_fetch"))
    monkeypatch.setattr(fastcore, "_run_binary",
                        lambda binary, payload: [{"url": u, "status": 200, "headers": {},
                                                  "body": "", "error": ""}
                                                 for u in payload["urls"]])
    results = fastcore.bulk_get(["https://t.test/a"])
    assert results[0]["status"] == 200


def test_rust_failure_falls_back_to_go(monkeypatch):
    monkeypatch.setattr(fastcore, "_rust_binary", lambda: Path("/fake/http-fetch-rs"))
    monkeypatch.setattr(fastcore, "_go_binary", lambda: Path("/fake/http_fetch"))

    def fake_run(binary, payload):
        if binary == Path("/fake/http-fetch-rs"):
            raise RuntimeError("rust crashed")
        return [{"url": u, "status": 200, "headers": {}, "body": "", "error": ""}
                for u in payload["urls"]]

    monkeypatch.setattr(fastcore, "_run_binary", fake_run)
    results = fastcore.bulk_get(["https://t.test/a"])
    assert results[0]["status"] == 200      # Go served it after Rust failed


def test_both_compiled_engines_failing_falls_back_to_python(monkeypatch):
    monkeypatch.setattr(fastcore, "_rust_binary", lambda: Path("/fake/http-fetch-rs"))
    monkeypatch.setattr(fastcore, "_go_binary", lambda: Path("/fake/http_fetch"))

    def boom(binary, payload):
        raise RuntimeError("crashed")

    monkeypatch.setattr(fastcore, "_run_binary", boom)
    monkeypatch.setattr(fastcore.requests, "get", lambda url, **k: _Resp(200, "ok"))
    results = fastcore.bulk_get(["https://t.test/a"])
    assert results[0]["status"] == 200      # Python fallback served it


def test_offensive_crawler_uses_fastcore_for_route_discovery(monkeypatch):
    from scanner.crawler import Crawler

    captured = {}

    def fake_bulk(urls, **kwargs):
        captured["urls"] = list(urls)
        out = []
        for u in urls:
            if u.endswith("/login"):
                out.append({"url": u, "status": 200})
            elif u.endswith("/admin"):
                out.append({"url": u, "status": 403})
            else:
                out.append({"url": u, "status": 404})
        return out

    monkeypatch.setattr(fastcore, "bulk_get", fake_bulk)

    class _Session:
        cookies = []
        headers = {"User-Agent": "x"}

    class _Handler:                     # real-session shape -> fast-core path
        session = _Session()
        verify_ssl = True

        def get(self, url, **kwargs):   # robots/sitemap/catch-all probe all 404
            return _Resp(404, "not found")

    crawler = Crawler("https://site.test/", max_depth=1, max_urls=80, aggressive=True)
    seeds = crawler.seed_urls(_Handler())

    assert captured.get("urls")                              # fast-core was invoked
    assert "https://site.test/login" in seeds               # 200 queued
    assert "https://site.test/admin" in seeds               # 403 queued
    assert not any(s.endswith("/nonexistent-zzz") for s in seeds)


def test_rust_binary_actually_builds_and_runs(tmp_path):
    """Real (non-mocked) build+run of the Rust fetcher, skipped when cargo is absent."""
    import shutil as _shutil

    if not _shutil.which("cargo"):
        import pytest
        pytest.skip("cargo not installed")

    binary = fastcore._rust_binary()
    assert binary is not None and binary.exists()

    import json
    import subprocess

    version = subprocess.run([str(binary), "--version"], capture_output=True, text=True)
    assert version.returncode == 0
    assert version.stdout.strip()

    # No network access required: two clearly-unroutable hosts is enough to prove the
    # binary parses its stdin protocol and emits well-formed per-URL JSON results.
    payload = {
        "urls": ["http://127.0.0.1:1/a", "http://127.0.0.1:1/b"],
        "timeout_ms": 1000, "concurrency": 2,
    }
    proc = subprocess.run([str(binary)], input=json.dumps(payload),
                          capture_output=True, text=True, timeout=15)
    assert proc.returncode == 0
    results = json.loads(proc.stdout)
    assert [r["url"] for r in results] == payload["urls"]     # input order preserved
    assert all(r["status"] == 0 and r["error"] for r in results)
