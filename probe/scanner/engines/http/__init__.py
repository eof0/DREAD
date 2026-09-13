"""Concurrent HTTP GET fast-core (Go, built on demand) with a pure-Python fallback.

The Python crawler makes many independent, rate-limited GETs during content discovery;
that request-heavy loop is where Python is slow. ``bulk_get`` fetches a batch of URLs
concurrently through a tiny Go binary (stdlib only, compiled on first use), and falls
back to a threaded Python fetcher when Go isn't available — so behavior is identical
either way, only faster when Go is present.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List, Optional

import requests  # module-level so tests can monkeypatch the fallback transport

GO_SOURCE = Path(__file__).parent / "fetch.go"
GO_BINARY = Path(__file__).parent / "http_fetch"

_DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


def _go_binary() -> Optional[Path]:
    """Path to the compiled Go fetcher, building it on demand when `go` is available."""
    if GO_BINARY.exists():
        return GO_BINARY
    if shutil.which("go"):
        try:
            result = subprocess.run(
                ["go", "build", "-o", str(GO_BINARY), str(GO_SOURCE)],
                capture_output=True, text=True, cwd=str(GO_SOURCE.parent), timeout=120,
            )
            if result.returncode == 0 and GO_BINARY.exists():
                return GO_BINARY
        except (OSError, subprocess.SubprocessError):
            pass
    return None


def _run_go(binary: Path, payload: dict) -> List[Dict]:
    proc = subprocess.run(
        [str(binary)], input=json.dumps(payload), capture_output=True, text=True,
        timeout=max(30, payload.get("timeout_ms", 8000) / 1000 + 10),
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        raise RuntimeError(f"go fetcher failed: {proc.stderr[:200]}")
    return json.loads(proc.stdout)


def _run_python(urls, headers, timeout_ms, concurrency, proxy, allow_redirects,
                insecure, max_body) -> List[Dict]:
    proxies = {"http": proxy, "https": proxy} if proxy else None
    timeout = max(0.1, timeout_ms / 1000)

    def _one(url: str) -> Dict:
        try:
            resp = requests.get(url, headers=headers, timeout=timeout, proxies=proxies,
                                allow_redirects=allow_redirects, verify=not insecure)
            return {
                "url": url, "status": resp.status_code,
                "headers": {k: v for k, v in resp.headers.items()},
                "body": (resp.text or "")[:max_body], "error": "",
            }
        except Exception as exc:  # noqa: BLE001 - report per-URL, never abort the batch
            return {"url": url, "status": 0, "headers": {}, "body": "", "error": str(exc)}

    with ThreadPoolExecutor(max_workers=max(1, min(concurrency, len(urls) or 1))) as pool:
        return list(pool.map(_one, urls))


def bulk_get(urls, *, headers: Optional[Dict[str, str]] = None,
             cookies: Optional[Dict[str, str]] = None, timeout_ms: int = 8000,
             concurrency: int = 50, proxy: Optional[str] = None,
             allow_redirects: bool = False, insecure: bool = False,
             max_body: int = 200000) -> List[Dict]:
    """Fetch every URL concurrently; return a result dict per URL (input order).

    Each result: ``{"url", "status", "headers", "body", "error"}`` (status 0 on error).
    """
    urls = list(urls)
    if not urls:
        return []
    headers = dict(headers or {})
    headers.setdefault("User-Agent", _DEFAULT_UA)
    if cookies:
        cookie = "; ".join(f"{k}={v}" for k, v in cookies.items() if k)
        if cookie:
            headers["Cookie"] = cookie

    binary = _go_binary()
    if binary is not None:
        payload = {
            "urls": urls, "timeout_ms": timeout_ms, "concurrency": concurrency,
            "headers": headers, "proxy": proxy or "", "allow_redirects": allow_redirects,
            "insecure": insecure, "max_body": max_body,
        }
        try:
            return _run_go(binary, payload)
        except Exception:  # noqa: BLE001 - fall back to Python on any Go failure
            pass
    return _run_python(urls, headers, timeout_ms, concurrency, proxy, allow_redirects,
                       insecure, max_body)
