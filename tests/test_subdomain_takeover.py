"""Subdomain takeover detection: dangling CNAME + service fingerprint."""

from __future__ import annotations

import sys
from pathlib import Path

_SCOPE = Path(__file__).resolve().parents[1] / "scope"
if str(_SCOPE) not in sys.path:
    sys.path.insert(0, str(_SCOPE))

from discovery.takeover import (
    detect_takeovers,
    fingerprint_for_cname,
    is_vulnerable,
)


def test_fingerprint_matches_known_service_by_cname():
    fp = fingerprint_for_cname("myapp.github.io")
    assert fp is not None and fp["service"] == "GitHub Pages"

    assert fingerprint_for_cname("app.internal.example.com") is None


def test_is_vulnerable_requires_both_cname_and_fingerprint_body():
    fp = fingerprint_for_cname("foo.github.io")
    assert is_vulnerable(fp, "There isn't a GitHub Pages site here.") is True
    # CNAME points at the service, but the body is a live site -> not claimable.
    assert is_vulnerable(fp, "<html>my real site</html>") is False


def test_detect_takeovers_flags_dangling_cname():
    subs = ["gone.example.com", "live.example.com", "no-cname.example.com"]

    def resolve_cname(host):
        return {
            "gone.example.com": "orphan.github.io",
            "live.example.com": "app.github.io",
            "no-cname.example.com": None,
        }.get(host)

    def fetch(host):
        return {
            "gone.example.com": "There isn't a GitHub Pages site here.",
            "live.example.com": "<html>real content</html>",
        }.get(host, "")

    results = detect_takeovers(subs, resolve_cname=resolve_cname, fetch=fetch)

    assert len(results) == 1
    assert results[0]["subdomain"] == "gone.example.com"
    assert results[0]["service"] == "GitHub Pages"
    assert results[0]["severity"] == "high"


def test_detect_takeovers_handles_resolver_errors_gracefully():
    def boom(host):
        raise RuntimeError("dns down")

    assert detect_takeovers(["x.example.com"], resolve_cname=boom, fetch=lambda h: "") == []
