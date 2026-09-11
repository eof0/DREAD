"""
Subdomain takeover detection.

A takeover is possible when a subdomain's DNS still points (via CNAME) at a
third-party service, but no resource is claimed there any more: an attacker who
registers that resource then controls content served from the victim's subdomain.

Detection needs two signals together — a CNAME to a known service, and that
service's "unclaimed" response fingerprint — so a live site is never flagged.
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional

# CNAME suffix -> service + the body fingerprint a service shows for an unclaimed name.
# Curated from the widely-used can-i-take-over-xyz corpus; extend as needed.
FINGERPRINTS: tuple[dict, ...] = (
    {"service": "GitHub Pages", "cname": (".github.io",),
     "fingerprint": "There isn't a GitHub Pages site here.", "severity": "high"},
    {"service": "Amazon S3", "cname": (".s3.amazonaws.com", ".s3-website"),
     "fingerprint": "The specified bucket does not exist", "severity": "high"},
    {"service": "Heroku", "cname": (".herokuapp.com", ".herokudns.com"),
     "fingerprint": "No such app", "severity": "high"},
    {"service": "AWS/Elastic Beanstalk", "cname": (".elasticbeanstalk.com",),
     "fingerprint": "404 Not Found", "severity": "medium"},
    {"service": "Fastly", "cname": (".fastly.net",),
     "fingerprint": "Fastly error: unknown domain", "severity": "high"},
    {"service": "Shopify", "cname": (".myshopify.com",),
     "fingerprint": "Sorry, this shop is currently unavailable", "severity": "high"},
    {"service": "Surge.sh", "cname": (".surge.sh",),
     "fingerprint": "project not found", "severity": "high"},
    {"service": "Bitbucket", "cname": (".bitbucket.io",),
     "fingerprint": "Repository not found", "severity": "high"},
    {"service": "Ghost", "cname": (".ghost.io",),
     "fingerprint": "The thing you were looking for is no longer here", "severity": "medium"},
    {"service": "Pantheon", "cname": (".pantheonsite.io",),
     "fingerprint": "The gods are wise, but do not know of the site which you seek", "severity": "high"},
)


def fingerprint_for_cname(cname: str) -> Optional[dict]:
    """The service fingerprint whose CNAME suffix matches, or None."""
    host = (cname or "").strip().lower().rstrip(".")
    for fp in FINGERPRINTS:
        if any(suffix in host for suffix in fp["cname"]):
            return fp
    return None


def is_vulnerable(fingerprint: Optional[dict], body: str) -> bool:
    """True when the served body shows the service's unclaimed-resource fingerprint."""
    if not fingerprint:
        return False
    return fingerprint["fingerprint"].lower() in (body or "").lower()


def _resolve_cname_dns(host: str) -> Optional[str]:
    """Best-effort CNAME lookup using dnspython if present, else None."""
    try:
        import dns.resolver  # type: ignore

        answers = dns.resolver.resolve(host, "CNAME")
        for rdata in answers:
            return str(rdata.target).rstrip(".")
    except Exception:
        return None
    return None


def _fetch_body(host: str, timeout: int = 8) -> str:
    try:
        import requests

        for scheme in ("https", "http"):
            try:
                resp = requests.get(f"{scheme}://{host}/", timeout=timeout, allow_redirects=True)
                return resp.text or ""
            except Exception:
                continue
    except Exception:
        return ""
    return ""


def run_takeover_scan(subdomains: List[str], limit: int = 100) -> List[Dict]:
    """Network-backed takeover scan over discovered subdomains (best-effort)."""
    hosts = [s for s in subdomains if s and not s.startswith("Error:")][:limit]
    return detect_takeovers(hosts, resolve_cname=_resolve_cname_dns, fetch=_fetch_body)


def detect_takeovers(
    subdomains: List[str],
    *,
    resolve_cname: Callable[[str], Optional[str]],
    fetch: Callable[[str], str],
) -> List[Dict]:
    """
    Return a takeover finding per subdomain whose CNAME points at a known service
    that serves its unclaimed fingerprint. Resolver/fetcher are injected so this is
    testable and so the network layer can be swapped.
    """
    findings: List[Dict] = []
    for sub in subdomains:
        try:
            cname = resolve_cname(sub)
        except Exception:
            continue
        fingerprint = fingerprint_for_cname(cname or "")
        if not fingerprint:
            continue
        try:
            body = fetch(sub)
        except Exception:
            body = ""
        if is_vulnerable(fingerprint, body):
            findings.append({
                "subdomain": sub,
                "cname": cname,
                "service": fingerprint["service"],
                "severity": fingerprint["severity"],
                "detail": (
                    f"{sub} has a dangling CNAME to {cname} ({fingerprint['service']}); "
                    "the target resource is unclaimed and can be registered by an attacker."
                ),
            })
    return findings
