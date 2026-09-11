"""
OS fingerprinting and hostname resolution for Spear.

The "press a button and it tells you what's out there" experience: for each live
host, guess the operating system from cheap signals (the IP TTL, which common
services are open, and any banners) and resolve a friendly hostname. Heuristic, not
authoritative — but enough to label a network map at a glance.

The scoring is pure and testable; the network helpers (ping for TTL, reverse DNS,
NetBIOS name query) are thin and injectable.
"""

from __future__ import annotations

import re
from typing import Callable, Dict, List, Optional

# Common initial TTL values by stack; observed TTL is this minus the hop count.
_INITIAL_TTLS = (64, 128, 255)
_TTL_OS = {64: "Linux/Unix", 128: "Windows", 255: "Network device"}

# Ports that strongly imply a platform.
_WINDOWS_PORTS = {135, 137, 139, 445, 3389, 5985, 5986}
_UNIX_PORTS = {22}

_BANNER_HINTS = (
    ("Windows", ("microsoft-iis", "windows", "win32", "win64", " microsoft")),
    ("Linux/Unix", ("openssh", "ubuntu", "debian", "centos", "linux", "apache", "nginx",
                    "unix")),
    ("Network device", ("cisco", "mikrotik", "routeros", "juniper", "fortinet", "dd-wrt")),
)


def guess_initial_ttl(observed: Optional[int]) -> Optional[int]:
    """Round an observed TTL up to the nearest known initial TTL (accounts for hops)."""
    if observed is None:
        return None
    for start in _INITIAL_TTLS:
        if observed <= start:
            return start
    return None


def ttl_from_ping_output(text: str) -> Optional[int]:
    """Parse the TTL from `ping` output (handles both `ttl=` and Windows `TTL=`)."""
    match = re.search(r"ttl[=\s]*(\d+)", text or "", re.IGNORECASE)
    return int(match.group(1)) if match else None


def fingerprint_os(ttl: Optional[int], open_ports: List[int], banners: Dict[int, str]) -> Dict:
    """Best-guess OS family with a confidence (0..1) and the reasons behind it."""
    scores: Dict[str, float] = {"Linux/Unix": 0.0, "Windows": 0.0, "Network device": 0.0}
    reasons: List[str] = []

    initial = guess_initial_ttl(ttl)
    if initial is not None:
        os_by_ttl = _TTL_OS[initial]
        scores[os_by_ttl] += 0.5
        reasons.append(f"TTL {ttl} -> initial {initial} ({os_by_ttl})")

    ports = set(open_ports or [])
    win_hits = ports & _WINDOWS_PORTS
    if win_hits:
        scores["Windows"] += min(0.15 * len(win_hits), 0.45)
        reasons.append(f"Windows-typical ports open: {sorted(win_hits)}")
    if ports & _UNIX_PORTS:
        scores["Linux/Unix"] += 0.3
        reasons.append("SSH (22) open")

    for text in (banners or {}).values():
        low = str(text).lower()
        for family, needles in _BANNER_HINTS:
            if any(n in low for n in needles):
                scores[family] += 0.6
                reasons.append(f"banner matched {family}: {text[:40]!r}")
                break

    family = max(scores, key=scores.get)
    top = scores[family]
    if top <= 0.0:
        return {"os_family": "Unknown", "confidence": 0.0, "reasons": []}
    return {"os_family": family, "confidence": round(min(top, 1.0), 2), "reasons": reasons}


def resolve_hostname(
    ip: str,
    *,
    reverse_dns: Callable[[str], Optional[str]],
    netbios: Callable[[str], Optional[str]],
) -> Optional[str]:
    """A friendly hostname for an IP: reverse DNS first, then NetBIOS name."""
    try:
        name = reverse_dns(ip)
    except Exception:
        name = None
    if name:
        return name
    try:
        return netbios(ip) or None
    except Exception:
        return None


# ---- default network helpers (injected in tests) ----

def ttl_via_ping(host: str, timeout: float = 1.0) -> Optional[int]:
    """Observed TTL from a single ping (no raw sockets needed)."""
    import subprocess

    try:
        proc = subprocess.run(
            ["ping", "-c", "1", "-W", str(int(max(timeout, 1))), host],
            capture_output=True, text=True, timeout=timeout + 2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return ttl_from_ping_output(proc.stdout)


def reverse_dns_lookup(ip: str) -> Optional[str]:
    import socket

    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror):
        return None
