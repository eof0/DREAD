"""OS fingerprinting: TTL + open-port + banner heuristics; hostname resolution."""

from __future__ import annotations

import sys
from pathlib import Path

_SPEAR = Path(__file__).resolve().parents[1] / "spear"
if str(_SPEAR) not in sys.path:
    sys.path.insert(0, str(_SPEAR))

from fingerprint import (
    fingerprint_os,
    guess_initial_ttl,
    resolve_hostname,
    ttl_from_ping_output,
)


def test_guess_initial_ttl_rounds_up_to_known_starts():
    assert guess_initial_ttl(54) == 64      # Linux, a few hops away
    assert guess_initial_ttl(64) == 64
    assert guess_initial_ttl(118) == 128    # Windows
    assert guess_initial_ttl(250) == 255    # network gear
    assert guess_initial_ttl(None) is None


def test_fingerprint_from_ttl():
    linux = fingerprint_os(ttl=64, open_ports=[], banners={})
    assert linux["os_family"] == "Linux/Unix"

    windows = fingerprint_os(ttl=128, open_ports=[], banners={})
    assert windows["os_family"] == "Windows"

    gear = fingerprint_os(ttl=255, open_ports=[], banners={})
    assert gear["os_family"] == "Network device"


def test_ports_reinforce_windows():
    fp = fingerprint_os(ttl=128, open_ports=[135, 139, 445, 3389], banners={})
    assert fp["os_family"] == "Windows"
    assert fp["confidence"] >= 0.8  # TTL and SMB/RDP ports agree


def test_banner_beats_ambiguous_ttl():
    fp = fingerprint_os(ttl=None, open_ports=[80], banners={80: "Microsoft-IIS/10.0"})
    assert fp["os_family"] == "Windows"

    fp2 = fingerprint_os(ttl=None, open_ports=[22], banners={22: "SSH-2.0-OpenSSH_9.6 Ubuntu"})
    assert fp2["os_family"] == "Linux/Unix"


def test_unknown_when_no_signal():
    fp = fingerprint_os(ttl=None, open_ports=[], banners={})
    assert fp["os_family"] == "Unknown"
    assert fp["confidence"] == 0.0


def test_ttl_from_ping_output():
    linux_ping = "64 bytes from 10.0.0.5: icmp_seq=1 ttl=63 time=0.4 ms"
    assert ttl_from_ping_output(linux_ping) == 63
    assert ttl_from_ping_output("no ttl here") is None
    # Windows ping uses uppercase TTL.
    assert ttl_from_ping_output("Reply from 10.0.0.5: bytes=32 time<1ms TTL=128") == 128


def test_resolve_hostname_prefers_reverse_dns_then_netbios():
    assert resolve_hostname("10.0.0.5",
                            reverse_dns=lambda ip: "server.corp.local",
                            netbios=lambda ip: "SERVER") == "server.corp.local"

    # Falls back to NetBIOS when reverse DNS has nothing.
    assert resolve_hostname("10.0.0.5",
                            reverse_dns=lambda ip: None,
                            netbios=lambda ip: "SERVER") == "SERVER"

    assert resolve_hostname("10.0.0.5",
                            reverse_dns=lambda ip: None,
                            netbios=lambda ip: None) is None
