"""LAN interaction monitor: build a host/service map and flag hardening issues."""

from __future__ import annotations

import sys
from pathlib import Path

_SPEAR = Path(__file__).resolve().parents[1] / "spear"
if str(_SPEAR) not in sys.path:
    sys.path.insert(0, str(_SPEAR))

from lan_monitor import Interaction, build_lan_map


def test_map_lists_hosts_and_services_they_expose():
    interactions = [
        Interaction("192.168.1.10", "192.168.1.20", 22, "tcp"),
        Interaction("192.168.1.11", "192.168.1.20", 22, "tcp"),
        Interaction("192.168.1.10", "192.168.1.30", 445, "tcp"),
    ]
    m = build_lan_map(interactions)

    services = {(s["host"], s["port"]) for s in m["services"]}
    assert ("192.168.1.20", 22) in services
    assert ("192.168.1.30", 445) in services
    # 192.168.1.20:22 was reached by two distinct clients.
    ssh = next(s for s in m["services"] if s["host"] == "192.168.1.20" and s["port"] == 22)
    assert ssh["client_count"] == 2


def test_cleartext_protocols_are_flagged():
    interactions = [
        Interaction("192.168.1.10", "192.168.1.40", 23, "tcp"),   # telnet
        Interaction("192.168.1.10", "192.168.1.41", 80, "tcp"),   # http (internal)
    ]
    m = build_lan_map(interactions)

    titles = " ".join(f["title"].lower() for f in m["findings"])
    assert "telnet" in titles
    telnet = [f for f in m["findings"] if "telnet" in f["title"].lower()][0]
    assert telnet["severity"] == "high"


def test_external_egress_is_flagged():
    interactions = [Interaction("192.168.1.10", "8.8.8.8", 4444, "tcp")]
    m = build_lan_map(interactions)

    egress = [f for f in m["findings"] if "external" in f["title"].lower()]
    assert egress and "8.8.8.8" in egress[0]["description"]


def test_internal_only_https_traffic_has_no_findings():
    interactions = [Interaction("192.168.1.10", "192.168.1.50", 443, "tcp")]
    m = build_lan_map(interactions)

    assert m["findings"] == []
    assert len(m["hosts"]) == 2
