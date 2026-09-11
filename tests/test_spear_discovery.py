"""Spear internal discovery: target expansion, host sweep, service enumeration."""

from __future__ import annotations

import sys
from pathlib import Path

_SPEAR = Path(__file__).resolve().parents[1] / "spear"
if str(_SPEAR) not in sys.path:
    sys.path.insert(0, str(_SPEAR))

from recon import (
    HostDiscovery,
    ServiceScanner,
    expand_targets,
    identify_service,
)


def test_expand_cidr():
    hosts = expand_targets("192.168.1.0/30")
    # /30 usable hosts (network + broadcast excluded)
    assert hosts == ["192.168.1.1", "192.168.1.2"]


def test_expand_single_and_range_and_list():
    assert expand_targets("10.0.0.5") == ["10.0.0.5"]
    assert expand_targets("10.0.0.1-10.0.0.3") == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert expand_targets("10.0.0.1, 10.0.0.9") == ["10.0.0.1", "10.0.0.9"]


def test_expand_rejects_public_ranges_by_default():
    # Guardrail: internal tooling should refuse to sweep the public internet unless forced.
    import pytest

    with pytest.raises(ValueError):
        expand_targets("8.8.8.0/30")

    assert expand_targets("8.8.8.0/30", allow_public=True) == ["8.8.8.1", "8.8.8.2"]


def test_host_discovery_returns_only_alive_hosts():
    alive = {"192.168.1.1", "192.168.1.3"}
    disco = HostDiscovery(prober=lambda ip: ip in alive)

    assert disco.discover("192.168.1.0/29") == ["192.168.1.1", "192.168.1.3"]


def test_identify_service_by_port_and_banner():
    assert identify_service(22, "SSH-2.0-OpenSSH_9.6") == "ssh"
    assert identify_service(3389, "") == "rdp"
    assert identify_service(445, "") == "smb"
    assert identify_service(9999, "220 my-ftp ready") == "ftp"  # banner beats unknown port
    assert identify_service(9999, "") == "unknown"


def test_service_scanner_reports_open_ports_with_service():
    # connector returns a banner for open ports, None for closed.
    open_ports = {22: "SSH-2.0-OpenSSH_9.6", 80: "HTTP/1.1 200 OK"}

    scanner = ServiceScanner(connector=lambda ip, port, timeout=1.0: open_ports.get(port))
    result = scanner.scan("192.168.1.10", ports=[22, 80, 3306])

    assert [(s["port"], s["service"]) for s in result] == [(22, "ssh"), (80, "http")]
    assert result[0]["banner"].startswith("SSH-2.0")
