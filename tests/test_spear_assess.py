"""Spear `assess`: discovery + service enum + risk analysis into a report-shaped result."""

from __future__ import annotations

import json
import sys
from pathlib import Path

_SPEAR = Path(__file__).resolve().parents[1] / "spear"
if str(_SPEAR) not in sys.path:
    sys.path.insert(0, str(_SPEAR))

import spear


def test_assess_produces_findings_per_risky_service():
    alive = {"192.168.1.10", "192.168.1.11"}
    services = {
        ("192.168.1.10", 23): "Telnet server",
        ("192.168.1.10", 6379): "",
        ("192.168.1.11", 443): "TLS",
    }

    result = spear.assess(
        "192.168.1.8/29",  # hosts .9-.14, includes .10 and .11
        prober=lambda ip: ip in alive,
        connector=lambda ip, port, timeout=1.0: services.get((ip, port)),
        ports=[23, 443, 6379],
    )

    assert result["hosts_up"] == 2
    titles = {f["title"] for f in result["findings"]}
    assert any("Telnet" in t for t in titles)       # 192.168.1.10:23
    assert any("Redis" in t for t in titles)         # 192.168.1.10:6379
    # 192.168.1.11 only exposes HTTPS -> no finding for it.
    assert all(f["host"] != "192.168.1.11" for f in result["findings"])
    assert result["rollups"]["findings_by_severity"]["high"] >= 1


def test_assess_is_json_serializable():
    result = spear.assess(
        "10.0.0.1",
        prober=lambda ip: True,
        connector=lambda ip, port, timeout=1.0: "OpenSSH" if port == 22 else None,
        ports=[22],
    )
    json.dumps(result)  # must not raise


def test_assess_command_outputs_json(capsys, monkeypatch):
    monkeypatch.setattr(spear, "tcp_ping", lambda ip, **kw: ip == "10.0.0.1")
    monkeypatch.setattr(spear, "tcp_connect_banner",
                        lambda ip, port, timeout=1.0: "redis" if port == 6379 else None)

    rc = spear.main(["assess", "10.0.0.1", "--ports", "6379", "--json"])
    out = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert any("Redis" in f["title"] for f in out["findings"])


def test_assess_enriches_hosts_with_os_and_hostname():
    alive = {"10.0.0.5"}
    services = {("10.0.0.5", 445): "SMB", ("10.0.0.5", 3389): "RDP"}

    result = spear.assess(
        "10.0.0.5",
        prober=lambda ip: ip in alive,
        connector=lambda ip, port, timeout=1.0: services.get((ip, port)),
        ports=[445, 3389],
        ttl_fn=lambda ip: 128,                       # Windows TTL
        hostname_fn=lambda ip: "FILESERVER.corp.local",
    )

    host = result["hosts"][0]
    assert host["os"]["os_family"] == "Windows"
    assert host["hostname"] == "FILESERVER.corp.local"
