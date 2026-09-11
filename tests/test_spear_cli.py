"""Spear CLI orchestration and monitor subcommand."""

from __future__ import annotations

import json
import sys
from pathlib import Path

_SPEAR = Path(__file__).resolve().parents[1] / "spear"
if str(_SPEAR) not in sys.path:
    sys.path.insert(0, str(_SPEAR))

import spear


def test_run_scan_combines_discovery_and_service_enum():
    alive = {"192.168.1.1", "192.168.1.2"}
    open_services = {("192.168.1.1", 22): "SSH-2.0-OpenSSH_9.6"}

    data = spear.run_scan(
        "192.168.1.0/29",
        prober=lambda ip: ip in alive,
        connector=lambda ip, port, timeout=1.0: open_services.get((ip, port)),
        ports=[22, 80],
    )

    assert data["hosts_up"] == 2
    host1 = next(h for h in data["hosts"] if h["host"] == "192.168.1.1")
    assert [s["service"] for s in host1["services"]] == ["ssh"]
    host2 = next(h for h in data["hosts"] if h["host"] == "192.168.1.2")
    assert host2["services"] == []


def test_monitor_subcommand_reads_flow_file(tmp_path, capsys):
    flows = [
        {"src_ip": "192.168.1.10", "dst_ip": "192.168.1.40", "dst_port": 23},
        {"src_ip": "192.168.1.10", "dst_ip": "192.168.1.50", "dst_port": 443},
    ]
    path = tmp_path / "flows.json"
    path.write_text(json.dumps(flows))

    rc = spear.main(["monitor", "--from-file", str(path), "--json"])
    out = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert any("telnet" in f["title"].lower() for f in out["findings"])


def test_monitor_missing_file_errors_cleanly(tmp_path):
    rc = spear.main(["monitor", "--from-file", str(tmp_path / "nope.json")])
    assert rc == 2
