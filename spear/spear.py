#!/usr/bin/env python3
"""
Spear — DREAD's internal-network assessment product.

Unifies capabilities that normally take several separate tools into one:
  - host discovery + service enumeration   (like nmap's host/port sweep)
  - name-resolution poisoning monitor       (the defensive inverse of Responder)
  - LAN interaction monitor                 (map who talks to whom, flag weak spots)

Use only on networks you own or are explicitly authorized to assess. Discovery
targets private ranges unless --allow-public is given.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

from recon import (
    COMMON_PORTS,
    HostDiscovery,
    ServiceScanner,
    tcp_connect_banner,
    tcp_ping,
)
from analysis import analyze_host
from lan_monitor import Interaction, build_lan_map
from poison_monitor import (
    Observation,
    analyze_observations,
    parse_llmnr_query,
    parse_nbns_query,
)

_SEVERITIES = ("critical", "high", "medium", "low", "info")


def run_scan(
    spec: str,
    *,
    prober: Callable[[str], bool],
    connector: Callable[..., Optional[str]],
    ports=COMMON_PORTS,
    allow_public: bool = False,
) -> Dict:
    """Discover live hosts and enumerate their services. I/O is injected for testability."""
    hosts = HostDiscovery(prober).discover(spec, allow_public=allow_public)
    scanner = ServiceScanner(connector)
    results = []
    for host in hosts:
        results.append({"host": host, "services": scanner.scan(host, ports=ports)})
    return {"target": spec, "hosts_up": len(hosts), "hosts": results}


def assess(
    spec: str,
    *,
    prober: Callable[[str], bool],
    connector: Callable[..., Optional[str]],
    ports=COMMON_PORTS,
    allow_public: bool = False,
    ttl_fn: Optional[Callable[[str], Optional[int]]] = None,
    hostname_fn: Optional[Callable[[str], Optional[str]]] = None,
) -> Dict:
    """Discover + enumerate + risk-analyze an internal range into report-shaped findings.

    Each live host is also labeled with a best-guess OS and a hostname (the
    "Advanced IP Scanner" view). ttl_fn/hostname_fn are injected for testability.
    """
    from fingerprint import (
        fingerprint_os,
        resolve_hostname,
        reverse_dns_lookup,
        ttl_via_ping,
    )

    ttl_fn = ttl_fn or ttl_via_ping
    hostname_fn = hostname_fn or (
        lambda ip: resolve_hostname(ip, reverse_dns=reverse_dns_lookup, netbios=lambda _ip: None)
    )

    scan = run_scan(spec, prober=prober, connector=connector, ports=ports, allow_public=allow_public)
    findings: List[Dict] = []
    for host in scan["hosts"]:
        ip = host["host"]
        open_ports = [s["port"] for s in host["services"]]
        banners = {s["port"]: s.get("banner", "") for s in host["services"]}
        try:
            ttl = ttl_fn(ip)
        except Exception:
            ttl = None
        host["os"] = fingerprint_os(ttl=ttl, open_ports=open_ports, banners=banners)
        try:
            host["hostname"] = hostname_fn(ip)
        except Exception:
            host["hostname"] = None
        findings.extend(analyze_host(ip, host["services"]))

    by_severity = {sev: sum(1 for f in findings if f["severity"] == sev) for sev in _SEVERITIES}
    return {
        "target": spec,
        "hosts_up": scan["hosts_up"],
        "hosts": scan["hosts"],
        "findings": findings,
        "rollups": {"total_findings": len(findings), "findings_by_severity": by_severity},
    }


def cmd_assess(args) -> int:
    ports = _parse_ports(args.ports)
    result = assess(
        args.target,
        prober=tcp_ping,
        connector=tcp_connect_banner,
        ports=ports,
        allow_public=args.allow_public,
    )
    print(f"[+] {result['hosts_up']} host(s) up, {result['rollups']['total_findings']} finding(s)",
          file=sys.stderr)
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        _print_findings({"findings": result["findings"]}, as_json=False)
    return 0


def _parse_ports(raw: Optional[str]):
    if not raw:
        return COMMON_PORTS
    return [int(p) for p in raw.replace(",", " ").split()]


def _print(data: Dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(data, indent=2, default=str))
        return
    for host in data.get("hosts", []):
        services = host["services"]
        print(f"\n{host['host']}  ({len(services)} service(s))")
        for s in services:
            banner = f"  {s['banner']}" if s.get("banner") else ""
            print(f"  {s['port']:>5}/{s['service']}{banner}")


def cmd_scan(args) -> int:
    data = run_scan(
        args.target,
        prober=tcp_ping,
        connector=tcp_connect_banner,
        allow_public=args.allow_public,
    )
    print(f"[+] {data['hosts_up']} host(s) up on {args.target}", file=sys.stderr)
    _print(data, args.json)
    return 0


def cmd_poison_watch(args) -> int:
    """Passively listen for LLMNR/NBT-NS queries and report poisoning exposure."""
    listeners = [
        ("LLMNR", 5355, parse_llmnr_query),
        ("NBT-NS", 137, parse_nbns_query),
    ]
    socks = []
    for proto, port, _parser in listeners:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
            s.settimeout(0.5)
            socks.append((proto, s, _parser))
        except OSError as e:
            print(f"[!] Could not bind {proto} :{port} ({e}); "
                  "run with privileges and ensure the port is free.", file=sys.stderr)

    if not socks:
        print("[!] No listeners could start. Poison monitoring needs privileged UDP bind.",
              file=sys.stderr)
        return 2

    print(f"[*] Listening for name-resolution poisoning exposure for {args.duration}s "
          "(passive; never answers).", file=sys.stderr)
    observations: List[Observation] = []
    deadline = time.time() + args.duration
    while time.time() < deadline:
        for proto, sock, parser in socks:
            try:
                data, addr = sock.recvfrom(4096)
            except (socket.timeout, OSError):
                continue
            name = parser(data)
            if name:
                observations.append(Observation(protocol=proto, src_ip=addr[0], name=name))

    report = analyze_observations(observations)
    _print_findings(report, args.json)
    return 0


def cmd_monitor(args) -> int:
    """Analyze observed LAN interactions from a flow file into a host/service map."""
    path = Path(args.from_file)
    if not path.is_file():
        print(f"[!] Flow file not found: {path}", file=sys.stderr)
        print("    Provide a JSON list of {src_ip, dst_ip, dst_port, protocol}. Live "
              "capture requires elevated packet-capture privileges (roadmap).",
              file=sys.stderr)
        return 2
    raw = json.loads(path.read_text())
    interactions = [
        Interaction(r["src_ip"], r["dst_ip"], int(r["dst_port"]), r.get("protocol", "tcp"))
        for r in raw
    ]
    lan_map = build_lan_map(interactions)
    if args.json:
        print(json.dumps(lan_map, indent=2, default=str))
    else:
        print(f"[+] {len(lan_map['hosts'])} host(s), {len(lan_map['services'])} service(s)")
        _print_findings(lan_map, as_json=False)
    return 0


def _print_findings(report: Dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(report, indent=2, default=str))
        return
    findings = report.get("findings", [])
    if not findings:
        print("[+] No findings.")
        return
    for f in sorted(findings, key=lambda x: x.get("severity", "")):
        print(f"\n[{f['severity'].upper()}] {f['title']}")
        print(f"  {f['description']}")
        if f.get("remediation"):
            print(f"  Fix: {f['remediation']}")


def cmd_info(_: argparse.Namespace) -> int:
    print(__doc__.strip())
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="spear", description="Spear — internal network assessment.")
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Discover hosts and enumerate services")
    scan.add_argument("target", help="CIDR, range (a-b), IP, or comma list (private by default)")
    scan.add_argument("--allow-public", action="store_true",
                      help="Permit public ranges (authorized external work only)")
    scan.add_argument("--json", action="store_true", help="JSON output")
    scan.set_defaults(func=cmd_scan)

    assess_p = sub.add_parser("assess", help="Discover, enumerate, and risk-analyze into findings")
    assess_p.add_argument("target", help="CIDR, range, IP, or comma list (private by default)")
    assess_p.add_argument("--ports", help="Comma/space-separated ports (default: common set)")
    assess_p.add_argument("--allow-public", action="store_true",
                          help="Permit public ranges (authorized external work only)")
    assess_p.add_argument("--json", action="store_true", help="JSON output")
    assess_p.set_defaults(func=cmd_assess)

    pw = sub.add_parser("poison-watch", help="Passively monitor LLMNR/NBT-NS poisoning exposure")
    pw.add_argument("--duration", type=int, default=60, help="Seconds to listen (default 60)")
    pw.add_argument("--json", action="store_true", help="JSON output")
    pw.set_defaults(func=cmd_poison_watch)

    mon = sub.add_parser("monitor", help="Analyze LAN interactions into a host/service map")
    mon.add_argument("--from-file", required=True, help="JSON list of observed interactions")
    mon.add_argument("--json", action="store_true", help="JSON output")
    mon.set_defaults(func=cmd_monitor)

    info = sub.add_parser("info", help="Product overview")
    info.set_defaults(func=cmd_info)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
