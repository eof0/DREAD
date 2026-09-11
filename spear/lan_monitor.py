"""
LAN interaction monitor.

Passively ingests observed interactions (who connected to whom, on what port) and
builds a picture of the network: which hosts expose which services, and where the
hardening opportunities are — cleartext protocols, risky management services, and
traffic leaving for the internet. Purely analytical; the packet/flow capture that
feeds it is injected by the CLI so this stays testable and side-effect free.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List

from recon import identify_service

# Protocols that carry credentials/data in the clear on the wire.
_CLEARTEXT_PORTS = {
    23: ("telnet", "high"),
    21: ("FTP", "high"),
    80: ("HTTP", "medium"),
    110: ("POP3", "medium"),
    143: ("IMAP", "medium"),
    389: ("LDAP", "medium"),
    5900: ("VNC", "high"),
}


@dataclass(frozen=True)
class Interaction:
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str = "tcp"


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def build_lan_map(interactions: List[Interaction]) -> Dict:
    """Aggregate observed interactions into a host/service map plus hardening findings."""
    hosts: set = set()
    service_clients: Dict[tuple, set] = defaultdict(set)
    findings: List[Dict] = []
    seen_cleartext: set = set()
    seen_egress: set = set()

    for it in interactions:
        hosts.add(it.src_ip)
        hosts.add(it.dst_ip)
        service_clients[(it.dst_ip, it.dst_port)].add(it.src_ip)

        # External egress: an internal host reaching a public address.
        if _is_private(it.src_ip) and not _is_private(it.dst_ip):
            key = (it.dst_ip, it.dst_port)
            if key not in seen_egress:
                seen_egress.add(key)
                findings.append({
                    "severity": "medium",
                    "title": "Traffic leaving for an external host",
                    "description": (
                        f"{it.src_ip} connected out to {it.dst_ip}:{it.dst_port}. Confirm "
                        "this egress is expected; unexpected outbound connections can be "
                        "command-and-control or data exfiltration."
                    ),
                    "remediation": "Restrict outbound traffic with an egress firewall allowlist.",
                    "affected_hosts": [it.src_ip],
                })

        # Cleartext protocol in use.
        if it.dst_port in _CLEARTEXT_PORTS and (it.dst_ip, it.dst_port) not in seen_cleartext:
            seen_cleartext.add((it.dst_ip, it.dst_port))
            name, severity = _CLEARTEXT_PORTS[it.dst_port]
            findings.append({
                "severity": severity,
                "title": f"Cleartext protocol in use: {name}",
                "description": (
                    f"{name} on {it.dst_ip}:{it.dst_port} sends data (often credentials) "
                    "unencrypted; anyone on the path can read it."
                ),
                "remediation": f"Replace {name} with an encrypted equivalent "
                               "(SSH/HTTPS/FTPS/LDAPS) and disable the cleartext service.",
                "affected_hosts": [it.dst_ip],
            })

    services = sorted(
        (
            {"host": host, "port": port, "service": identify_service(port, ""),
             "client_count": len(clients), "clients": sorted(clients)}
            for (host, port), clients in service_clients.items()
        ),
        key=lambda s: (s["host"], s["port"]),
    )

    return {
        "hosts": sorted(hosts),
        "services": services,
        "findings": findings,
    }
