"""
Internal host discovery and service enumeration for Spear.

Network I/O is injected (a ``prober`` for host liveness, a ``connector`` for TCP
service probes) so the logic is testable and so the transport can be swapped
(raw sockets, ARP, an external tool). Defaults target private ranges only; use
only on networks you are authorized to assess.
"""

from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Dict, List, Optional

# Common internal service ports, enough to fingerprint most hosts without a full sweep.
COMMON_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143, 389, 443, 445, 465, 587,
    636, 993, 995, 1433, 1521, 2049, 3268, 3306, 3389, 5432, 5900, 5985, 5986,
    6379, 8000, 8080, 8443, 9200, 11211, 27017,
)

_PORT_SERVICES: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    88: "kerberos", 110: "pop3", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    389: "ldap", 443: "https", 445: "smb", 465: "smtps", 587: "submission",
    636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    2049: "nfs", 3268: "globalcat", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    5900: "vnc", 5985: "winrm", 5986: "winrm-https", 6379: "redis", 8000: "http-alt",
    8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch", 11211: "memcached",
    27017: "mongodb",
}

_BANNER_SIGNATURES = (
    ("ssh", ("ssh-",)),
    ("ftp", ("220 ", "ftp")),
    ("smtp", ("220 ", "smtp", "esmtp")),
    ("http", ("http/", "server:")),
    ("redis", ("-err", "+pong", "redis")),
    ("mysql", ("mysql",)),
)


def expand_targets(spec: str, allow_public: bool = False) -> List[str]:
    """
    Expand a target spec into a list of IPv4 addresses.

    Accepts a single IP, CIDR (192.168.1.0/24), inclusive range (a-b), or a
    comma-separated mix. Refuses public/global ranges unless allow_public=True,
    so internal tooling can't be pointed at the internet by accident.
    """
    hosts: List[str] = []
    seen: set[str] = set()

    def _add(ip: str) -> None:
        if ip not in seen:
            seen.add(ip)
            hosts.append(ip)

    for part in (p.strip() for p in spec.split(",") if p.strip()):
        addrs: List[ipaddress.IPv4Address] = []
        if "/" in part:
            net = ipaddress.ip_network(part, strict=False)
            addrs = list(net.hosts()) if net.num_addresses > 2 else [
                ipaddress.ip_address(int(net.network_address) + i)
                for i in range(net.num_addresses)
            ]
        elif "-" in part:
            lo, hi = (ipaddress.ip_address(x.strip()) for x in part.split("-", 1))
            addrs = [ipaddress.ip_address(i) for i in range(int(lo), int(hi) + 1)]
        else:
            addrs = [ipaddress.ip_address(part)]

        for addr in addrs:
            if not allow_public and addr.is_global:
                raise ValueError(
                    f"{addr} is a public address; internal discovery targets private "
                    "ranges. Pass allow_public=True only for authorized external work."
                )
            _add(str(addr))
    return hosts


def identify_service(port: int, banner: str) -> str:
    """Best-guess service name from a banner (preferred) then the port number."""
    text = (banner or "").strip().lower()
    for service, needles in _BANNER_SIGNATURES:
        if any(n in text for n in needles):
            return service
    return _PORT_SERVICES.get(port, "unknown")


class HostDiscovery:
    """Sweep a target spec for live hosts using an injectable liveness prober."""

    def __init__(self, prober: Callable[[str], bool], workers: int = 64):
        self._prober = prober
        self._workers = workers

    def discover(self, spec: str, allow_public: bool = False) -> List[str]:
        targets = expand_targets(spec, allow_public=allow_public)
        with ThreadPoolExecutor(max_workers=self._workers) as pool:
            alive_flags = list(pool.map(self._safe_probe, targets))
        return [ip for ip, alive in zip(targets, alive_flags) if alive]

    def _safe_probe(self, ip: str) -> bool:
        try:
            return bool(self._prober(ip))
        except Exception:
            return False


class ServiceScanner:
    """TCP service enumeration using an injectable connector returning a banner or None."""

    def __init__(self, connector: Callable[..., Optional[str]], workers: int = 64):
        self._connector = connector
        self._workers = workers

    def scan(self, host: str, ports=COMMON_PORTS, timeout: float = 1.0) -> List[Dict]:
        def probe(port: int):
            try:
                banner = self._connector(host, port, timeout=timeout)
            except Exception:
                return None
            if banner is None:
                return None
            return {"port": port, "service": identify_service(port, banner),
                    "banner": (banner or "").strip()[:200]}

        with ThreadPoolExecutor(max_workers=self._workers) as pool:
            results = [r for r in pool.map(probe, ports) if r]
        return sorted(results, key=lambda s: s["port"])


# ---- default socket-backed I/O (used by the CLI; the classes above stay testable) ----

def tcp_connect_banner(host: str, port: int, timeout: float = 1.0) -> Optional[str]:
    """Connect to host:port; return a (possibly empty) banner string, or None if closed."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                data = sock.recv(256)
                return data.decode("latin-1", "replace")
            except socket.timeout:
                return ""  # open but silent
    except (OSError, socket.timeout):
        return None


def tcp_ping(host: str, ports=(445, 135, 22, 80, 443), timeout: float = 0.5) -> bool:
    """Liveness via a quick TCP connect to any common port (no raw-socket privileges needed)."""
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (OSError, socket.timeout):
            continue
    return False
