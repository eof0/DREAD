"""
Spear service-risk analysis and active service probes.

`analyze_host` turns enumerated services (from recon.ServiceScanner) into findings
shaped like the rest of DREAD (severity/title/description/remediation/host/port), so
they flow into Reports and DreadAI. The active probes (`check_redis_unauth`,
`check_ftp_anonymous`) confirm the highest-value exposures; their network I/O is
injected so the logic is testable and the transport swappable.
"""

from __future__ import annotations

import socket
from typing import Callable, Dict, List, Optional

# service -> (severity, title, description, remediation). Keyed by the names
# recon.identify_service emits. Absent services are treated as benign.
_SERVICE_RISK: Dict[str, tuple] = {
    "telnet": ("high", "Telnet exposed (cleartext administration)",
               "Telnet sends credentials and commands unencrypted; anyone on the path can read or hijack the session.",
               "Disable Telnet and use SSH."),
    "ftp": ("medium", "FTP exposed (cleartext)",
            "FTP transfers credentials and data unencrypted.",
            "Replace FTP with SFTP/FTPS; if anonymous access is enabled, disable it."),
    "http": ("low", "Plain HTTP service",
             "An unencrypted HTTP service was found on the internal network.",
             "Serve over HTTPS and redirect HTTP."),
    "pop3": ("medium", "POP3 exposed (cleartext)",
             "Mail credentials and messages travel unencrypted.",
             "Use POP3S/IMAPS (implicit TLS) or STARTTLS-enforced connections."),
    "imap": ("medium", "IMAP exposed (cleartext)",
             "Mail credentials and messages travel unencrypted.",
             "Use IMAPS or enforce STARTTLS."),
    "ldap": ("medium", "LDAP exposed (cleartext)",
             "Directory queries and bind credentials travel unencrypted.",
             "Use LDAPS (636) or enforce StartTLS; restrict who can reach the directory."),
    "vnc": ("high", "VNC exposed",
            "VNC often ships with weak or no authentication and gives full desktop control.",
            "Restrict VNC to a VPN/jump host, require strong auth, or replace with a managed remote-access tool."),
    "rdp": ("medium", "RDP (Remote Desktop) exposed",
            "Exposed RDP is a top ransomware entry point and a brute-force / relay target.",
            "Require Network Level Authentication, put RDP behind a VPN/gateway, and enforce MFA."),
    "winrm": ("medium", "WinRM exposed",
              "WinRM enables remote command execution; exposed broadly it aids lateral movement.",
              "Limit WinRM to management subnets and require HTTPS + strong auth."),
    "smb": ("medium", "SMB exposed",
            "SMB is a primary lateral-movement and relay surface; SMBv1 and unsigned SMB are especially risky.",
            "Disable SMBv1, require SMB signing, and restrict SMB to trusted segments."),
    "netbios-ssn": ("medium", "Legacy NetBIOS session service exposed",
                    "NetBIOS (139) is legacy and aids name-based attacks and enumeration.",
                    "Disable NetBIOS over TCP/IP where SMB over 445 suffices."),
    "redis": ("high", "Redis exposed",
              "Redis binds with no authentication by default; if reachable it allows full data access and often RCE.",
              "Bind Redis to localhost, require a password/ACL, and never expose it to the network."),
    "mongodb": ("high", "MongoDB exposed",
                "Internet/network-reachable MongoDB is a classic source of data breaches.",
                "Enable authentication, bind to trusted interfaces, and firewall the port."),
    "elasticsearch": ("high", "Elasticsearch exposed",
                      "Unauthenticated Elasticsearch exposes all indexed data and cluster control.",
                      "Enable security/authentication and restrict network access."),
    "memcached": ("high", "Memcached exposed",
                  "Exposed memcached leaks cached data and is abused for UDP amplification DDoS.",
                  "Bind to localhost, disable UDP, and firewall the port."),
    "mysql": ("medium", "MySQL exposed",
              "A network-reachable database is a high-value target for brute-force and data theft.",
              "Restrict the database to app servers only and enforce strong credentials."),
    "mssql": ("medium", "Microsoft SQL Server exposed",
              "A network-reachable database is a high-value target.",
              "Restrict access to app servers and enforce strong authentication."),
    "postgres": ("medium", "PostgreSQL exposed",
                 "A network-reachable database is a high-value target.",
                 "Restrict access to app servers and enforce strong authentication."),
    "oracle": ("medium", "Oracle DB exposed",
               "A network-reachable database is a high-value target.",
               "Restrict access and enforce strong authentication."),
}


def analyze_host(host: str, services: List[Dict]) -> List[Dict]:
    """Findings for the risky services exposed on one host."""
    findings: List[Dict] = []
    for svc in services:
        service = svc.get("service", "")
        risk = _SERVICE_RISK.get(service)
        if not risk:
            continue
        severity, title, description, remediation = risk
        findings.append({
            "source_product": "spear",
            "host": host,
            "port": svc.get("port"),
            "service": service,
            "severity": severity,
            "title": title,
            "description": description,
            "remediation": remediation,
            "evidence": {"banner": (svc.get("banner") or "")[:200]},
        })
    return findings


# ---- active confirmation probes (injected I/O) ----

def check_redis_unauth(host: str, *, connector: Callable[..., str], port: int = 6379) -> bool:
    """True when Redis answers PING with PONG (no auth required)."""
    reply = connector(host, port, b"PING\r\n", timeout=2.0) or ""
    return "+PONG" in reply


def check_ftp_anonymous(host: str, *, conversation: Callable[..., List[str]], port: int = 21) -> bool:
    """True when the FTP server accepts anonymous login (a 230 after USER anonymous)."""
    replies = conversation(host, port, timeout=2.0) or []
    return any(str(line).startswith("230") for line in replies)


# ---- default socket-backed I/O for the probes above ----

def redis_connector(host: str, port: int, payload: bytes, timeout: float = 2.0) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(payload)
            return sock.recv(256).decode("latin-1", "replace")
    except OSError:
        return ""


def ftp_anonymous_conversation(host: str, port: int, timeout: float = 2.0) -> List[str]:
    replies: List[str] = []
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            replies.append(sock.recv(256).decode("latin-1", "replace"))
            sock.sendall(b"USER anonymous\r\n")
            replies.append(sock.recv(256).decode("latin-1", "replace"))
            sock.sendall(b"PASS dread@example.com\r\n")
            replies.append(sock.recv(256).decode("latin-1", "replace"))
    except OSError:
        return replies
    return replies
