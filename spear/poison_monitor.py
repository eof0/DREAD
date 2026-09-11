"""
Name-resolution poisoning monitor (defensive).

LLMNR, NBT-NS and mDNS let hosts resolve names by broadcasting a question to the
whole subnet. Any machine can answer — which is exactly how tools like Responder
steal credentials: they reply to these queries and capture the authentication that
follows. This monitor does the opposite of an attacker: it *passively listens* for
those broadcast queries and reports which hosts are making them, so you can disable
LLMNR/NBT-NS and close the exposure. It never answers a query and never captures
credentials.

Packet parsing and analysis are pure and testable; the actual socket listening is
injected (see ``sniff`` in the CLI) so this module stays safe to import and test.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class Observation:
    protocol: str  # "LLMNR" | "NBT-NS" | "mDNS"
    src_ip: str
    name: str


# Protocols where a broadcast query invites poisoning (an attacker can answer).
_POISONABLE = {"LLMNR", "NBT-NS"}

# Names that, if hijacked, hand an attacker credentials or code execution outright.
_DANGEROUS_NAMES = {
    "wpad": ("WPAD", "high",
             "A hijacked WPAD response makes every browser use the attacker as its web "
             "proxy, capturing credentials and letting them tamper with traffic."),
    "proxy": ("proxy autodiscovery", "high",
              "Autodiscovery of a proxy over a poisonable protocol can be hijacked to "
              "intercept traffic and credentials."),
}


def encode_dns_name(name: str) -> bytes:
    """Encode a name into DNS label format (length-prefixed labels, null-terminated)."""
    out = bytearray()
    for label in name.split("."):
        out.append(len(label))
        out.extend(label.encode("ascii"))
    out.append(0)
    return bytes(out)


def _decode_dns_name(data: bytes, offset: int) -> Optional[str]:
    labels: List[str] = []
    i = offset
    while i < len(data):
        length = data[i]
        if length == 0:
            return ".".join(labels)
        if length & 0xC0:  # compression pointer — not expected in a question, bail
            return None
        i += 1
        if i + length > len(data):
            return None
        labels.append(data[i:i + length].decode("latin-1", "replace"))
        i += length
    return None


def parse_llmnr_query(packet: bytes) -> Optional[str]:
    """Extract the queried name from an LLMNR (or mDNS) DNS-format query packet."""
    if len(packet) < 13:  # 12-byte header + at least one name byte
        return None
    name = _decode_dns_name(packet, 12)
    return name or None


def parse_nbns_query(packet: bytes) -> Optional[str]:
    """Extract and decode the queried name from an NBT-NS (NetBIOS) query packet."""
    if len(packet) < 13:
        return None
    length = packet[12]
    if length != 0x20:  # first-level-encoded NetBIOS names are always 32 bytes
        return None
    encoded = packet[13:13 + 32]
    if len(encoded) < 32:
        return None
    decoded = bytearray()
    for j in range(0, 32, 2):
        hi = encoded[j] - ord("A")
        lo = encoded[j + 1] - ord("A")
        if not (0 <= hi <= 15 and 0 <= lo <= 15):
            return None
        decoded.append((hi << 4) | lo)
    return decoded.decode("latin-1", "replace").rstrip(" \x00") or None


def analyze_observations(observations: List[Observation]) -> Dict:
    """Turn observed name queries into susceptible-host and finding summaries."""
    by_host: Dict[str, set] = defaultdict(set)
    dangerous: List[Observation] = []

    for obs in observations:
        if obs.protocol in _POISONABLE:
            by_host[obs.src_ip].add(obs.protocol)
            if obs.name.split(".")[0].lower() in _DANGEROUS_NAMES:
                dangerous.append(obs)

    susceptible_hosts = [
        {"ip": ip, "protocols": sorted(protos)}
        for ip, protos in sorted(by_host.items())
    ]

    findings: List[Dict] = []
    if susceptible_hosts:
        protos = sorted({p for h in susceptible_hosts for p in h["protocols"]})
        findings.append({
            "severity": "medium",
            "title": f"Name-resolution poisoning exposure ({', '.join(protos)})",
            "description": (
                f"{len(susceptible_hosts)} host(s) resolve names via broadcast protocols "
                f"({', '.join(protos)}). Any device on the subnet can answer these and "
                "capture the authentication that follows (the Responder attack)."
            ),
            "remediation": (
                "Disable LLMNR (Group Policy: Turn off multicast name resolution) and "
                "NBT-NS (TCP/IP NetBIOS = disabled) across the fleet; ensure DNS resolves "
                "the names these hosts are looking for."
            ),
            "affected_hosts": [h["ip"] for h in susceptible_hosts],
        })

    seen_names = set()
    for obs in dangerous:
        key = obs.name.split(".")[0].lower()
        if key in seen_names:
            continue
        seen_names.add(key)
        label, severity, impact = _DANGEROUS_NAMES[key]
        findings.append({
            "severity": severity,
            "title": f"{label} query over a poisonable protocol",
            "description": (
                f"Host {obs.src_ip} looked up '{obs.name}' via {obs.protocol}. {impact}"
            ),
            "remediation": (
                "Disable LLMNR/NBT-NS and, for WPAD, create a DNS record for 'wpad' or "
                "disable proxy autodiscovery in browsers/OS."
            ),
            "affected_hosts": [obs.src_ip],
        })

    return {
        "observation_count": len(observations),
        "susceptible_hosts": susceptible_hosts,
        "findings": findings,
    }
