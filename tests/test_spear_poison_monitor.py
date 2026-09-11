"""Defensive name-resolution-poisoning monitor: parse queries, flag susceptibility."""

from __future__ import annotations

import sys
from pathlib import Path

_SPEAR = Path(__file__).resolve().parents[1] / "spear"
if str(_SPEAR) not in sys.path:
    sys.path.insert(0, str(_SPEAR))

from poison_monitor import (
    Observation,
    analyze_observations,
    encode_dns_name,
    parse_llmnr_query,
    parse_nbns_query,
)


def _llmnr_packet(name: str) -> bytes:
    # DNS-format query: 12-byte header (1 question) + encoded name + QTYPE + QCLASS.
    header = bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    return header + encode_dns_name(name) + bytes([0x00, 0x01, 0x00, 0x01])


def test_parse_llmnr_query_extracts_name():
    assert parse_llmnr_query(_llmnr_packet("wpad")) == "wpad"
    assert parse_llmnr_query(_llmnr_packet("fileserver")) == "fileserver"


def test_parse_llmnr_query_rejects_garbage():
    assert parse_llmnr_query(b"\x00\x01") is None
    assert parse_llmnr_query(b"") is None


def test_parse_nbns_query_decodes_name():
    # NBT-NS first-level encoding: each nibble + 'A'. "WPAD" (padded to 16) -> encoded.
    name = "WPAD"
    padded = name.ljust(15) + "\x00"
    encoded = "".join(chr((ord(c) >> 4) + ord("A")) + chr((ord(c) & 0xF) + ord("A")) for c in padded)
    header = bytes([0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    packet = header + bytes([0x20]) + encoded.encode("ascii") + bytes([0x00, 0x00, 0x20, 0x00, 0x01])

    assert parse_nbns_query(packet) == "WPAD"


def test_analysis_flags_llmnr_and_nbtns_as_susceptible():
    obs = [
        Observation(protocol="LLMNR", src_ip="192.168.1.10", name="fileserver"),
        Observation(protocol="NBT-NS", src_ip="192.168.1.11", name="printer"),
    ]
    report = analyze_observations(obs)

    susceptible = {h["ip"] for h in report["susceptible_hosts"]}
    assert susceptible == {"192.168.1.10", "192.168.1.11"}
    assert any("LLMNR" in f["title"] or "NBT-NS" in f["title"] for f in report["findings"])


def test_wpad_query_is_high_severity_credential_theft_risk():
    obs = [Observation(protocol="LLMNR", src_ip="192.168.1.50", name="wpad")]
    report = analyze_observations(obs)

    wpad = [f for f in report["findings"] if "WPAD" in f["title"]]
    assert wpad and wpad[0]["severity"] == "high"


def test_mdns_alone_is_informational_not_a_poisoning_risk():
    obs = [Observation(protocol="mDNS", src_ip="192.168.1.20", name="printer.local")]
    report = analyze_observations(obs)

    # mDNS is normal on most LANs; it shouldn't be reported as a poisoning weakness.
    assert report["susceptible_hosts"] == []
