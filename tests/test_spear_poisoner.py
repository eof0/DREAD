"""Active poisoner: craft LLMNR/NBT-NS responses; the listener is authorization-gated."""

from __future__ import annotations

import socket
import struct
import sys
from pathlib import Path

import pytest

_SPEAR = Path(__file__).resolve().parents[1] / "spear"
if str(_SPEAR) not in sys.path:
    sys.path.insert(0, str(_SPEAR))

from authorization import AuthorizationError
from poison_monitor import encode_dns_name
from poisoner import build_llmnr_response, build_nbns_response, run_poisoner


def _llmnr_query(name: str, txid: bytes = b"\xab\xcd") -> bytes:
    header = txid + bytes([0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    return header + encode_dns_name(name) + bytes([0x00, 0x01, 0x00, 0x01])


def test_llmnr_response_echoes_txid_and_points_to_attacker():
    query = _llmnr_query("fileserver", txid=b"\x12\x34")
    resp = build_llmnr_response(query, "10.0.0.66")

    assert resp[:2] == b"\x12\x34"                       # transaction id echoed
    flags = struct.unpack_from(">H", resp, 2)[0]
    assert flags & 0x8000                                 # QR bit set (this is a response)
    assert resp.endswith(socket.inet_aton("10.0.0.66"))   # answer -> attacker IP


def test_llmnr_response_none_for_garbage():
    assert build_llmnr_response(b"\x00\x01", "10.0.0.66") is None


def test_nbns_response_points_to_attacker_and_echoes_txid():
    # Minimal NBT-NS name query for "WPAD".
    name = "WPAD".ljust(15) + "\x00"
    encoded = "".join(chr((ord(c) >> 4) + ord("A")) + chr((ord(c) & 0xF) + ord("A")) for c in name)
    header = b"\x99\x88" + bytes([0x01, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    query = header + bytes([0x20]) + encoded.encode("ascii") + bytes([0x00, 0x00, 0x20, 0x00, 0x01])

    resp = build_nbns_response(query, "10.0.0.66")
    assert resp[:2] == b"\x99\x88"
    assert resp.endswith(socket.inet_aton("10.0.0.66"))


def test_run_poisoner_refuses_without_authorization(monkeypatch, tmp_path):
    monkeypatch.delenv("SPEAR_AUTHORIZED", raising=False)
    with pytest.raises(AuthorizationError):
        run_poisoner("10.0.0.66", duration=0, acknowledged=False,
                     audit_path=tmp_path / "audit.log")


def test_run_poisoner_refuses_env_without_ack(monkeypatch, tmp_path):
    monkeypatch.setenv("SPEAR_AUTHORIZED", "1")
    with pytest.raises(AuthorizationError):
        run_poisoner("10.0.0.66", duration=0, acknowledged=False,
                     audit_path=tmp_path / "audit.log")
