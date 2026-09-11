"""NTLM challenge/response handling: Type2 build, Type3 parse, NetNTLMv2 hashcat format."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

_SPEAR = Path(__file__).resolve().parents[1] / "spear"
if str(_SPEAR) not in sys.path:
    sys.path.insert(0, str(_SPEAR))

from ntlm import (
    DEFAULT_CHALLENGE,
    NTLMSSP_SIGNATURE,
    build_type2,
    build_type3,
    extract_netntlmv2,
    message_type,
    parse_type3,
)


def test_build_type2_is_a_valid_challenge_message():
    msg = build_type2(challenge=DEFAULT_CHALLENGE, target_name="MERIDIAN")
    assert msg.startswith(NTLMSSP_SIGNATURE)
    assert message_type(msg) == 2
    # The 8-byte server challenge sits at offset 24.
    assert msg[24:32] == DEFAULT_CHALLENGE


def test_default_challenge_is_the_known_crackable_value():
    # 1122334455667788 — the well-known static challenge used for offline cracking.
    assert DEFAULT_CHALLENGE == bytes.fromhex("1122334455667788")


def test_parse_type3_round_trip():
    nt_response = b"\xaa" * 16 + b"\x01\x01" + b"\x00" * 40  # NTProofStr + NTLMv2 blob
    msg = build_type3(user="bob", domain="MERIDIAN", workstation="BOB-PC",
                      nt_response=nt_response)
    assert message_type(msg) == 3

    parsed = parse_type3(msg)
    assert parsed["user"] == "bob"
    assert parsed["domain"] == "MERIDIAN"
    assert parsed["workstation"] == "BOB-PC"
    assert parsed["nt_response"] == nt_response
    assert parsed["is_v2"] is True


def test_extract_netntlmv2_hashcat_format():
    ntproof = bytes(range(16))
    blob = b"\x01\x01\x00\x00" + b"\xcd" * 20
    nt_response = ntproof + blob
    msg = build_type3(user="alice", domain="CORP", workstation="WS1", nt_response=nt_response)
    parsed = parse_type3(msg)

    line = extract_netntlmv2(parsed, DEFAULT_CHALLENGE)
    # hashcat mode 5600: user::domain:serverchallenge:ntproof:blob
    fields = line.split(":")
    assert fields[0] == "alice"
    assert fields[1] == ""            # empty LM field position (user::domain)
    assert fields[2] == "CORP"
    assert fields[3] == DEFAULT_CHALLENGE.hex()
    assert fields[4] == ntproof.hex()
    assert fields[5] == blob.hex()


def test_ntlmv1_response_is_not_treated_as_v2():
    nt_response = b"\x11" * 24  # exactly 24 bytes -> NTLMv1
    msg = build_type3(user="carol", domain="CORP", workstation="WS", nt_response=nt_response)
    parsed = parse_type3(msg)
    assert parsed["is_v2"] is False


def test_parse_rejects_non_ntlm():
    import pytest

    with pytest.raises(ValueError):
        parse_type3(b"not an ntlm message")
