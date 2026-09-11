"""Authorization gate for Spear's active/offensive capabilities."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SPEAR = Path(__file__).resolve().parents[1] / "spear"
if str(_SPEAR) not in sys.path:
    sys.path.insert(0, str(_SPEAR))

from authorization import (
    ACK_PHRASE,
    AuditLog,
    AuthorizationError,
    require_authorization,
)


def test_requires_env_and_ack(monkeypatch):
    monkeypatch.delenv("SPEAR_AUTHORIZED", raising=False)
    # Neither set -> refused.
    with pytest.raises(AuthorizationError):
        require_authorization(acknowledged=False)

    # Env only, no explicit acknowledgment -> refused.
    monkeypatch.setenv("SPEAR_AUTHORIZED", "1")
    with pytest.raises(AuthorizationError):
        require_authorization(acknowledged=False)


def test_grants_when_both_present(monkeypatch):
    monkeypatch.setenv("SPEAR_AUTHORIZED", "1")
    ctx = require_authorization(acknowledged=True, operator="ryan", target="10.0.0.0/24")
    assert ctx["operator"] == "ryan"
    assert ctx["target"] == "10.0.0.0/24"


def test_ack_phrase_is_explicit_about_permission_and_liability():
    text = ACK_PHRASE.lower()
    # Names the real constraint...
    assert "authorized" in text
    assert "permission" in text
    # ...and the liability disclaimer the user required.
    assert "not designed for client engagements" in text
    assert "not responsible" in text or "no responsibility" in text
    assert "risk" in text


def test_audit_log_records_events(tmp_path):
    path = tmp_path / "audit.log"
    log = AuditLog(path)
    log.record("poison.start", target="10.0.0.5", detail="LLMNR answerer")
    log.record("capture.hash", src="10.0.0.9", detail="user=BOB")

    lines = path.read_text().strip().splitlines()
    assert len(lines) == 2
    assert "poison.start" in lines[0] and "10.0.0.5" in lines[0]
    assert "capture.hash" in lines[1] and "BOB" in lines[1]
    # Each line is timestamped (ISO-8601 UTC).
    assert "T" in lines[0] and lines[0].endswith("Z") is False  # offset form, has +00:00
    assert "+00:00" in lines[0]
