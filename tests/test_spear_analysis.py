"""Spear service-risk analysis: turn enumerated services into findings, and active probes."""

from __future__ import annotations

import sys
from pathlib import Path

_SPEAR = Path(__file__).resolve().parents[1] / "spear"
if str(_SPEAR) not in sys.path:
    sys.path.insert(0, str(_SPEAR))

from analysis import (
    analyze_host,
    check_ftp_anonymous,
    check_redis_unauth,
)


def _svc(port, service, banner=""):
    return {"port": port, "service": service, "banner": banner}


def test_cleartext_services_flagged_high():
    findings = analyze_host("10.0.0.5", [_svc(23, "telnet"), _svc(21, "ftp")])
    by_title = {f["title"]: f for f in findings}
    assert any("Telnet" in t for t in by_title)
    telnet = next(f for f in findings if "Telnet" in f["title"])
    assert telnet["severity"] == "high"
    assert telnet["host"] == "10.0.0.5" and telnet["port"] == 23


def test_exposed_datastores_flagged():
    findings = analyze_host("10.0.0.9", [_svc(6379, "redis"), _svc(27017, "mongodb"),
                                          _svc(9200, "elasticsearch")])
    titles = " ".join(f["title"].lower() for f in findings)
    assert "redis" in titles and "mongodb" in titles and "elasticsearch" in titles
    assert all(f["severity"] in ("high", "critical") for f in findings)


def test_smb_and_rdp_noted():
    findings = analyze_host("10.0.0.10", [_svc(445, "smb"), _svc(3389, "rdp")])
    titles = " ".join(f["title"].lower() for f in findings)
    assert "smb" in titles and ("rdp" in titles or "remote desktop" in titles)


def test_https_only_host_has_no_findings():
    assert analyze_host("10.0.0.20", [_svc(443, "https")]) == []


def test_redis_unauth_probe_detects_pong():
    # connector returns the bytes a server would send in reply to our command.
    def connector(host, port, payload, timeout=2.0):
        return "+PONG\r\n" if b"PING" in payload else ""

    assert check_redis_unauth("10.0.0.9", connector=connector) is True

    def auth_required(host, port, payload, timeout=2.0):
        return "-NOAUTH Authentication required.\r\n"

    assert check_redis_unauth("10.0.0.9", connector=auth_required) is False


def test_ftp_anonymous_probe():
    def allows_anon(host, port, timeout=2.0):
        return ["220 FTP ready", "331 Please specify the password", "230 Login successful"]

    assert check_ftp_anonymous("10.0.0.5", conversation=allows_anon) is True

    def denies(host, port, timeout=2.0):
        return ["220 FTP ready", "331 password", "530 Login incorrect"]

    assert check_ftp_anonymous("10.0.0.5", conversation=denies) is False
