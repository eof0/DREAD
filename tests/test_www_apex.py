from __future__ import annotations

import sys
from pathlib import Path

_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))

from scanner.crawler import _same_site_netlocs
from dread import _hostname_from_scan_target, _omit_redundant_www_when_user_chose_apex


def test_same_site_netlocs_apex_and_www() -> None:
    assert _same_site_netlocs("example.com") == {"example.com", "www.example.com"}
    assert _same_site_netlocs("www.example.com") == {"www.example.com", "example.com"}


def test_same_site_netlocs_preserves_port() -> None:
    assert _same_site_netlocs("example.com:8443") == {
        "example.com:8443",
        "www.example.com:8443",
    }


def test_same_site_netlocs_ipv6_literal_only() -> None:
    assert _same_site_netlocs("[::1]:8080") == {"[::1]:8080"}


def test_omit_www_when_primary_is_apex() -> None:
    primary = "example.com"
    targets = ["example.com", "www.example.com", "api.example.com"]
    assert _omit_redundant_www_when_user_chose_apex(primary, targets) == [
        "example.com",
        "api.example.com",
    ]


def test_keep_www_when_primary_is_www() -> None:
    primary = "www.example.com"
    targets = ["www.example.com", "example.com"]
    assert _omit_redundant_www_when_user_chose_apex(primary, targets) == targets


def test_hostname_from_target() -> None:
    assert _hostname_from_scan_target("HTTPS://Example.COM/path") == "example.com"
    assert _hostname_from_scan_target("api.foo.test") == "api.foo.test"
