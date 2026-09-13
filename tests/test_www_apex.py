from __future__ import annotations

import sys
from pathlib import Path

_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))

from scanner.crawler import _same_site_netlocs
from dread import (
    _dedupe_scan_targets,
    _hostname_from_scan_target,
    _omit_redundant_www_when_user_chose_apex,
)


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


def test_dedupe_drops_url_and_bare_host_for_same_site() -> None:
    targets = ["https://ryanwilson.io", "ryanwilson.io", "api.ryanwilson.io"]
    assert _dedupe_scan_targets(targets) == ["https://ryanwilson.io", "api.ryanwilson.io"]


def test_dedupe_ignores_case_path_and_default_ports() -> None:
    targets = ["example.com", "HTTPS://Example.com/", "http://example.com", "example.com:443"]
    assert _dedupe_scan_targets(targets) == ["example.com"]


def test_dedupe_keeps_distinct_ports() -> None:
    targets = ["https://example.com:8443", "example.com"]
    assert _dedupe_scan_targets(targets) == targets


def test_hostname_from_target() -> None:
    assert _hostname_from_scan_target("HTTPS://Example.COM/path") == "example.com"
    assert _hostname_from_scan_target("api.foo.test") == "api.foo.test"


def test_run_probe_marks_staged_output_so_probe_skips_temp_paths(monkeypatch) -> None:
    import dread

    seen = {}
    monkeypatch.setattr(dread, "_run_with_heartbeat", lambda cmd, **kw: seen.update(kw))

    dread.run_probe("example.com", output_dir="/tmp/x", staged_output=True)
    assert seen["env"]["DREAD_STAGED_OUTPUT"] == "1"

    dread.run_probe("example.com", output_dir="/tmp/x")
    assert seen["env"] is None


def test_target_supports_discovery_skips_local_and_ip():
    from dread import _target_supports_discovery

    # No point enumerating subdomains of these:
    for t in ("http://localhost:5000", "localhost", "127.0.0.1", "http://127.0.0.1:8080",
              "192.168.1.10", "app.localhost", "myhost.local", "singlelabel", "[::1]"):
        assert _target_supports_discovery(t) is False, t

    # Real registrable domains: discovery makes sense.
    for t in ("example.com", "https://sub.example.com", "linuxcraft.io", "ryanwilson.io"):
        assert _target_supports_discovery(t) is True, t
