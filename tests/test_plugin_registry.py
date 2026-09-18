"""The engine can load every plugin named in the default profiles, api_discovery included."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))

from scanner.config import SCAN_PROFILES, ScanConfig
from scanner.engine import ScanEngine


def test_api_discovery_and_waf_detection_are_registered():
    engine = ScanEngine(ScanConfig("https://example.test",
                                   enabled_plugins=["api_discovery", "waf_detection"]))
    engine.load_plugins()

    names = {p.get_name() for p in engine.plugins}
    assert {"api_discovery", "waf_detection"} <= names


def test_default_scan_includes_api_discovery():
    assert "api_discovery" in ScanConfig("https://example.test").enabled_plugins


def test_aggressive_mode_widens_the_host_failure_threshold():
    # Aggressive mode sends several times the request volume, so the default
    # circuit-breaker threshold trips on the target's own rate limiter far more
    # easily than it would under a normal scan -- it should be widened, not left
    # at the default meant for gentle, low-concurrency traffic.
    default_engine = ScanEngine(ScanConfig("https://example.test"))
    aggressive_engine = ScanEngine(ScanConfig("https://example.test", aggressive=True))

    assert aggressive_engine.request_handler._max_host_failures > \
        default_engine.request_handler._max_host_failures


@pytest.mark.parametrize("profile", sorted(SCAN_PROFILES))
def test_every_profile_plugin_is_loadable(profile):
    engine = ScanEngine(ScanConfig("https://example.test", profile=profile))
    engine.load_plugins()

    # get_name() can differ from the profile key (e.g. "infrastructure" ->
    # "infrastructure_intel"), so assert every enabled plugin loaded, by count.
    assert len(engine.plugins) == len(SCAN_PROFILES[profile]["enabled_plugins"]), (
        f"{profile}: not all plugins loaded"
    )
