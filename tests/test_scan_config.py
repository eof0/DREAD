"""ScanConfig precedence: explicit args override a profile; render_js flows through."""

from __future__ import annotations

import sys
from pathlib import Path

_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))

from scanner.config import ScanConfig


def test_profile_sets_depth_when_not_overridden():
    cfg = ScanConfig("https://example.test", profile="quick")
    assert cfg.depth == 1
    assert cfg.max_urls == 20


def test_explicit_depth_and_max_urls_override_profile():
    cfg = ScanConfig("https://example.test", profile="quick", depth=4, max_urls=300)
    assert cfg.depth == 4
    assert cfg.max_urls == 300


def test_defaults_when_no_profile():
    cfg = ScanConfig("https://example.test")
    assert cfg.depth == 2
    assert cfg.max_urls == 50


def test_render_js_defaults_off_and_is_settable():
    assert ScanConfig("https://example.test").render_js is False
    assert ScanConfig("https://example.test", render_js=True).render_js is True


def test_full_profile_enables_js_rendering():
    assert ScanConfig("https://example.test", profile="full").render_js is True


def test_offensive_forces_browser_and_full_coverage():
    cfg = ScanConfig("https://example.test", aggressive=True)
    assert cfg.aggressive is True
    assert cfg.render_js is True  # aggressive always drives the browser

    # Explicit render_js=False cannot silently disable the browser under aggressive.
    cfg2 = ScanConfig("https://example.test", aggressive=True, render_js=False)
    assert cfg2.render_js is True


def test_default_is_not_aggressive():
    assert ScanConfig("https://example.test").aggressive is False
