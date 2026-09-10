from scanner.config import ScanConfig
from scanner.engine import ScanEngine


def test_safe_active_profile_enables_safe_mode():
    config = ScanConfig("https://example.test", profile="safe-active")

    assert config.active_scan_mode == "safe"
    assert "web_vulnerabilities" in config.enabled_plugins


def test_active_web_checks_load_for_default_standard_and_full_scans():
    assert "web_vulnerabilities" in ScanConfig("https://example.test").enabled_plugins
    assert "web_vulnerabilities" in ScanConfig(
        "https://example.test",
        profile="standard",
    ).enabled_plugins
    assert "web_vulnerabilities" in ScanConfig(
        "https://example.test",
        profile="full",
    ).enabled_plugins


def test_quick_and_infrastructure_profiles_remain_passive():
    assert "web_vulnerabilities" not in ScanConfig(
        "https://example.test",
        profile="quick",
    ).enabled_plugins
    assert "web_vulnerabilities" not in ScanConfig(
        "https://example.test",
        profile="infrastructure",
    ).enabled_plugins


def test_engine_registers_active_web_plugin():
    config = ScanConfig(
        "https://example.test",
        enabled_plugins=["web_vulnerabilities"],
    )
    engine = ScanEngine(config)

    engine.load_plugins()

    assert [plugin.get_name() for plugin in engine.plugins] == [
        "web_vulnerabilities"
    ]
