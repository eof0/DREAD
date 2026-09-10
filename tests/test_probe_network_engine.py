from scanner.engines import network
from scanner.engines.network import native


def test_rust_binary_must_run_on_the_current_host(tmp_path, monkeypatch):
    incompatible = tmp_path / "probe-engine"
    incompatible.write_bytes(b"not a native executable")
    incompatible.chmod(0o755)
    monkeypatch.setattr(network, "RUST_BINARY", incompatible)

    assert network._get_rust_binary() is None


def test_network_scanner_falls_back_when_rust_is_incompatible(tmp_path, monkeypatch):
    incompatible = tmp_path / "probe-engine"
    incompatible.write_bytes(b"not a native executable")
    incompatible.chmod(0o755)
    monkeypatch.setattr(network, "RUST_BINARY", incompatible)
    monkeypatch.setattr(network, "_get_go_binary", lambda: None)

    scanner = network.NetworkScanner()

    assert scanner.engine == "python-native"


def test_native_scanner_honors_explicit_port_string():
    result = native.scan_target(
        "127.0.0.1",
        ports="1",
        timeout_ms=10,
        concurrency=1,
    )

    assert result["total_ports_scanned"] == 1
    assert all(item["port"] == 1 for item in result["results"])


def test_native_scanner_resolves_ranges_and_deduplicates():
    assert native.resolve_ports("80,443,8000-8002,443") == [80, 443, 8000, 8001, 8002]


def test_network_scanner_accepts_null_engine_results(monkeypatch):
    monkeypatch.setattr(
        network,
        "scan_target",
        lambda **_kwargs: {"results": None},
    )

    assert network.NetworkScanner().scan("127.0.0.1") == []
