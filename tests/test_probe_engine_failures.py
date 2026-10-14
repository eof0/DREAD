from scanner.config import ScanConfig
from scanner.engine import ScanEngine
import pytest


class Plugin:
    def get_name(self):
        return "test_plugin"

    def scan(self, *_args):
        raise AssertionError("plugins must not rescan an unavailable URL")


def test_plugin_scan_is_skipped_after_crawl_failure():
    engine = ScanEngine(ScanConfig("https://unavailable.example"))

    result = engine._safe_plugin_scan(
        Plugin(),
        {"url": "https://unavailable.example", "response": None},
    )

    assert result == ("test_plugin", [], "No response from target")


@pytest.mark.parametrize("responses,broken,expected", [
    ([None], False, "failed"),
    ([object()], True, "failed"),
    ([object(), None], False, "partial"),
    ([object()], False, "completed"),
])
def test_scan_records_coverage(monkeypatch, tmp_path, responses, broken, expected):
    import scanner.engine as module

    class Check:
        def get_name(self):
            return "check"

        def scan(self, *_):
            if broken:
                raise RuntimeError("check crashed")
            return []

    engine = ScanEngine(ScanConfig("http://localhost", output_dir=str(tmp_path), output_formats=["json"]))
    monkeypatch.setattr(module, "check_and_notify", lambda: None)
    monkeypatch.setattr(module, "refresh_asn_db_before_scan", lambda **_: None)
    monkeypatch.setattr(engine, "load_plugins", lambda: engine.plugins.append(Check()))
    urls = [{"url": f"http://localhost/{i}", "response": response} for i, response in enumerate(responses)]
    monkeypatch.setattr(engine.crawler, "crawl", lambda *_, **__: urls)
    report = engine.run_scan()
    stats = report["statistics"]
    assert stats["status"] == expected
    assert stats["urls_scanned"] == sum(response is not None for response in responses)
    assert stats["checks"]["successful"] == (0 if broken else stats["urls_scanned"])
    assert stats["checks_performed"] == ([] if expected == "failed" else ["check"])
    if expected == "failed":
        assert stats["risk"]["level"] == "unknown"
        assert stats["risk"]["normalized_score"] is None
    if expected != "completed":
        assert stats["partial"] is True
        assert stats["check_errors"]
