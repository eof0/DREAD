from scanner.config import ScanConfig
from scanner.engine import ScanEngine


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

    assert result == ("test_plugin", [], None)
