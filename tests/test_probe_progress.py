from scanner.engine import _pending_plugin_status


class Plugin:
    def __init__(self, name):
        self.name = name

    def get_name(self):
        return self.name


def test_pending_status_names_checks_and_elapsed_time():
    first = object()
    second = object()
    tasks = {
        first: (Plugin("sensitive_files"), {"url": "https://one.test"}, 10.0),
        second: (Plugin("cve_correlation"), {"url": "https://two.test"}, 12.0),
    }

    assert _pending_plugin_status({first, second}, tasks, now=17.9) == (
        "cve_correlation, sensitive_files (7s elapsed)"
    )
