from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock


_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))


def test_scan_time_update_uses_snapshot_policy(monkeypatch) -> None:
    import scanner.update_notifier as notifier

    monkeypatch.setattr(notifier, "cve_db_needs_update", lambda: True)
    policy = mock.Mock(return_value=5)
    monkeypatch.setattr(notifier, "update_with_snapshot_policy", policy)

    notifier.check_and_notify(auto_update=True)

    policy.assert_called_once_with(verbose=False)
