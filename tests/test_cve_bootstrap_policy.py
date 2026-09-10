from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock


_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))


def test_incomplete_database_installs_snapshot_then_incremental(monkeypatch) -> None:
    import scanner.cve_db_bootstrap as bootstrap
    import scanner.cve_db_manager as manager

    monkeypatch.setattr(manager, "cve_db_is_complete", lambda: False)
    install = mock.Mock(return_value={"nvd_cursor": "2026-08-18T00:00:00.000"})
    update = mock.Mock(return_value=7)
    monkeypatch.setattr(bootstrap, "bootstrap_from_snapshot", install)
    monkeypatch.setattr(manager, "update_cve_database", update)

    assert bootstrap.update_with_snapshot_policy() == 7
    install.assert_called_once_with()
    update.assert_called_once_with(days=30, incremental=True, verbose=False)


def test_snapshot_failure_on_empty_db_uses_bounded_fallback(monkeypatch) -> None:
    import scanner.cve_db_bootstrap as bootstrap
    import scanner.cve_db_manager as manager

    monkeypatch.setattr(manager, "cve_db_is_complete", lambda: False)
    monkeypatch.setattr(
        bootstrap,
        "bootstrap_from_snapshot",
        mock.Mock(side_effect=bootstrap.SnapshotError("offline")),
    )
    update = mock.Mock(return_value=3)
    monkeypatch.setattr(manager, "update_cve_database", update)

    assert bootstrap.update_with_snapshot_policy() == 3
    update.assert_called_once_with(days=30, incremental=False, verbose=False)


def test_snapshot_only_never_contacts_nvd(monkeypatch) -> None:
    import scanner.cve_db_bootstrap as bootstrap
    import scanner.cve_db_manager as manager

    install = mock.Mock(return_value={})
    update = mock.Mock()
    monkeypatch.setattr(bootstrap, "bootstrap_from_snapshot", install)
    monkeypatch.setattr(manager, "update_cve_database", update)

    assert bootstrap.update_with_snapshot_policy(snapshot_only=True) == 0
    install.assert_called_once_with()
    update.assert_not_called()


def test_full_database_over_119_days_stale_prefers_snapshot(monkeypatch) -> None:
    import scanner.cve_db_bootstrap as bootstrap
    import scanner.cve_db_manager as manager

    monkeypatch.setattr(manager, "cve_db_is_complete", lambda: True)
    monkeypatch.setattr(
        manager,
        "read_cve_metadata",
        lambda: {"nvd_cursor": "2020-01-01T00:00:00.000"},
    )
    install = mock.Mock(return_value={})
    update = mock.Mock(return_value=8)
    monkeypatch.setattr(bootstrap, "bootstrap_from_snapshot", install)
    monkeypatch.setattr(manager, "update_cve_database", update)

    assert bootstrap.update_with_snapshot_policy() == 8
    install.assert_called_once_with()
    update.assert_called_once()


def test_stale_complete_database_falls_back_to_incremental(monkeypatch) -> None:
    import scanner.cve_db_bootstrap as bootstrap
    import scanner.cve_db_manager as manager

    monkeypatch.setattr(manager, "cve_db_is_complete", lambda: True)
    monkeypatch.setattr(
        manager,
        "read_cve_metadata",
        lambda: {"nvd_cursor": "2020-01-01T00:00:00.000"},
    )
    monkeypatch.setattr(
        bootstrap,
        "bootstrap_from_snapshot",
        mock.Mock(side_effect=bootstrap.SnapshotError("offline")),
    )
    update = mock.Mock(return_value=9)
    monkeypatch.setattr(manager, "update_cve_database", update)

    assert bootstrap.update_with_snapshot_policy() == 9
    update.assert_called_once_with(days=30, incremental=True, verbose=False)


def test_invalid_complete_cursor_prefers_snapshot(monkeypatch) -> None:
    import scanner.cve_db_bootstrap as bootstrap
    import scanner.cve_db_manager as manager

    monkeypatch.setattr(manager, "cve_db_is_complete", lambda: True)
    monkeypatch.setattr(manager, "read_cve_metadata", lambda: {"nvd_cursor": "bad"})
    install = mock.Mock(return_value={})
    monkeypatch.setattr(bootstrap, "bootstrap_from_snapshot", install)
    monkeypatch.setattr(manager, "update_cve_database", mock.Mock(return_value=1))

    assert bootstrap.update_with_snapshot_policy() == 1
    install.assert_called_once_with()
