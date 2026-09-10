from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock


_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))


def test_iter_nvd_windows_splits_long_ranges() -> None:
    from scanner.cve_db_manager import iter_nvd_windows

    start = datetime(2020, 1, 1)
    end = start + timedelta(days=365)
    windows = list(iter_nvd_windows(start, end))

    assert windows[0][0] == start
    assert windows[-1][1] == end
    assert all(window_end - window_start <= timedelta(days=119) for window_start, window_end in windows)
    assert all(windows[index][1] == windows[index + 1][0] for index in range(len(windows) - 1))


def test_iter_nvd_windows_keeps_exact_boundary_single() -> None:
    from scanner.cve_db_manager import iter_nvd_windows

    start = datetime(2026, 1, 1)
    end = start + timedelta(days=119)
    assert list(iter_nvd_windows(start, end)) == [(start, end)]


def test_zero_result_incremental_advances_sqlite_cursor(monkeypatch, tmp_path: Path) -> None:
    import scanner.cve_db_manager as manager
    import scanner.update_state as state

    monkeypatch.setattr(manager, "CVE_DB_PATH", str(tmp_path / "cve.sqlite"))
    monkeypatch.setattr(manager, "CVE_META_PATH", str(tmp_path / "meta.json"))
    monkeypatch.setattr(manager, "migrate_legacy_cve_database", lambda: False)
    monkeypatch.setattr(state, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(state, "STATE_PATH", tmp_path / "state" / "state.json")
    manager.init_cve_database()
    manager.write_cve_metadata({"nvd_cursor": "2026-08-17T00:00:00.000"})
    with manager._connect() as conn:
        conn.execute(
            "INSERT INTO cve_entries (cve_id, description) VALUES (?, ?)",
            ("CVE-2026-0001", "existing"),
        )

    response = mock.Mock(status_code=200)
    response.json.return_value = {
        "vulnerabilities": [],
        "totalResults": 0,
        "resultsPerPage": 2000,
    }
    monkeypatch.setattr(manager, "_nvd_get", lambda *args, **kwargs: response)

    manager.update_cve_database()

    cursor = manager.read_cve_metadata()["nvd_cursor"]
    assert cursor is not None
    assert cursor > "2026-08-17T00:00:00.000"
    assert state.get_state_timestamp("cve", "last_modified") == cursor


def test_years_mode_sends_only_nvd_safe_windows(monkeypatch, tmp_path: Path) -> None:
    import scanner.cve_db_manager as manager
    import scanner.update_state as state

    monkeypatch.setattr(manager, "CVE_DB_PATH", str(tmp_path / "cve.sqlite"))
    monkeypatch.setattr(manager, "CVE_META_PATH", str(tmp_path / "meta.json"))
    monkeypatch.setattr(manager, "migrate_legacy_cve_database", lambda: False)
    monkeypatch.setattr(state, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(state, "STATE_PATH", tmp_path / "state" / "state.json")
    now = datetime(2026, 8, 18)
    monkeypatch.setattr(manager, "_utcnow", lambda: now)
    seen = []

    def response_for(params, *_args, **_kwargs):
        seen.append(dict(params))
        response = mock.Mock(status_code=200)
        response.json.return_value = {"vulnerabilities": [], "totalResults": 0}
        return response

    monkeypatch.setattr(manager, "_nvd_get", response_for)
    manager.update_cve_database(years=1, incremental=False)

    start = now - timedelta(days=365)
    expected_windows = list(manager.iter_nvd_windows(start, now))
    actual_windows = [
        (
            datetime.fromisoformat(params["pubStartDate"]),
            datetime.fromisoformat(params["pubEndDate"]),
        )
        for params in seen
    ]
    assert len(seen) == len(expected_windows)
    assert actual_windows == expected_windows
    assert all(
        window_end - window_start <= timedelta(days=119)
        for window_start, window_end in actual_windows
    )
    metadata = manager.read_cve_metadata()
    assert metadata["coverage_mode"] == "windowed"
    assert metadata["coverage_start"] == seen[0]["pubStartDate"]
    assert metadata["coverage_end"] == seen[-1]["pubEndDate"]


def test_raw_full_never_uses_date_filters(monkeypatch, tmp_path: Path) -> None:
    import scanner.cve_db_manager as manager
    import scanner.update_state as state

    monkeypatch.setattr(manager, "CVE_DB_PATH", str(tmp_path / "cve.sqlite"))
    monkeypatch.setattr(manager, "CVE_META_PATH", str(tmp_path / "meta.json"))
    monkeypatch.setattr(manager, "migrate_legacy_cve_database", lambda: False)
    monkeypatch.setattr(state, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(state, "STATE_PATH", tmp_path / "state" / "state.json")
    seen = []

    def response_for(params, *_args, **_kwargs):
        seen.append(dict(params))
        response = mock.Mock(status_code=200)
        response.json.return_value = {"vulnerabilities": [], "totalResults": 0}
        return response

    monkeypatch.setattr(manager, "_nvd_get", response_for)
    manager.update_cve_database(full_sync=True, raw_full_sync=True, force=False)

    assert len(seen) == 1
    assert not {"lastModStartDate", "lastModEndDate", "pubStartDate", "pubEndDate"} & seen[0].keys()
