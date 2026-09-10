from __future__ import annotations

import sys
from contextlib import closing
from pathlib import Path
from unittest import mock

import pytest


_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))


def _db(monkeypatch, tmp_path: Path):
    import scanner.cve_db_manager as manager
    import scanner.update_state as state

    monkeypatch.setattr(manager, "CVE_DB_PATH", str(tmp_path / "cve.sqlite"))
    monkeypatch.setattr(manager, "CVE_META_PATH", str(tmp_path / "meta.json"))
    monkeypatch.setattr(manager, "migrate_legacy_cve_database", lambda: False)
    monkeypatch.setattr(state, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(state, "STATE_PATH", tmp_path / "state" / "state.json")
    manager.init_cve_database()
    return manager


def test_matching_incomplete_window_resumes_next_index(monkeypatch, tmp_path: Path) -> None:
    manager = _db(monkeypatch, tmp_path)
    with manager._connect() as conn:
        assert manager.prepare_sync_window(
            conn, mode="publication", window_start="a", window_end="b", results_per_page=2000
        ) == 0
        manager.checkpoint_sync_page(conn, next_start_index=4000, total_expected=9000)

    with manager._connect() as conn:
        assert manager.prepare_sync_window(
            conn, mode="publication", window_start="a", window_end="b", results_per_page=2000
        ) == 4000


def test_changed_window_invalidates_checkpoint(monkeypatch, tmp_path: Path) -> None:
    manager = _db(monkeypatch, tmp_path)
    with manager._connect() as conn:
        manager.prepare_sync_window(
            conn, mode="publication", window_start="a", window_end="b", results_per_page=2000
        )
        manager.checkpoint_sync_page(conn, next_start_index=4000, total_expected=9000)
        assert manager.prepare_sync_window(
            conn, mode="publication", window_start="b", window_end="c", results_per_page=2000
        ) == 0


def test_completed_window_does_not_resume(monkeypatch, tmp_path: Path) -> None:
    manager = _db(monkeypatch, tmp_path)
    with manager._connect() as conn:
        manager.prepare_sync_window(
            conn, mode="modified", window_start="a", window_end="b", results_per_page=2000
        )
        manager.checkpoint_sync_page(conn, next_start_index=2000, total_expected=2000)
        manager.complete_sync_window(conn)
        assert manager.prepare_sync_window(
            conn, mode="modified", window_start="a", window_end="b", results_per_page=2000
        ) == 0


def test_resumed_full_build_preserves_committed_rows(monkeypatch, tmp_path: Path) -> None:
    manager = _db(monkeypatch, tmp_path)
    manager.CVE_DB_PATH = str(tmp_path / ".cve.sqlite.full-build")
    manager.init_cve_database()
    target = "2026-08-18T00:00:00.000"
    with closing(manager._connect()) as conn:
        conn.execute(
            "INSERT INTO cve_entries (cve_id, description) VALUES (?, ?)",
            ("CVE-1999-0001", "already committed"),
        )
        manager.write_cve_metadata(
            {"coverage_mode": "windowed", "coverage_end": target}, conn=conn
        )
        conn.execute(
            "INSERT OR REPLACE INTO sync_state "
            "(id, mode, window_start, window_end, results_per_page, next_start_index, "
            "total_expected, started_at, completed) VALUES (1, ?, ?, ?, 2000, 2000, 4000, ?, 0)",
            (
                "full-publication",
                "2026-04-21T00:00:00.000",
                target,
                "2026-08-17T00:00:00.000",
            ),
        )
        conn.commit()

    manager.CVE_DB_PATH = str(tmp_path / "cve.sqlite")

    response = mock.Mock(status_code=200)
    response.json.return_value = {"vulnerabilities": [], "totalResults": 0}
    monkeypatch.setattr(manager, "_nvd_get", lambda *args, **kwargs: response)

    manager.update_cve_database(full_sync=True, force=True)

    with manager._connect() as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM cve_entries WHERE cve_id='CVE-1999-0001'"
        ).fetchone()[0] == 1
    assert manager.read_cve_metadata()["coverage_mode"] == "full"


def test_failed_full_build_preserves_active_database(monkeypatch, tmp_path: Path) -> None:
    manager = _db(monkeypatch, tmp_path)
    with closing(manager._connect()) as conn:
        conn.execute(
            "INSERT INTO cve_entries (cve_id, description) VALUES (?, ?)",
            ("CVE-2026-0001", "active"),
        )
        conn.commit()
    monkeypatch.setattr(
        manager,
        "_update_cve_database_unlocked",
        mock.Mock(side_effect=RuntimeError("interrupted")),
    )

    with pytest.raises(RuntimeError, match="interrupted"):
        manager.update_cve_database(full_sync=True)

    with closing(manager._connect()) as conn:
        assert conn.execute("SELECT description FROM cve_entries").fetchone()[0] == "active"
