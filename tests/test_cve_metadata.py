from __future__ import annotations

import sqlite3
import sys
from contextlib import closing
from datetime import timedelta
from pathlib import Path

import pytest


_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))


def _isolate(monkeypatch, tmp_path: Path):
    import scanner.cve_db_manager as manager
    import scanner.update_state as state

    db = tmp_path / "cve_db.sqlite"
    monkeypatch.setattr(manager, "CVE_DB_PATH", str(db))
    monkeypatch.setattr(manager, "CVE_META_PATH", str(tmp_path / "cve_meta.json"))
    monkeypatch.setattr(manager, "migrate_legacy_cve_database", lambda: False)
    monkeypatch.setattr(state, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(state, "STATE_PATH", tmp_path / "state" / "state.json")
    return manager, state, db


def test_schema_initializes_coverage_metadata(monkeypatch, tmp_path: Path) -> None:
    manager, _, db = _isolate(monkeypatch, tmp_path)
    manager.init_cve_database()

    metadata = manager.read_cve_metadata()
    assert metadata["schema_version"] == str(manager.CVE_SCHEMA_VERSION)
    assert metadata["coverage_mode"] == "windowed"
    assert metadata["coverage_start"] is None
    assert metadata["coverage_end"] is None
    assert metadata["nvd_cursor"] is None
    assert db.exists()


def test_only_full_coverage_is_bootstrap_complete(monkeypatch, tmp_path: Path) -> None:
    manager, _, _ = _isolate(monkeypatch, tmp_path)
    manager.init_cve_database()

    assert manager.cve_db_is_complete() is False
    manager.write_cve_metadata({"coverage_mode": "full"})
    assert manager.cve_db_is_complete() is True


def test_metadata_rejects_unknown_keys(monkeypatch, tmp_path: Path) -> None:
    manager, _, _ = _isolate(monkeypatch, tmp_path)
    manager.init_cve_database()

    with pytest.raises(ValueError, match="Unknown CVE metadata keys"):
        manager.write_cve_metadata({"unexpected": "value"})


def test_sqlite_cursor_overrides_compatibility_state(monkeypatch, tmp_path: Path) -> None:
    manager, state, _ = _isolate(monkeypatch, tmp_path)
    manager.init_cve_database()
    manager.write_cve_metadata({"nvd_cursor": "2026-08-18T00:00:00.000"})
    state.set_state_timestamp("cve", "last_modified", "2020-01-01T00:00:00.000")

    assert manager.bootstrap_cve_state() == "2026-08-18T00:00:00.000"
    assert state.get_state_timestamp("cve", "last_modified") == "2026-08-18T00:00:00.000"


def test_mirror_cursor_never_copies_state_into_sqlite(monkeypatch, tmp_path: Path) -> None:
    manager, state, _ = _isolate(monkeypatch, tmp_path)
    manager.init_cve_database()
    state.set_state_timestamp("cve", "last_modified", "2020-01-01T00:00:00.000")

    assert manager.mirror_sqlite_cursor_to_state() is None
    assert manager.read_cve_metadata()["nvd_cursor"] is None


def test_status_uses_coverage_metadata_not_row_threshold(monkeypatch, tmp_path: Path) -> None:
    manager, _, _ = _isolate(monkeypatch, tmp_path)
    manager.init_cve_database()
    with manager._connect() as conn:
        conn.execute(
            "INSERT INTO cve_entries (cve_id, description) VALUES (?, ?)",
            ("CVE-2026-0001", "test"),
        )
    manager.write_cve_metadata(
        {
            "coverage_mode": "full",
            "nvd_cursor": manager._format_nvd_datetime(manager._utcnow()),
        }
    )

    assert manager.describe_cve_db_local_status().startswith("ok (1 CVEs loaded)")


def test_invalid_cursor_uses_last_updated_fallback(monkeypatch, tmp_path: Path) -> None:
    manager, _, _ = _isolate(monkeypatch, tmp_path)
    manager.init_cve_database()
    now = manager._utcnow()
    with closing(manager._connect()) as conn:
        conn.execute(
            "INSERT INTO cve_entries (cve_id, description) VALUES (?, ?)",
            ("CVE-2026-0001", "test"),
        )
        conn.executemany(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            [
                ("nvd_cursor", "invalid"),
                ("last_updated", (now - timedelta(days=30)).isoformat()),
            ],
        )
        conn.commit()

    assert manager.cve_db_needs_update() is True

    with closing(manager._connect()) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            ("last_updated", now.isoformat()),
        )
        conn.commit()

    assert manager.cve_db_needs_update() is False
