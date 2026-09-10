from __future__ import annotations

import importlib
import sqlite3
import sys
from pathlib import Path


_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))


def _valid_legacy_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE cve_entries (cve_id TEXT PRIMARY KEY)")
        conn.execute("CREATE TABLE cve_products (id INTEGER PRIMARY KEY)")
        conn.execute("CREATE TABLE cve_cpes (id INTEGER PRIMARY KEY)")
        conn.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT)")


def test_cve_paths_honor_data_dir_override(monkeypatch, tmp_path: Path) -> None:
    target = tmp_path / "custom-data"
    import scanner.paths as paths

    with monkeypatch.context() as patch:
        patch.setenv("DREAD_DATA_DIR", str(target))
        paths = importlib.reload(paths)
        assert Path(paths.CVE_DB_PATH) == target / "cve_db.sqlite"
        assert Path(paths.CVE_META_PATH) == target / "cve_meta.json"
    importlib.reload(paths)


def test_migration_copies_valid_legacy_database_atomically(tmp_path: Path) -> None:
    from scanner.paths import migrate_legacy_cve_database

    legacy = tmp_path / "legacy" / "cve_db.sqlite"
    destination = tmp_path / "new" / "cve_db.sqlite"
    _valid_legacy_db(legacy)

    assert migrate_legacy_cve_database(legacy, destination) is True
    assert legacy.exists()
    assert destination.exists()
    with sqlite3.connect(destination) as conn:
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_migration_rejects_invalid_legacy_database(tmp_path: Path) -> None:
    from scanner.paths import migrate_legacy_cve_database

    legacy = tmp_path / "legacy.sqlite"
    destination = tmp_path / "new" / "cve_db.sqlite"
    legacy.write_text("not sqlite", encoding="utf-8")

    assert migrate_legacy_cve_database(legacy, destination) is False
    assert not destination.exists()
    assert legacy.read_text(encoding="utf-8") == "not sqlite"


def test_existing_destination_prevents_legacy_read(tmp_path: Path) -> None:
    from scanner.paths import migrate_legacy_cve_database

    legacy = tmp_path / "missing-legacy.sqlite"
    destination = tmp_path / "data" / "cve_db.sqlite"
    destination.parent.mkdir(parents=True)
    destination.write_bytes(b"already installed")

    assert migrate_legacy_cve_database(legacy, destination) is False
    assert destination.read_bytes() == b"already installed"


def test_legacy_json_adapter_checks_new_sqlite_path() -> None:
    import scanner.cve_db as adapter
    from scanner.paths import CVE_DB_PATH

    assert adapter.CVE_SQLITE_PATH == CVE_DB_PATH
