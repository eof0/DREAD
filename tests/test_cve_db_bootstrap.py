from __future__ import annotations

import gzip
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

import pytest
import requests


_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))


def _snapshot_db(path: Path, *, cursor: str = "2026-08-18T00:00:00.000") -> None:
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE cve_entries (cve_id TEXT PRIMARY KEY, description TEXT)")
        conn.execute("CREATE TABLE cve_products (id INTEGER PRIMARY KEY)")
        conn.execute("CREATE TABLE cve_cpes (id INTEGER PRIMARY KEY)")
        conn.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT)")
        conn.execute("INSERT INTO cve_entries VALUES ('CVE-2020-0001', 'old')")
        conn.executemany(
            "INSERT INTO metadata VALUES (?, ?)",
            [
                ("schema_version", "1"),
                ("coverage_mode", "full"),
                ("coverage_start", None),
                ("coverage_end", cursor),
                ("nvd_cursor", cursor),
            ],
        )


def _artifact(tmp_path: Path):
    db = tmp_path / "snapshot.sqlite"
    gz = tmp_path / "snapshot.sqlite.gz"
    _snapshot_db(db)
    with db.open("rb") as source, gzip.open(gz, "wb") as target:
        target.write(source.read())
    compressed = gz.read_bytes()
    manifest = {
        "format_version": 1,
        "schema_version": 1,
        "coverage_mode": "full",
        "coverage_start": None,
        "coverage_end": "2026-08-18T00:00:00.000",
        "built_at": "2026-08-18T00:01:00Z",
        "nvd_cursor": "2026-08-18T00:00:00.000",
        "cve_count": 1,
        "artifact": "cve_db.sqlite.gz",
        "sha256_gz": hashlib.sha256(compressed).hexdigest(),
        "compressed_size": len(compressed),
        "uncompressed_size": db.stat().st_size,
        "source_commit": "abc123",
    }
    return db, gz, manifest


def test_validate_manifest_rejects_unsupported_schema(tmp_path: Path) -> None:
    from scanner.cve_db_bootstrap import SnapshotValidationError, validate_manifest

    _, _, manifest = _artifact(tmp_path)
    manifest["schema_version"] = 99
    with pytest.raises(SnapshotValidationError, match="schema_version"):
        validate_manifest(manifest)


def test_verify_snapshot_rejects_checksum_mismatch(tmp_path: Path) -> None:
    from scanner.cve_db_bootstrap import SnapshotValidationError, verify_snapshot

    _, gz, manifest = _artifact(tmp_path)
    manifest["sha256_gz"] = "0" * 64
    with pytest.raises(SnapshotValidationError, match="checksum"):
        verify_snapshot(gz, manifest)


def test_fetch_manifest_wraps_transport_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    from scanner.cve_db_bootstrap import SnapshotError, fetch_snapshot_manifest

    client = requests.Session()
    monkeypatch.setattr(
        client,
        "get",
        lambda *args, **kwargs: (_ for _ in ()).throw(requests.Timeout("offline")),
    )
    with pytest.raises(SnapshotError, match="download snapshot manifest"):
        fetch_snapshot_manifest(session=client)


def test_download_snapshot_wraps_transport_errors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from scanner.cve_db_bootstrap import SnapshotError, download_snapshot

    _, _, manifest = _artifact(tmp_path)
    client = requests.Session()
    monkeypatch.setattr(
        client,
        "get",
        lambda *args, **kwargs: (_ for _ in ()).throw(requests.ConnectionError("offline")),
    )
    with pytest.raises(SnapshotError, match="download CVE snapshot"):
        download_snapshot(manifest, tmp_path / "download.gz", session=client)


@pytest.mark.parametrize(
    "artifact",
    ["", ".", "..", "../db.gz", "dir/db.gz", "dir\\db.gz", "C:db.gz", "db\x00.gz"],
)
def test_validate_manifest_rejects_unsafe_artifact(
    tmp_path: Path,
    artifact: str,
) -> None:
    from scanner.cve_db_bootstrap import SnapshotValidationError, validate_manifest

    _, _, manifest = _artifact(tmp_path)
    manifest["artifact"] = artifact
    with pytest.raises(SnapshotValidationError, match="artifact"):
        validate_manifest(manifest)


def test_validate_database_rejects_manifest_cursor_mismatch(tmp_path: Path) -> None:
    from scanner.cve_db_bootstrap import SnapshotValidationError, validate_snapshot_database

    db, _, manifest = _artifact(tmp_path)
    manifest["nvd_cursor"] = "2026-08-17T00:00:00.000"
    with pytest.raises(SnapshotValidationError, match="nvd_cursor"):
        validate_snapshot_database(db, manifest)


def test_atomic_install_preserves_existing_database_on_validation_failure(tmp_path: Path) -> None:
    from scanner.cve_db_bootstrap import SnapshotValidationError, install_snapshot_atomically

    destination = tmp_path / "installed.sqlite"
    destination.write_bytes(b"existing")
    invalid = tmp_path / "invalid.sqlite"
    invalid.write_bytes(b"bad")
    manifest = {"format_version": 1, "schema_version": 1}

    with pytest.raises(SnapshotValidationError):
        install_snapshot_atomically(invalid, manifest, destination=destination)
    assert destination.read_bytes() == b"existing"


def test_atomic_install_replaces_database_and_returns_cursor(tmp_path: Path) -> None:
    from scanner.cve_db_bootstrap import install_snapshot_atomically

    db, _, manifest = _artifact(tmp_path)
    destination = tmp_path / "data" / "cve.sqlite"
    destination.parent.mkdir()
    destination.write_bytes(b"existing")

    cursor = install_snapshot_atomically(db, manifest, destination=destination)

    assert cursor == manifest["nvd_cursor"]
    with sqlite3.connect(destination) as conn:
        assert conn.execute("SELECT COUNT(*) FROM cve_entries").fetchone()[0] == 1


def test_atomic_install_checkpoints_stale_sidecars_before_replace(tmp_path: Path) -> None:
    from scanner.cve_db_bootstrap import install_snapshot_atomically

    db, _, manifest = _artifact(tmp_path)
    destination = tmp_path / "data" / "cve.sqlite"
    destination.parent.mkdir()
    _snapshot_db(destination, cursor="2026-08-17T00:00:00.000")
    Path(f"{destination}-wal").touch()
    Path(f"{destination}-shm").touch()

    install_snapshot_atomically(db, manifest, destination=destination)

    assert not Path(f"{destination}-wal").exists()
    assert not Path(f"{destination}-shm").exists()
    with sqlite3.connect(destination) as conn:
        assert conn.execute("SELECT COUNT(*) FROM cve_entries").fetchone()[0] == 1


def test_install_local_artifact_used_by_ci(monkeypatch, tmp_path: Path) -> None:
    import scanner.cve_db_bootstrap as bootstrap

    _, gz, manifest = _artifact(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    destination = tmp_path / "data" / "cve.sqlite"
    monkeypatch.setattr(bootstrap, "CVE_DB_PATH", str(destination))
    monkeypatch.setattr(bootstrap, "set_state_timestamp", lambda *args: None)

    bootstrap.install_snapshot_artifact(manifest_path, gz)

    with sqlite3.connect(destination) as conn:
        assert conn.execute("SELECT COUNT(*) FROM cve_entries").fetchone()[0] == 1
