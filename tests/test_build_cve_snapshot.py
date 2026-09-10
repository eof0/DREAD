from __future__ import annotations

import gzip
import hashlib
import importlib.util
import json
import sqlite3
from pathlib import Path

import pytest


def _load_builder():
    path = Path(__file__).resolve().parents[1] / "scripts" / "build_cve_snapshot.py"
    spec = importlib.util.spec_from_file_location("build_cve_snapshot", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _database(path: Path) -> None:
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE cve_entries (cve_id TEXT PRIMARY KEY)")
        conn.execute("CREATE TABLE cve_products (id INTEGER PRIMARY KEY)")
        conn.execute("CREATE TABLE cve_cpes (id INTEGER PRIMARY KEY)")
        conn.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT)")
        conn.execute("INSERT INTO cve_entries VALUES ('CVE-2020-0001')")
        conn.executemany(
            "INSERT INTO metadata VALUES (?, ?)",
            [
                ("schema_version", "1"),
                ("coverage_mode", "full"),
                ("coverage_start", None),
                ("coverage_end", "2026-08-18T00:00:00.000"),
                ("nvd_cursor", "2026-08-18T00:00:00.000"),
            ],
        )


def test_build_snapshot_copies_sqlite_metadata_and_hashes_artifact(tmp_path: Path) -> None:
    builder = _load_builder()
    db = tmp_path / "cve.sqlite"
    dist = tmp_path / "dist"
    second_dist = tmp_path / "dist-second"
    _database(db)

    manifest = builder.build_snapshot(db, dist, source_commit="deadbeef")
    second_manifest = builder.build_snapshot(db, second_dist, source_commit="deadbeef")

    artifact = dist / "cve_db.sqlite.gz"
    on_disk = json.loads((dist / "manifest.json").read_text(encoding="utf-8"))
    assert on_disk == manifest
    assert manifest["coverage_mode"] == "full"
    assert manifest["nvd_cursor"] == "2026-08-18T00:00:00.000"
    assert manifest["cve_count"] == 1
    assert manifest["sha256_gz"] == hashlib.sha256(artifact.read_bytes()).hexdigest()
    assert second_manifest["sha256_gz"] == manifest["sha256_gz"]
    with gzip.open(artifact, "rb") as source:
        assert source.read() == db.read_bytes()


def test_build_snapshot_rejects_oversized_database(monkeypatch, tmp_path: Path) -> None:
    builder = _load_builder()
    db = tmp_path / "cve.sqlite"
    _database(db)
    monkeypatch.setattr(builder, "MAX_UNCOMPRESSED_SIZE", 0)

    with pytest.raises(RuntimeError, match="uncompressed size limit"):
        builder.build_snapshot(db, tmp_path / "dist", source_commit="deadbeef")
