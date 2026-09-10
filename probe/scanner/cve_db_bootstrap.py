"""Download, validate, and atomically install published CVE snapshots."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests

from scanner.cve_db_manager import CVE_SCHEMA_VERSION
from scanner.paths import CVE_DB_PATH
from scanner.update_lock import dread_update_lock
from scanner.update_state import set_state_timestamp


SNAPSHOT_FORMAT_VERSION = 1
SNAPSHOT_RELEASE_URL = (
    "https://github.com/eof0/DREAD/releases/download/cve-db-latest"
)
MANIFEST_URL = f"{SNAPSHOT_RELEASE_URL}/manifest.json"
MAX_COMPRESSED_SIZE = 512 * 1024 * 1024
MAX_UNCOMPRESSED_SIZE = 2 * 1024 * 1024 * 1024
REQUIRED_TABLES = frozenset({"cve_entries", "cve_products", "cve_cpes", "metadata"})
REQUIRED_MANIFEST_FIELDS = frozenset(
    {
        "format_version",
        "schema_version",
        "coverage_mode",
        "coverage_start",
        "coverage_end",
        "built_at",
        "nvd_cursor",
        "cve_count",
        "artifact",
        "sha256_gz",
        "compressed_size",
        "uncompressed_size",
        "source_commit",
    }
)


class SnapshotError(RuntimeError):
    pass


class SnapshotValidationError(SnapshotError):
    pass


def validate_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        raise SnapshotValidationError("manifest must be a JSON object")
    missing = REQUIRED_MANIFEST_FIELDS - set(manifest)
    if missing:
        raise SnapshotValidationError(f"manifest missing fields: {sorted(missing)}")
    if manifest["format_version"] != SNAPSHOT_FORMAT_VERSION:
        raise SnapshotValidationError("unsupported format_version")
    if manifest["schema_version"] != CVE_SCHEMA_VERSION:
        raise SnapshotValidationError("unsupported schema_version")
    if manifest["coverage_mode"] != "full":
        raise SnapshotValidationError("snapshot coverage_mode must be full")
    for field in ("compressed_size", "uncompressed_size", "cve_count"):
        if not isinstance(manifest[field], int) or manifest[field] < 0:
            raise SnapshotValidationError(f"invalid {field}")
    if manifest["compressed_size"] > MAX_COMPRESSED_SIZE:
        raise SnapshotValidationError("compressed snapshot exceeds size limit")
    if manifest["uncompressed_size"] > MAX_UNCOMPRESSED_SIZE:
        raise SnapshotValidationError("uncompressed snapshot exceeds size limit")
    digest = manifest["sha256_gz"]
    if not isinstance(digest, str) or len(digest) != 64:
        raise SnapshotValidationError("invalid sha256_gz")
    if not isinstance(manifest["nvd_cursor"], str) or not manifest["nvd_cursor"]:
        raise SnapshotValidationError("invalid nvd_cursor")
    artifact = manifest["artifact"]
    if (
        not isinstance(artifact, str)
        or not artifact
        or "\x00" in artifact
        or "/" in artifact
        or "\\" in artifact
        or ":" in artifact
        or artifact in {".", ".."}
        or Path(artifact).name != artifact
    ):
        raise SnapshotValidationError("invalid artifact")
    return manifest


def fetch_snapshot_manifest(
    url: str = MANIFEST_URL,
    *,
    session: requests.Session | None = None,
) -> dict[str, Any]:
    client = session or requests.Session()
    try:
        response = client.get(url, timeout=(10, 30))
        response.raise_for_status()
    except requests.RequestException as exc:
        raise SnapshotError("could not download snapshot manifest") from exc
    try:
        manifest = response.json()
    except ValueError as exc:
        raise SnapshotValidationError("manifest is not valid JSON") from exc
    return validate_manifest(manifest)


def download_snapshot(
    manifest: dict[str, Any],
    destination: Path,
    *,
    session: requests.Session | None = None,
    base_url: str = SNAPSHOT_RELEASE_URL,
) -> Path:
    validate_manifest(manifest)
    client = session or requests.Session()
    url = f"{base_url}/{manifest['artifact']}"
    written = 0
    try:
        response = client.get(url, stream=True, timeout=(10, 120))
        response.raise_for_status()
        with destination.open("wb") as output:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if not chunk:
                    continue
                written += len(chunk)
                if written > MAX_COMPRESSED_SIZE or written > manifest["compressed_size"]:
                    raise SnapshotValidationError("compressed snapshot exceeds declared size")
                output.write(chunk)
    except requests.RequestException as exc:
        destination.unlink(missing_ok=True)
        raise SnapshotError("could not download CVE snapshot") from exc
    if written != manifest["compressed_size"]:
        raise SnapshotValidationError("compressed snapshot size mismatch")
    return destination


def verify_snapshot(path: Path, manifest: dict[str, Any]) -> None:
    validate_manifest(manifest)
    if path.stat().st_size != manifest["compressed_size"]:
        raise SnapshotValidationError("compressed snapshot size mismatch")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != manifest["sha256_gz"]:
        raise SnapshotValidationError("snapshot checksum mismatch")


def decompress_snapshot(source: Path, destination: Path, manifest: dict[str, Any]) -> Path:
    verify_snapshot(source, manifest)
    written = 0
    try:
        with gzip.open(source, "rb") as compressed, destination.open("wb") as output:
            while block := compressed.read(1024 * 1024):
                written += len(block)
                if written > MAX_UNCOMPRESSED_SIZE or written > manifest["uncompressed_size"]:
                    raise SnapshotValidationError("uncompressed snapshot exceeds declared size")
                output.write(block)
    except (gzip.BadGzipFile, EOFError) as exc:
        raise SnapshotValidationError("invalid gzip snapshot") from exc
    if written != manifest["uncompressed_size"]:
        raise SnapshotValidationError("uncompressed snapshot size mismatch")
    return destination


def validate_snapshot_database(path: Path, manifest: dict[str, Any]) -> dict[str, str | None]:
    validate_manifest(manifest)
    try:
        with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True)) as conn:
            if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise SnapshotValidationError("SQLite integrity_check failed")
            tables = {
                row[0]
                for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            if not REQUIRED_TABLES <= tables:
                raise SnapshotValidationError("snapshot is missing required tables")
            metadata = dict(conn.execute("SELECT key, value FROM metadata"))
            count = conn.execute("SELECT COUNT(*) FROM cve_entries").fetchone()[0]
    except sqlite3.Error as exc:
        raise SnapshotValidationError("snapshot is not a valid SQLite database") from exc

    comparisons = {
        "schema_version": str(manifest["schema_version"]),
        "coverage_mode": manifest["coverage_mode"],
        "coverage_start": manifest["coverage_start"],
        "coverage_end": manifest["coverage_end"],
        "nvd_cursor": manifest["nvd_cursor"],
    }
    for field, expected in comparisons.items():
        if metadata.get(field) != expected:
            raise SnapshotValidationError(f"manifest/SQLite {field} mismatch")
    if count != manifest["cve_count"]:
        raise SnapshotValidationError("manifest/SQLite cve_count mismatch")
    return {key: metadata.get(key) for key in comparisons}


def _checkpoint_existing_database(destination: Path) -> None:
    sidecars = [Path(f"{destination}{suffix}") for suffix in ("-wal", "-shm")]
    if not any(path.exists() for path in sidecars):
        return
    if not destination.exists():
        raise SnapshotValidationError("SQLite sidecar exists without the main database")

    try:
        with closing(sqlite3.connect(destination, timeout=0)) as conn:
            conn.execute("PRAGMA busy_timeout=0")
            busy, _, _ = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    except sqlite3.Error as exc:
        raise SnapshotValidationError(
            "cannot checkpoint the current database before snapshot installation"
        ) from exc
    if busy:
        raise SnapshotValidationError(
            "current database is busy; snapshot installation was not attempted"
        )

    for sidecar in sidecars:
        if not sidecar.exists():
            continue
        if sidecar.stat().st_size:
            raise SnapshotValidationError(
                f"SQLite sidecar remains after checkpoint: {sidecar}"
            )
        sidecar.unlink()


def install_snapshot_atomically(
    snapshot_db: Path,
    manifest: dict[str, Any],
    *,
    destination: Path | None = None,
) -> str:
    destination = destination or Path(CVE_DB_PATH)
    validate_snapshot_database(snapshot_db, manifest)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    with dread_update_lock():
        _checkpoint_existing_database(destination)
        try:
            with tempfile.NamedTemporaryFile(
                dir=destination.parent,
                prefix=".cve-install-",
                suffix=".sqlite",
                delete=False,
            ) as temp_file:
                temp_path = Path(temp_file.name)
            shutil.copyfile(snapshot_db, temp_path)
            with closing(sqlite3.connect(temp_path)) as conn:
                conn.execute("PRAGMA journal_mode=DELETE")
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                conn.commit()
            validate_snapshot_database(temp_path, manifest)
            os.replace(temp_path, destination)
            temp_path = None
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
    return manifest["nvd_cursor"]


def bootstrap_from_snapshot() -> dict[str, Any]:
    manifest = fetch_snapshot_manifest()
    destination = Path(CVE_DB_PATH)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent) as temp_dir:
        temp_root = Path(temp_dir)
        compressed = download_snapshot(manifest, temp_root / manifest["artifact"])
        database = decompress_snapshot(compressed, temp_root / "cve_db.sqlite", manifest)
        cursor = install_snapshot_atomically(database, manifest, destination=destination)
    set_state_timestamp("cve", "last_modified", cursor)
    return manifest


def update_with_snapshot_policy(
    *,
    snapshot_only: bool = False,
    verbose: bool = False,
) -> int:
    """Bootstrap incomplete stores from a snapshot, then catch up from NVD."""
    from scanner import cve_db_manager as manager

    if snapshot_only:
        bootstrap_from_snapshot()
        return 0

    complete = manager.cve_db_is_complete()
    cursor = manager.read_cve_metadata().get("nvd_cursor") if complete else None
    cursor_too_old = False
    if cursor:
        try:
            parsed = datetime.fromisoformat(cursor.replace("Z", "+00:00"))
        except ValueError:
            cursor_too_old = True
        else:
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            cursor_too_old = datetime.now(timezone.utc) - parsed > timedelta(days=119)

    if not complete or cursor_too_old:
        try:
            bootstrap_from_snapshot()
        except SnapshotError as exc:
            print(f"[!] CVE snapshot unavailable: {exc}")
            if not complete:
                print("[!] Falling back to a 30-day publication bootstrap; coverage is partial.")
                return manager.update_cve_database(
                    days=30,
                    incremental=False,
                    verbose=verbose,
                )
            print("[!] Falling back to chunked incremental NVD catch-up.")
    return manager.update_cve_database(days=30, incremental=True, verbose=verbose)


def install_snapshot_artifact(manifest_path: Path, artifact_path: Path) -> dict[str, Any]:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SnapshotValidationError("cannot read local snapshot manifest") from exc
    validate_manifest(manifest)
    destination = Path(CVE_DB_PATH)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent) as temp_dir:
        database = decompress_snapshot(
            artifact_path,
            Path(temp_dir) / "cve_db.sqlite",
            manifest,
        )
        cursor = install_snapshot_atomically(database, manifest, destination=destination)
    set_state_timestamp("cve", "last_modified", cursor)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Install a DREAD CVE snapshot")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    args = parser.parse_args()
    install_snapshot_artifact(args.manifest, args.artifact)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
