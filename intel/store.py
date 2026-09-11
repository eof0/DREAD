"""Read layer over the local DREAD CVE store for the Intel product.

Intel does not own or write the CVE database — Probe's cve_db_manager builds and
enriches it (NVD sync + CISA KEV + FIRST EPSS). Intel reads it. This module is a
thin, read-only accessor that returns a fuller record than
``cve_db_manager.get_cve_by_id`` (which omits epss_percentile, kev_date_added and
cvss_vector), plus store-wide coverage stats.

The canonical DB path (``~/.dread/data/cve_db.sqlite``, override with
``DREAD_DATA_DIR``) is reused from ``scanner.paths`` so Intel and Probe never
disagree on where the store lives. Every query accepts an explicit ``db_path``
override so tests can point at a temp database.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Reuse Probe's single source of truth for the store location. The product is
# launched with cwd=intel/, so probe/ is added to sys.path to import it — the
# same shim the CVE tests use.
_PROBE_DIR = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE_DIR) not in sys.path:
    sys.path.insert(0, str(_PROBE_DIR))


def default_db_path() -> str:
    """Path to the CVE store, honouring DREAD_DATA_DIR at call time."""
    from scanner.paths import CVE_DB_PATH

    return CVE_DB_PATH


class CVEStoreMissing(FileNotFoundError):
    """The CVE database file does not exist yet."""


@dataclass(frozen=True)
class IntelRecord:
    """One CVE as Intel sees it: the store record plus its scoring signals."""

    cve_id: str
    found: bool
    description: str | None = None
    severity: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    published_date: str | None = None
    kev: bool = False
    kev_date_added: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    references: list[str] = field(default_factory=list)


# Column list is a fixed literal (no caller input); every value is bound as a
# parameter. Kept inline in each query string so no variable is interpolated
# into raw SQL.
_SELECT_ONE = (
    "SELECT cve_id, description, severity, cvss_score, cvss_vector, "
    "published_date, kev, kev_date_added, epss_score, epss_percentile, "
    '"references" FROM cve_entries WHERE cve_id = ?'
)


def _resolve(db_path: str | None) -> str:
    path = db_path or default_db_path()
    if not os.path.exists(path):
        raise CVEStoreMissing("CVE database not found. Run 'dread update-cve-db' first.")
    return path


def _decode_references(raw: Any) -> list[str]:
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return []


def _row_to_record(row: sqlite3.Row) -> IntelRecord:
    return IntelRecord(
        cve_id=row["cve_id"],
        found=True,
        description=row["description"],
        severity=row["severity"],
        cvss_score=row["cvss_score"],
        cvss_vector=row["cvss_vector"],
        published_date=row["published_date"],
        kev=bool(row["kev"]),
        kev_date_added=row["kev_date_added"],
        epss_score=row["epss_score"],
        epss_percentile=row["epss_percentile"],
        references=_decode_references(row["references"]),
    )


def normalize_cve_id(cve_id: str) -> str:
    """Canonical upper-case form of a CVE id (whitespace trimmed)."""
    return (cve_id or "").strip().upper()


def _query_one(conn: sqlite3.Connection, cid: str) -> IntelRecord:
    row = conn.execute(_SELECT_ONE, (cid,)).fetchone()
    if row is None:
        return IntelRecord(cve_id=cid, found=False)
    return _row_to_record(row)


def fetch_record(cve_id: str, db_path: str | None = None) -> IntelRecord:
    """Fetch one CVE. A missing CVE returns a record with ``found=False``."""
    path = _resolve(db_path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        return _query_one(conn, normalize_cve_id(cve_id))
    finally:
        conn.close()


def fetch_records(cve_ids: list[str], db_path: str | None = None) -> list[IntelRecord]:
    """Fetch many CVEs; unknown ids come back ``found=False``.

    Order and duplicates of the input are preserved so a caller triaging a
    report gets a record for every id it asked about. Lookups are indexed
    primary-key hits, so a per-id loop over one connection is plenty fast for
    triage-sized batches.
    """
    path = _resolve(db_path)
    wanted = [normalize_cve_id(c) for c in cve_ids]
    if not wanted:
        return []
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        cache: dict[str, IntelRecord] = {}
        for cid in dict.fromkeys(wanted):
            cache[cid] = _query_one(conn, cid)
    finally:
        conn.close()
    return [cache[cid] for cid in wanted]


def coverage_stats(db_path: str | None = None) -> dict[str, Any]:
    """Store-wide intel coverage: totals, KEV/EPSS counts, and tier breakdown.

    The tier breakdown mirrors intel.prioritize's KEV-first doctrine, computed
    in SQL so it stays fast on a full store.
    """
    path = _resolve(db_path)
    conn = sqlite3.connect(path)
    try:
        cur = conn.cursor()
        total = cur.execute("SELECT COUNT(*) FROM cve_entries").fetchone()[0]
        kev_count = cur.execute("SELECT COUNT(*) FROM cve_entries WHERE kev = 1").fetchone()[0]
        epss_count = cur.execute(
            "SELECT COUNT(*) FROM cve_entries WHERE epss_score IS NOT NULL"
        ).fetchone()[0]
        # COALESCE a missing score to -1 so the boolean logic is total — SQL
        # three-valued logic would otherwise drop rows with a NULL epss/cvss
        # out of the NOT(...) branch.
        tiers = {
            "act_now": cur.execute("SELECT COUNT(*) FROM cve_entries WHERE kev = 1").fetchone()[0],
            "urgent": cur.execute(
                "SELECT COUNT(*) FROM cve_entries WHERE kev = 0 "
                "AND (COALESCE(epss_score, -1) >= 0.5 "
                "OR COALESCE(cvss_score, -1) >= 9.0)"
            ).fetchone()[0],
            "scheduled": cur.execute(
                "SELECT COUNT(*) FROM cve_entries WHERE kev = 0 "
                "AND NOT (COALESCE(epss_score, -1) >= 0.5 "
                "OR COALESCE(cvss_score, -1) >= 9.0) "
                "AND (COALESCE(epss_score, -1) >= 0.1 "
                "OR COALESCE(cvss_score, -1) >= 7.0)"
            ).fetchone()[0],
        }
        graded = tiers["act_now"] + tiers["urgent"] + tiers["scheduled"]
        tiers["low"] = max(total - graded, 0)
    finally:
        conn.close()
    return {
        "db_path": path,
        "total_cves": total,
        "kev_count": kev_count,
        "epss_scored": epss_count,
        "tiers": tiers,
    }
