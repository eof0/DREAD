#!/usr/bin/env python3
"""
CVE Database Manager

Manages SQLite database for CVE tracking with NVD feed integration.
"""

import csv
import gzip
import io
import sqlite3
import json
import os
import time
import requests
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional, Any
from pathlib import Path
from scanner.paths import CVE_DB_PATH, CVE_META_PATH, migrate_legacy_cve_database
from scanner.update_lock import dread_update_lock
from scanner.update_state import get_state_timestamp, set_state_timestamp, merge_section

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_BULK_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
DEFAULT_STALE_DAYS = 7
# NVD rate limits (https://nvd.nist.gov/developers/start-here): 5 req/30s
# without a key (6.0s spacing), 50 req/30s with one (0.6s spacing, +margin).
NVD_SLEEP_NO_KEY = 6.0
NVD_SLEEP_WITH_KEY = 0.65
NVD_MAX_RETRIES = 6
NVD_RETRY_HTTP = frozenset({404, 429, 500, 502, 503, 504})
CVE_SCHEMA_VERSION = 1
CVE_METADATA_KEYS = (
    "schema_version",
    "coverage_mode",
    "coverage_start",
    "coverage_end",
    "nvd_cursor",
)
SYNC_PROGRESS_SQL = (
    "UPDATE sync_state SET next_start_index = ?, total_expected = ? WHERE id = 1"
)
_MIRROR_COMPAT_STATE = True


def _set_compatibility_cursor(value: str) -> None:
    if _MIRROR_COMPAT_STATE:
        set_state_timestamp("cve", "last_modified", value)


def _utcnow() -> datetime:
    """Naive UTC datetime for compatibility with existing NVD timestamps."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _format_nvd_datetime(dt: datetime) -> str:
    """Return NVD-compatible timestamp with milliseconds."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def _normalize_nvd_timestamp(value: str) -> str:
    """Coerce stored timestamps to NVD lastMod format (yyyy-MM-ddTHH:mm:ss.000)."""
    value = (value or "").strip()
    if not value:
        return value
    try:
        parsed = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(parsed)
        if dt.tzinfo is not None:
            dt = dt.replace(tzinfo=None)
        return _format_nvd_datetime(dt)
    except ValueError:
        pass
    if "T" in value and "." in value:
        base, frac = value.split(".", 1)
        frac_digits = "".join(c for c in frac if c.isdigit())[:3].ljust(3, "0")
        return f"{base}.{frac_digits}"
    return value


def iter_nvd_windows(
    start: datetime,
    end: datetime,
    max_days: int = 119,
):
    """Yield contiguous NVD-safe date windows with frozen boundaries."""
    if max_days <= 0:
        raise ValueError("max_days must be positive")
    if end < start:
        raise ValueError("end must not precede start")
    cursor = start
    width = timedelta(days=max_days)
    while cursor < end:
        window_end = min(cursor + width, end)
        yield cursor, window_end
        cursor = window_end


def _nvd_inter_request_sleep(api_key: Optional[str]) -> float:
    """
    Seconds to wait between NVD requests (rate-limit safe).

    Same pacing for full_sync and incremental/windowed: a stale DB catching
    up incrementally can span just as many pages as a full sync, and NVD's
    rate limit is a rolling window, not a per-request-type budget.
    """
    return NVD_SLEEP_WITH_KEY if api_key else NVD_SLEEP_NO_KEY


def _nvd_rejected_key(response: requests.Response) -> bool:
    """NVD answers a bad or unactivated key with 404 plus a `message: Invalid apiKey.` header."""
    return response.status_code == 404 and "apikey" in response.headers.get("message", "").lower()


def _nvd_get(
    params: Dict[str, Any],
    headers: Dict[str, str],
    *,
    timeout: int = 60,
    verbose: bool = False,
) -> requests.Response:
    """GET NVD CVE API with retries on transient HTTP errors."""
    last: Optional[requests.Response] = None
    for attempt in range(1, NVD_MAX_RETRIES + 1):
        response = requests.get(
            NVD_API_URL, params=params, headers=headers, timeout=timeout
        )
        last = response
        if response.status_code == 200:
            return response
        if response.status_code not in NVD_RETRY_HTTP or _nvd_rejected_key(response):
            return response
        wait = (NVD_SLEEP_WITH_KEY if headers.get("apiKey") else NVD_SLEEP_NO_KEY) * attempt
        nvd_message = response.headers.get("message")
        print(
            f"  [!] NVD HTTP {response.status_code}"
            f"{f' ({nvd_message})' if nvd_message else ''} "
            f"(attempt {attempt}/{NVD_MAX_RETRIES}); retrying in {wait:.0f}s..."
        )
        if verbose:
            print(f"[VERBOSE] URL: {response.url}")
            body = (response.text or "").strip()
            if body:
                print(f"[VERBOSE] Body: {body[:500]}")
        time.sleep(wait)
    assert last is not None
    return last


def _normalize_severity(
    raw: Optional[str], cvss_score: Optional[float]
) -> Optional[str]:
    """
    Map NVD/CVSS severity strings to DB enum values.
    Returns None when severity cannot be classified (allowed by schema).
    """
    allowed = frozenset({"critical", "high", "medium", "low"})
    aliases = {
        "moderate": "medium",
        "none": None,
        "unknown": None,
        "": None,
    }

    if raw:
        normalized = str(raw).strip().lower()
        normalized = aliases.get(normalized, normalized)
        if normalized in allowed:
            return normalized

    if cvss_score is not None:
        try:
            score = float(cvss_score)
        except (TypeError, ValueError):
            return None
        if score <= 0:
            return None
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        return "low"

    return None


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(CVE_DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def _load_legacy_meta() -> dict:
    if not os.path.exists(CVE_META_PATH):
        return {}
    with open(CVE_META_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, dict) else {}


def bootstrap_cve_state() -> str | None:
    """
    Seed ~/.dread/state.json cve.last_modified from DB or legacy meta
    so incremental NVD sync works after upgrades or empty state files.
    """
    if os.path.exists(CVE_DB_PATH):
        conn = _connect()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM metadata WHERE key = 'nvd_cursor'")
            sqlite_cursor = cursor.fetchone()
            if sqlite_cursor and sqlite_cursor[0]:
                _set_compatibility_cursor(sqlite_cursor[0])
                return sqlite_cursor[0]
            cursor.execute("SELECT COUNT(*) FROM cve_entries")
            if cursor.fetchone()[0] == 0:
                return None
            cursor.execute(
                "SELECT MAX(last_modified) FROM cve_entries "
                "WHERE last_modified IS NOT NULL AND last_modified != ''"
            )
            row = cursor.fetchone()
            if row and row[0]:
                _set_compatibility_cursor(row[0])
                return row[0]
        finally:
            conn.close()

    existing = get_state_timestamp("cve", "last_modified")
    if existing:
        return existing

    # Do not seed from legacy meta when SQLite is empty — that cursor is too
    # stale and triggers huge lastMod incremental pulls (~40k+ CVEs).
    meta = _load_legacy_meta()
    if meta.get("entry_count", 0) == 0:
        return None

    last_update = meta.get("last_update")
    if isinstance(last_update, str) and last_update:
        try:
            dt = datetime.fromisoformat(last_update.replace("Z", "+00:00"))
            if dt.tzinfo is not None:
                dt = dt.replace(tzinfo=None)
            seeded = _format_nvd_datetime(dt)
        except ValueError:
            seeded = last_update
        _set_compatibility_cursor(seeded)
        return seeded

    return None


def read_cve_metadata(
    conn: sqlite3.Connection | None = None,
) -> Dict[str, Optional[str]]:
    owns_conn = conn is None
    conn = conn or _connect()
    try:
        rows = conn.execute(
            "SELECT key, value FROM metadata WHERE key IN ({})".format(
                ",".join("?" for _ in CVE_METADATA_KEYS)
            ),
            CVE_METADATA_KEYS,
        ).fetchall()
        values = {key: value for key, value in rows}
        return {key: values.get(key) for key in CVE_METADATA_KEYS}
    finally:
        if owns_conn:
            conn.close()


def write_cve_metadata(
    updates: Dict[str, Optional[str]],
    conn: sqlite3.Connection | None = None,
) -> None:
    unknown = set(updates) - set(CVE_METADATA_KEYS)
    if unknown:
        raise ValueError(f"Unknown CVE metadata keys: {sorted(unknown)}")
    owns_conn = conn is None
    conn = conn or _connect()
    try:
        conn.executemany(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            list(updates.items()),
        )
        if owns_conn:
            conn.commit()
    finally:
        if owns_conn:
            conn.close()


def cve_db_is_complete() -> bool:
    if not os.path.exists(CVE_DB_PATH):
        return False
    return read_cve_metadata().get("coverage_mode") == "full"


def mirror_sqlite_cursor_to_state() -> str | None:
    if not os.path.exists(CVE_DB_PATH):
        return None
    cursor = read_cve_metadata().get("nvd_cursor")
    if cursor:
        _set_compatibility_cursor(cursor)
    return cursor


def prepare_sync_window(
    conn: sqlite3.Connection,
    *,
    mode: str,
    window_start: str,
    window_end: str,
    results_per_page: int,
) -> int:
    row = conn.execute(
        "SELECT mode, window_start, window_end, results_per_page, "
        "next_start_index, completed FROM sync_state WHERE id = 1"
    ).fetchone()
    signature = (mode, window_start, window_end, results_per_page)
    if row and tuple(row[:4]) == signature and row[5] == 0:
        return int(row[4])
    conn.execute(
        "INSERT OR REPLACE INTO sync_state "
        "(id, mode, window_start, window_end, results_per_page, "
        "next_start_index, total_expected, started_at, completed) "
        "VALUES (1, ?, ?, ?, ?, 0, NULL, ?, 0)",
        (mode, window_start, window_end, results_per_page, _utcnow().isoformat()),
    )
    conn.commit()
    return 0


def checkpoint_sync_page(
    conn: sqlite3.Connection,
    *,
    next_start_index: int,
    total_expected: int,
) -> None:
    conn.execute(SYNC_PROGRESS_SQL, (next_start_index, total_expected))
    conn.commit()


def complete_sync_window(conn: sqlite3.Connection) -> None:
    conn.execute("UPDATE sync_state SET completed = 1 WHERE id = 1")
    conn.commit()


def cve_db_needs_update(stale_days: int = DEFAULT_STALE_DAYS) -> bool:
    """True when the local CVE store is missing or older than stale_days."""
    if os.environ.get("DREAD_SKIP_CVE_UPDATE", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }:
        return False

    if not os.path.exists(CVE_DB_PATH):
        return True

    conn = _connect()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM cve_entries")
        count = cursor.fetchone()[0]
        if count == 0:
            return True

        cursor.execute("SELECT value FROM metadata WHERE key = 'nvd_cursor'")
        row = cursor.fetchone()
        if row and row[0]:
            try:
                last_dt = datetime.fromisoformat(_normalize_nvd_timestamp(row[0]))
            except ValueError:
                pass
            else:
                return _utcnow() - last_dt > timedelta(days=stale_days)
        cursor.execute("SELECT value FROM metadata WHERE key = 'last_updated'")
        row = cursor.fetchone()
        if not row or not row[0]:
            meta = _load_legacy_meta()
            last_update = meta.get("last_update")
            if not last_update:
                return True
            last_dt = datetime.fromisoformat(last_update)
        else:
            last_dt = datetime.fromisoformat(row[0])
    finally:
        conn.close()

    return _utcnow() - last_dt > timedelta(days=stale_days)


def describe_cve_db_local_status() -> str:
    """
    Short status string for installers / diagnostics (no network).
    """
    if not os.path.exists(CVE_DB_PATH):
        return "missing (never built)"
    conn = _connect()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM cve_entries")
        count = cursor.fetchone()[0]
    finally:
        conn.close()
    if count == 0:
        return "empty (0 CVEs; bootstrap required before reliable correlation)"
    if read_cve_metadata().get("coverage_mode") != "full":
        return (
            f"partial ({count} CVEs; run update-cve-db to install full coverage)"
        )
    if cve_db_needs_update():
        return f"stale or incomplete ({count} CVEs; refresh recommended)"
    return f"ok ({count} CVEs loaded)"


def _ensure_enrichment_columns(cursor: sqlite3.Cursor) -> None:
    """
    Add KEV/EPSS columns to cve_entries if they're missing.

    `CREATE TABLE IF NOT EXISTS` is a no-op against a database that was
    built before these columns existed, so databases installed from an
    older cve-db-* release snapshot need them added in place rather than
    requiring a full rebuild.
    """
    existing = {row[1] for row in cursor.execute("PRAGMA table_info(cve_entries)")}
    additions = {
        "kev": "BOOLEAN DEFAULT 0",
        "kev_date_added": "TEXT",
        "epss_score": "REAL",
        "epss_percentile": "REAL",
    }
    for column, ddl in additions.items():
        if column not in existing:
            cursor.execute(f"ALTER TABLE cve_entries ADD COLUMN {column} {ddl}")


def init_cve_database():
    """Initialize SQLite database with CVE schema."""
    migrate_legacy_cve_database()
    os.makedirs(os.path.dirname(CVE_DB_PATH), exist_ok=True)
    
    conn = _connect()
    cursor = conn.cursor()
    
    # Main CVE entries table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cve_entries (
            cve_id TEXT PRIMARY KEY,
            description TEXT NOT NULL,
            severity TEXT CHECK(severity IN ('critical', 'high', 'medium', 'low')),
            cvss_score REAL CHECK(cvss_score >= 0 AND cvss_score <= 10),
            cvss_vector TEXT,
            published_date TEXT,
            last_modified TEXT,
            "references" TEXT,
            kev BOOLEAN DEFAULT 0,
            kev_date_added TEXT,
            epss_score REAL,
            epss_percentile REAL
        )
    """)
    _ensure_enrichment_columns(cursor)

    # Product mappings for version matching
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cve_products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT REFERENCES cve_entries(cve_id),
            vendor TEXT,
            product TEXT NOT NULL,
            version_start TEXT,
            version_end TEXT,
            version_start_including BOOLEAN DEFAULT 1,
            version_end_including BOOLEAN DEFAULT 1,
            UNIQUE(cve_id, vendor, product, version_start, version_end)
        )
    """)
    
    # CPE mappings
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cve_cpes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT REFERENCES cve_entries(cve_id),
            cpe_uri TEXT NOT NULL,
            is_vulnerable BOOLEAN DEFAULT 1
        )
    """)
    
    # Metadata table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sync_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            mode TEXT NOT NULL,
            window_start TEXT,
            window_end TEXT,
            results_per_page INTEGER NOT NULL,
            next_start_index INTEGER NOT NULL,
            total_expected INTEGER,
            started_at TEXT NOT NULL,
            completed INTEGER NOT NULL DEFAULT 0
        )
    """)
    cursor.executemany(
        "INSERT OR IGNORE INTO metadata (key, value) VALUES (?, ?)",
        [
            ("schema_version", str(CVE_SCHEMA_VERSION)),
            ("coverage_mode", "windowed"),
            ("coverage_start", None),
            ("coverage_end", None),
            ("nvd_cursor", None),
        ],
    )
    
    # Create indexes for performance
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cve_severity ON cve_entries(severity)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cve_cvss ON cve_entries(cvss_score)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_product_lookup ON cve_products(vendor, product)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_product_version ON cve_products(product, version_start, version_end)")
    
    conn.commit()
    conn.close()
    
    print(f"[+] CVE database initialized at {CVE_DB_PATH}")


def _update_cve_database_unlocked(
    days: int = 30,
    years: Optional[int] = None,
    full_sync: bool = False,
    raw_full_sync: bool = False,
    api_key: Optional[str] = None,
    incremental: bool = True,
    force: bool = False,
    verbose: bool = False,
    _window: tuple[str, datetime, datetime] | None = None,
) -> int:
    """
    Update CVE database from NVD feeds.

    Args:
        days: Days of *publication* window when bootstrapping (not scan coverage)
        years: Alternative bootstrap: CVEs published in the last N years
        full_sync: Download entire NVD corpus (slow; use for first-time DB build)
        api_key: Optional NVD API key for higher rate limits
        incremental: If True, only fetch CVEs modified since last update
        force: Force update even if not needed
        verbose: Enable verbose output

    Returns:
        Number of CVEs added/updated
    """
    init_cve_database()
    bootstrap_cve_state()

    headers = {
        "User-Agent": "DREAD/1.0",
    }
    api_key = api_key or os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    params: Dict[str, Any] = {
        "resultsPerPage": 2000,
        "startIndex": 0,
    }
    conn = _connect()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM cve_entries")
        existing_count = cursor.fetchone()[0]
    finally:
        conn.close()

    # Determine update strategy from persistent state.
    state_last_modified = read_cve_metadata().get("nvd_cursor") or get_state_timestamp(
        "cve", "last_modified"
    )
    update_end = _format_nvd_datetime(_utcnow())

    if _window is None:
        now_dt = _utcnow()
        if full_sync and not raw_full_sync:
            metadata = read_cve_metadata()
            with closing(_connect()) as state_conn:
                resume_row = state_conn.execute(
                    "SELECT mode, window_start, window_end, completed "
                    "FROM sync_state WHERE id = 1"
                ).fetchone()
            resuming_full = bool(
                resume_row
                and str(resume_row[0]).startswith("full-")
                and metadata.get("coverage_mode") == "windowed"
                and metadata.get("coverage_end")
            )
            if resuming_full:
                build_started = datetime.fromisoformat(metadata["coverage_end"])
            else:
                build_started = now_dt
                with closing(_connect()) as reset_conn:
                    reset_conn.execute("DELETE FROM cve_products")
                    reset_conn.execute("DELETE FROM cve_cpes")
                    reset_conn.execute("DELETE FROM cve_entries")
                    write_cve_metadata(
                        {
                            "coverage_mode": "windowed",
                            "coverage_start": None,
                            "coverage_end": _format_nvd_datetime(build_started),
                            "nvd_cursor": None,
                        },
                        conn=reset_conn,
                    )
                    reset_conn.commit()
            total = 0
            history_start = datetime(1999, 1, 1)
            resume_catchup: tuple[datetime, datetime] | None = None
            if resuming_full and resume_row:
                if resume_row[0] == "full-publication":
                    history_start = datetime.fromisoformat(
                        resume_row[2] if resume_row[3] else resume_row[1]
                    )
                elif resume_row[0] == "full-catchup":
                    history_start = build_started
                    resume_catchup = (
                        datetime.fromisoformat(resume_row[1]),
                        datetime.fromisoformat(resume_row[2]),
                    )
            for window_start, window_end in iter_nvd_windows(history_start, build_started):
                total += _update_cve_database_unlocked(
                    api_key=api_key,
                    incremental=False,
                    force=True,
                    verbose=verbose,
                    _window=("full-publication", window_start, window_end),
                )
            catchup_start, catchup_end = resume_catchup or (
                build_started,
                _utcnow(),
            )
            total += _update_cve_database_unlocked(
                api_key=api_key,
                incremental=True,
                force=False,
                verbose=verbose,
                _window=("full-catchup", catchup_start, catchup_end),
            )
            completed = _format_nvd_datetime(catchup_end)
            write_cve_metadata(
                {
                    "coverage_mode": "full",
                    "coverage_start": None,
                    "coverage_end": completed,
                    "nvd_cursor": completed,
                }
            )
            _set_compatibility_cursor(completed)
            return total

        if incremental and state_last_modified and existing_count and not force:
            cursor_dt = datetime.fromisoformat(
                _normalize_nvd_timestamp(state_last_modified)
            )
            if now_dt - cursor_dt > timedelta(days=119):
                total = 0
                for window_start, window_end in iter_nvd_windows(cursor_dt, now_dt):
                    total += _update_cve_database_unlocked(
                        api_key=api_key,
                        incremental=True,
                        verbose=verbose,
                        _window=("modified", window_start, window_end),
                    )
                return total
        elif not full_sync:
            window_days = years * 365 if years is not None and years > 0 else days
            start_dt = now_dt - timedelta(days=window_days)
            if now_dt - start_dt > timedelta(days=119):
                total = 0
                for window_start, window_end in iter_nvd_windows(start_dt, now_dt):
                    total += _update_cve_database_unlocked(
                        api_key=api_key,
                        incremental=False,
                        force=True,
                        verbose=verbose,
                        _window=("publication", window_start, window_end),
                    )
                coverage_start = _format_nvd_datetime(start_dt)
                coverage_end = _format_nvd_datetime(now_dt)
                write_cve_metadata(
                    {
                        "coverage_mode": "windowed",
                        "coverage_start": coverage_start,
                        "coverage_end": coverage_end,
                        "nvd_cursor": coverage_end,
                    }
                )
                _set_compatibility_cursor(coverage_end)
                return total

    use_incremental = False
    if _window is not None:
        window_kind, window_start_dt, window_end_dt = _window
        window_start_text = _format_nvd_datetime(window_start_dt)
        window_end_text = _format_nvd_datetime(window_end_dt)
        use_incremental = window_kind in {"modified", "full-catchup"}
        if use_incremental:
            params["lastModStartDate"] = window_start_text
            params["lastModEndDate"] = window_end_text
        else:
            params["pubStartDate"] = window_start_text
            params["pubEndDate"] = window_end_text
    elif full_sync:
        merge_section("cve", {"last_modified": None})
        state_last_modified = None
        print("[*] Full sync requested: ignoring incremental cursor and date windows")
    elif existing_count == 0:
        merge_section("cve", {"last_modified": None})
        state_last_modified = None
        use_incremental = False

    else:
        use_incremental = (
            incremental
            and state_last_modified
            and not force
            and not full_sync
            and not raw_full_sync
        )

    if _window is not None:
        pass
    elif use_incremental:
        # Incremental: only fetch CVEs modified since last update
        mod_start = _normalize_nvd_timestamp(state_last_modified)
        params['lastModStartDate'] = mod_start
        params['lastModEndDate'] = update_end
        print("[*] Incremental CVE update:")
        print(f"    from: {mod_start}")
        print(f"    to:   {update_end}")
        if verbose:
            print(f"[VERBOSE] Using lastModStartDate filter: {mod_start}")
    else:
        if full_sync:
            if incremental and not state_last_modified and not force:
                print(
                    "[!] CVE DB empty: building full local NVD mirror "
                    "(~350k CVEs; may take 30–90+ min without NVD_API_KEY)."
                )
            print("[*] Full NVD corpus sync (no date filter)")
        else:
            end_date = _utcnow()
            if years is not None and years > 0:
                window_days = years * 365
                label = f"{years} year(s)"
            else:
                window_days = days
                label = f"{days} days"
            start_date = end_date - timedelta(days=window_days)
            params['pubStartDate'] = _format_nvd_datetime(start_date)
            params['pubEndDate'] = _format_nvd_datetime(end_date)
            if incremental and not state_last_modified and not force:
                print(
                    f"[!] CVE DB empty: bootstrapping publications from last {label}. "
                    "For complete product coverage run: update-cve-db --full "
                    "(or --years 15)."
                )
            print(f"[*] Windowed update: CVEs published in last {label}")
            if verbose:
                print(f"[VERBOSE] Using pubStartDate filter: {params['pubStartDate']}")
    
    total_updated = 0
    start_index = 0
    batch_num = 0
    batch_cves = []  # Collect CVEs for batch insert
    store_conn = _connect()  # reused across all batches in this run
    overall_start_time = time.time()
    latest_last_modified: str | None = None
    saw_vulnerabilities = False
    api_failed = False
    expected_total: Optional[int] = None

    if _window is not None:
        update_type = f"{_window[0]} window"
    elif use_incremental:
        update_type = "incremental"
    elif full_sync:
        update_type = "full corpus"
    elif years:
        update_type = f"last {years} year(s) of publications"
    else:
        update_type = f"last {days} days of publications"
    print(f"[*] Fetching CVEs from NVD ({update_type})...")
    print(f"[*] Timeout per request: 60s | Results per page: {params['resultsPerPage']}")

    if _window is not None:
        checkpoint_mode = _window[0]
        checkpoint_start = (
            params["lastModStartDate"] if use_incremental else params["pubStartDate"]
        )
        checkpoint_end = (
            params["lastModEndDate"] if use_incremental else params["pubEndDate"]
        )
    elif use_incremental:
        checkpoint_mode = "modified"
        checkpoint_start = params["lastModStartDate"]
        checkpoint_end = params["lastModEndDate"]
    elif full_sync:
        checkpoint_mode = "raw-full"
        checkpoint_start = "unbounded"
        checkpoint_end = update_end
    else:
        checkpoint_mode = "publication"
        checkpoint_start = params["pubStartDate"]
        checkpoint_end = params["pubEndDate"]
    start_index = prepare_sync_window(
        store_conn,
        mode=checkpoint_mode,
        window_start=checkpoint_start,
        window_end=checkpoint_end,
        results_per_page=params["resultsPerPage"],
    )
    if start_index:
        print(f"[*] Resuming {checkpoint_mode} sync from startIndex={start_index}")

    while True:
        batch_num += 1
        params['startIndex'] = start_index
        request_start = time.time()

        try:
            print(f"[Batch {batch_num}] startIndex={start_index}", flush=True)
            response = _nvd_get(params, headers, timeout=60, verbose=verbose)
            request_time = time.time() - request_start
            print(f"({request_time:.1f}s)")
            if response.status_code != 200:
                nvd_message = response.headers.get("message")
                print(
                    f"[!] NVD API request failed: HTTP {response.status_code}"
                    f"{f' - {nvd_message}' if nvd_message else ''}"
                )
                if _nvd_rejected_key(response):
                    print(
                        "[!] NVD rejected NVD_API_KEY. Make sure the key is activated "
                        "(link in NVD's email) and that an old exported NVD_API_KEY "
                        "isn't overriding the one in .env."
                    )
                    raise RuntimeError(f"NVD rejected NVD_API_KEY: {nvd_message}")
                print(f"[!] URL: {response.url}")
                print(f"[!] Response: {response.text}")
                raise RuntimeError(
                    f"NVD API request failed with HTTP {response.status_code}"
                )
            data = response.json()
            if "vulnerabilities" not in data:
                print(f"[!] Invalid NVD response (missing 'vulnerabilities') from: {response.url}")
                print(f"[!] Response body: {response.text}")
                raise RuntimeError("NVD response missing 'vulnerabilities'")

            vulnerabilities = data.get('vulnerabilities', [])
            if not vulnerabilities:
                if use_incremental:
                    print("[+] CVE DB already up to date (no changes)")
                else:
                    print(f"  [!] No vulnerabilities returned, ending.")
                break

            saw_vulnerabilities = True
            store_start = time.time()
            total_results = int(data.get("totalResults", 0))
            if expected_total is None:
                expected_total = total_results
            page_stride = int(
                data.get("resultsPerPage") or params["resultsPerPage"]
            )
            next_start_index = start_index + page_stride
            # Collect CVE data for batch processing
            for vuln in vulnerabilities:
                cve_data = vuln.get('cve', {})
                if cve_data.get('id'):
                    batch_cves.append(cve_data)
                    cve_last_modified = cve_data.get("lastModified")
                    if cve_last_modified and (
                        latest_last_modified is None
                        or cve_last_modified > latest_last_modified
                    ):
                        latest_last_modified = cve_last_modified
                    if verbose and len(batch_cves) % 100 == 0:
                        print(f"[VERBOSE] Collected {len(batch_cves)} CVEs in current batch")

            # Store and checkpoint each NVD page in one transaction.
            if batch_cves:
                if verbose:
                    print(f"[VERBOSE] Storing batch of {len(batch_cves)} CVEs...")
                _store_cves_batch(
                    batch_cves,
                    conn=store_conn,
                    checkpoint=(next_start_index, total_results),
                )
                total_updated += len(batch_cves)
                if verbose:
                    print(f"[VERBOSE] Batch stored. Total updated so far: {total_updated}")
                batch_cves = []

            store_time = time.time() - store_start

            start_index = next_start_index

            elapsed = time.time() - overall_start_time
            rate = start_index / elapsed if elapsed > 0 else 0
            remaining = total_results - start_index
            eta_seconds = remaining / rate if rate > 0 else 0
            eta_str = f"{int(eta_seconds//60)}m{int(eta_seconds%60):02d}s" if rate > 0 else "unknown"

            print(f"  Progress: {start_index}/{total_results} CVEs | "
                  f"Rate: {rate:.1f}/s | ETA: {eta_str} | "
                  f"Store: {store_time:.1f}s")

            if start_index >= total_results:
                break

            time.sleep(_nvd_inter_request_sleep(api_key))

        except requests.exceptions.Timeout:
            print(f"\n[!] Request timeout after 60s - possible hang detected at batch {batch_num}")
            api_failed = True
            break
        except requests.exceptions.RequestException as e:
            print(f"\n[!] Request failed: {e}")
            api_failed = True
            break
        except Exception as e:
            print(f"\n[!] Error processing CVEs: {e}")
            api_failed = True
            break

    if api_failed:
        store_conn.close()
        raise RuntimeError("CVE update failed before completion; state not updated.")

    if (
        full_sync
        and expected_total
        and start_index < expected_total
        and saw_vulnerabilities
    ):
        raise RuntimeError(
            f"Incomplete full NVD sync: reached index {start_index} of "
            f"{expected_total} CVEs. Re-run: dread update-cve-db --full"
        )

    complete_sync_window(store_conn)
    store_conn.close()

    conn = _connect()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT COUNT(*) FROM cve_entries")
        total_in_db = cursor.fetchone()[0]
        cursor.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            ('last_updated', _utcnow().isoformat()),
        )
        cursor.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            ('total_entries', str(total_in_db)),
        )
        conn.commit()
    finally:
        conn.close()

    os.makedirs(os.path.dirname(CVE_META_PATH), exist_ok=True)
    with open(CVE_META_PATH, "w", encoding="utf-8") as f:
        json.dump(
            {
                "last_update": _utcnow().isoformat(),
                "updated": _utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                "entry_count": total_in_db,
                "incremental": bool(use_incremental),
            },
            f,
            indent=2,
        )

    completed_window_end = (
        _format_nvd_datetime(_window[2]) if _window is not None else update_end
    )
    if use_incremental:
        write_cve_metadata({"nvd_cursor": completed_window_end})
        _set_compatibility_cursor(completed_window_end)
    elif saw_vulnerabilities and not (
        _window is not None and _window[0] == "full-publication"
    ):
        cursor_value = latest_last_modified or update_end
        write_cve_metadata(
            {
                "nvd_cursor": cursor_value,
                "coverage_mode": "full" if full_sync else "windowed",
                "coverage_start": None if full_sync else params.get("pubStartDate"),
                "coverage_end": params.get("pubEndDate", update_end),
            }
        )
        _set_compatibility_cursor(cursor_value)
    
    print(
        f"[+] CVE database updated: {total_updated} CVEs added/updated "
        f"({total_in_db} total in DB)"
    )
    return total_updated


def update_cve_database(
    days: int = 30,
    years: Optional[int] = None,
    full_sync: bool = False,
    raw_full_sync: bool = False,
    api_key: Optional[str] = None,
    incremental: bool = True,
    force: bool = False,
    verbose: bool = False,
) -> int:
    """Run a CVE update while holding the shared mutable-data lock."""
    with dread_update_lock():
        if not full_sync or raw_full_sync:
            return _update_cve_database_unlocked(
                days=days,
                years=years,
                full_sync=full_sync,
                raw_full_sync=raw_full_sync,
                api_key=api_key,
                incremental=incremental,
                force=force,
                verbose=verbose,
            )

        global CVE_DB_PATH, CVE_META_PATH, _MIRROR_COMPAT_STATE
        destination = Path(CVE_DB_PATH)
        staging = destination.with_name(f".{destination.name}.full-build")
        metadata_destination = Path(CVE_META_PATH)
        metadata_staging = metadata_destination.with_name(
            f".{metadata_destination.name}.full-build"
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        active_path = CVE_DB_PATH
        active_metadata_path = CVE_META_PATH
        mirror_state = _MIRROR_COMPAT_STATE
        try:
            CVE_DB_PATH = str(staging)
            CVE_META_PATH = str(metadata_staging)
            _MIRROR_COMPAT_STATE = False
            count = _update_cve_database_unlocked(
                days=days,
                years=years,
                full_sync=True,
                raw_full_sync=False,
                api_key=api_key,
                incremental=incremental,
                force=force,
                verbose=verbose,
            )
            with closing(_connect()) as conn:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                conn.execute("PRAGMA journal_mode=DELETE")
                conn.commit()
        finally:
            CVE_DB_PATH = active_path
            CVE_META_PATH = active_metadata_path
            _MIRROR_COMPAT_STATE = mirror_state
        if destination.exists():
            with closing(sqlite3.connect(destination, timeout=0)) as conn:
                conn.execute("PRAGMA busy_timeout=0")
                busy, _, _ = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                if busy:
                    raise RuntimeError("current CVE database is busy")
                conn.execute("PRAGMA journal_mode=DELETE")
            if any(Path(f"{destination}{suffix}").exists() for suffix in ("-wal", "-shm")):
                raise RuntimeError("current CVE database still has active WAL state")
        os.replace(staging, destination)
        if metadata_staging.exists():
            os.replace(metadata_staging, metadata_destination)
        cursor = read_cve_metadata().get("nvd_cursor")
        if cursor:
            set_state_timestamp("cve", "last_modified", cursor)
        return count


def update_kev_data(verbose: bool = False) -> int:
    """
    Flag CVEs already in the local database that CISA's Known Exploited
    Vulnerabilities catalog lists as actively exploited in the wild.

    Only updates existing rows — a KEV entry for a CVE our local NVD data
    doesn't have yet is skipped rather than inserted as a stub, since we
    have no description/CVSS/CPE data for it.
    """
    init_cve_database()
    response = requests.get(KEV_FEED_URL, timeout=60)
    response.raise_for_status()
    vulnerabilities = response.json().get("vulnerabilities", [])

    rows = [
        (vuln.get("dateAdded"), vuln["cveID"])
        for vuln in vulnerabilities
        if vuln.get("cveID")
    ]
    if verbose:
        print(f"[VERBOSE] Parsed {len(rows)} entries from CISA KEV catalog")

    conn = _connect()
    try:
        cursor = conn.cursor()
        # Clear stale flags first so a CVE CISA later removes from the
        # catalog doesn't stay marked forever.
        cursor.execute("UPDATE cve_entries SET kev = 0, kev_date_added = NULL WHERE kev = 1")
        cursor.executemany(
            "UPDATE cve_entries SET kev = 1, kev_date_added = ? WHERE cve_id = ?",
            rows,
        )
        updated = max(cursor.rowcount, 0)
        conn.commit()
    finally:
        conn.close()

    print(f"[+] CISA KEV flag set for {updated} known CVEs")
    return updated


def update_epss_data(verbose: bool = False) -> int:
    """
    Refresh FIRST EPSS (Exploit Prediction Scoring System) scores for CVEs
    already in the local database, from FIRST's daily bulk export.

    Only updates existing rows, same reasoning as update_kev_data: EPSS
    scores for CVEs we don't have NVD data for yet aren't useful without
    the rest of the record.
    """
    init_cve_database()
    response = requests.get(EPSS_BULK_URL, timeout=60)
    response.raise_for_status()
    raw = gzip.decompress(response.content).decode("utf-8")

    rows = []
    for row in csv.reader(io.StringIO(raw)):
        if not row or row[0].startswith("#") or row[0] == "cve" or len(row) < 3:
            continue
        cve_id, score, percentile = row[0], row[1], row[2]
        try:
            rows.append((float(score), float(percentile), cve_id))
        except ValueError:
            continue
    if verbose:
        print(f"[VERBOSE] Parsed {len(rows)} EPSS scores from bulk export")

    conn = _connect()
    try:
        cursor = conn.cursor()
        cursor.executemany(
            "UPDATE cve_entries SET epss_score = ?, epss_percentile = ? WHERE cve_id = ?",
            rows,
        )
        updated = max(cursor.rowcount, 0)
        conn.commit()
    finally:
        conn.close()

    print(f"[+] EPSS score updated for {updated} known CVEs")
    return updated


def update_kev_epss(verbose: bool = False) -> Dict[str, int]:
    """
    Refresh both CISA KEV and FIRST EPSS enrichment. Each source is
    independent of the other and of the core NVD sync, so a failure in
    one (e.g. a feed being temporarily unreachable) doesn't block the
    other or the primary CVE update.
    """
    kev_updated = 0
    epss_updated = 0
    try:
        kev_updated = update_kev_data(verbose=verbose)
    except Exception as e:
        print(f"[!] CISA KEV update failed: {e}")
    try:
        epss_updated = update_epss_data(verbose=verbose)
    except Exception as e:
        print(f"[!] FIRST EPSS update failed: {e}")
    return {"kev_updated": kev_updated, "epss_updated": epss_updated}


def _extract_cpe_matches_from_node(node: Dict) -> List[Dict]:
    """
    Extract product entries from one NVD configuration node, recursing into
    nested 'children' nodes (used for AND/OR vulnerable-configuration logic,
    e.g. "product A AND (component B OR component C)"). Without recursion,
    CVEs whose CPE matches live only under a child node are stored with no
    product mapping and silently never correlate during a scan.
    """
    products = []
    for match in node.get('cpeMatch', []):
        if not match.get('vulnerable'):
            continue
        criteria = match.get('criteria', '')
        parts = criteria.split(':')
        if len(parts) < 5:
            continue
        vendor = parts[3] if len(parts) > 3 else ''
        product = parts[4] if len(parts) > 4 else ''
        version_str = parts[5] if len(parts) > 5 else '*'

        # Including and Excluding are mutually exclusive per NVD's schema;
        # track which applied so an Excluding bound (that version is
        # already patched) isn't treated as inclusive downstream.
        version_start = match.get('versionStartIncluding')
        version_start_including = 1
        if version_start is None:
            version_start = match.get('versionStartExcluding')
            if version_start is not None:
                version_start_including = 0

        version_end = match.get('versionEndIncluding')
        version_end_including = 1
        if version_end is None:
            version_end = match.get('versionEndExcluding')
            if version_end is not None:
                version_end_including = 0

        if version_start is None and version_end is None and version_str != '*':
            # Exact-version CPE entry (e.g. "...:1.18.0:*:*:..."): treat as
            # an inclusive single-version range.
            version_start = version_str
            version_end = version_str

        products.append({
            'vendor': vendor.lower(),
            'product': product.lower(),
            'version_start': version_start,
            'version_end': version_end,
            'version_start_including': version_start_including,
            'version_end_including': version_end_including,
        })

    for child in node.get('children', []):
        products.extend(_extract_cpe_matches_from_node(child))

    return products


def _extract_cve_data(cve_data: Dict) -> Optional[Dict]:
    """Extract normalized CVE data from NVD format."""
    cve_id = cve_data.get('id')
    if not cve_id:
        return None

    # Extract severity and CVSS
    severity = None
    cvss_score = None
    cvss_vector = None

    metrics = cve_data.get('metrics', {})
    for cvss_version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
        if cvss_version in metrics and metrics[cvss_version]:
            metric = metrics[cvss_version][0]
            cvss_data = metric.get('cvssData', {})
            cvss_score = cvss_data.get('baseScore')
            cvss_vector = cvss_data.get('vectorString')
            severity = _normalize_severity(metric.get('baseSeverity'), cvss_score)
            break

    # Extract description
    description = ""
    for desc in cve_data.get('descriptions', []):
        if desc.get('lang') == 'en':
            description = desc.get('value', '')
            break

    # Extract references
    references = []
    for ref in cve_data.get('references', []):
        if ref.get('url'):
            references.append(ref['url'])

    # Extract products
    products = []
    for config in cve_data.get('configurations', []):
        for node in config.get('nodes', []):
            products.extend(_extract_cpe_matches_from_node(node))

    return {
        'cve_id': cve_id,
        'description': description,
        'severity': severity,
        'cvss_score': cvss_score,
        'cvss_vector': cvss_vector,
        'published_date': cve_data.get('published'),
        'last_modified': cve_data.get('lastModified'),
        'references': json.dumps(references),
        'products': products,
    }


def _store_cves_batch(
    cve_data_list: List[Dict],
    conn: Optional[sqlite3.Connection] = None,
    checkpoint: tuple[int, int] | None = None,
):
    """
    Store multiple CVEs in a single batch transaction (much faster).

    Accepts an existing connection so callers doing many batches in one run
    (e.g. update_cve_database) don't reopen the SQLite file per batch.
    """
    if not cve_data_list:
        return

    owns_conn = conn is None
    conn = conn or _connect()
    cursor = conn.cursor()

    try:
        # Prepare batch data
        cve_entries = []
        product_entries = []

        for cve_data in cve_data_list:
            normalized = _extract_cve_data(cve_data)
            if not normalized:
                continue

            cve_entries.append((
                normalized['cve_id'], normalized['description'],
                normalized['severity'], normalized['cvss_score'],
                normalized['cvss_vector'], normalized['published_date'],
                normalized['last_modified'], normalized['references']
            ))

            for prod in normalized['products']:
                product_entries.append((
                    normalized['cve_id'], prod['vendor'], prod['product'],
                    prod['version_start'], prod['version_end'],
                    prod['version_start_including'], prod['version_end_including']
                ))

        # Batch insert CVEs
        if cve_entries:
            cursor.executemany("""
                INSERT OR REPLACE INTO cve_entries
                (cve_id, description, severity, cvss_score, cvss_vector,
                 published_date, last_modified, "references")
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, cve_entries)

        # Batch insert products (delete old first to avoid duplicates)
        cve_ids = [c[0] for c in cve_entries]
        if cve_ids:
            cursor.execute(
                "DELETE FROM cve_products WHERE cve_id IN ({})".format(
                    ','.join('?' * len(cve_ids))
                ), cve_ids
            )

        if product_entries:
            seen_products: set[tuple] = set()
            unique_products = []
            for row in product_entries:
                if row in seen_products:
                    continue
                seen_products.add(row)
                unique_products.append(row)
            cursor.executemany("""
                INSERT OR IGNORE INTO cve_products
                (cve_id, vendor, product, version_start, version_end,
                 version_start_including, version_end_including)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, unique_products)

        if checkpoint is not None:
            cursor.execute(SYNC_PROGRESS_SQL, checkpoint)

        conn.commit()
    finally:
        if owns_conn:
            conn.close()


def _store_cve(cve_data: Dict):
    """Store a single CVE in the database (deprecated, use batch)."""
    _store_cves_batch([cve_data])


def get_cve_by_id(cve_id: str) -> Optional[Dict[str, Any]]:
    """Return one CVE entry by id from the local store, or None if absent."""
    if not os.path.exists(CVE_DB_PATH):
        raise FileNotFoundError("CVE database not found. Run 'probe update-cve-db' first.")
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            'SELECT cve_id, description, severity, cvss_score, "references", '
            "published_date, kev, epss_score FROM cve_entries WHERE cve_id = ?",
            (cve_id,),
        ).fetchone()
    finally:
        conn.close()
    return dict(row) if row else None


def query_cves(
    product: str,
    vendor: Optional[str] = None,
    version: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Query CVEs affecting a specific product/version via exact CPE name matching.
    
    Uses PRODUCT_ALIASES from cve_matcher to resolve detected technology names
    to their known CPE product identifiers, avoiding false positives from
    substring matching (e.g., 'astro' no longer matches 'astrocam').

    Version filtering is done in Python (not SQL): version_start/version_end
    are dotted version strings, and comparing them with SQL's ">="/"<="
    does a lexicographic string comparison, not a numeric one (e.g. the
    string "2.4.9" sorts after "2.4.10"), which silently produces both
    false positives and false negatives. See scanner.cve_matcher.version_in_range.
    
    Args:
        product: Product name (e.g., "nginx", "wordpress")
        version: Version string (e.g., "1.18.0")
        vendor: Vendor name (optional)
        
    Returns:
        List of CVE dictionaries
    """
    if not os.path.exists(CVE_DB_PATH):
        raise FileNotFoundError("CVE database not found. Run 'probe update-cve-db' first.")
    
    from scanner.cve_matcher import _get_cpe_names, _get_expected_vendor, version_in_range
    
    cpe_names = _get_cpe_names(product)
    if not cpe_names:
        return []
    
    expected_vendor = vendor or _get_expected_vendor(product)
    
    conn = _connect()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        # Map cpe_names to their expected vendor strings for filtering
        placeholders = ','.join('?' * len(cpe_names))
        query = f"""
            SELECT DISTINCT
                c.cve_id, c.description, c.severity,
                c.cvss_score, c."references", c.published_date,
                c.kev, c.kev_date_added, c.epss_score, c.epss_percentile,
                p.version_start, p.version_end,
                p.version_start_including, p.version_end_including
            FROM cve_entries c
            JOIN cve_products p ON c.cve_id = p.cve_id
            WHERE p.product IN ({placeholders})
        """
        params: list = list(cpe_names)
        
        # Auto-filter by known vendor when the product has ambiguous vendors.
        # E.g. product="astro" has vendor="astro" (real Astro web framework)
        # and vendor="saxum2003" (Saxum Astro Joomla component).
        if expected_vendor:
            query += " AND p.vendor = ?"
            params.append(expected_vendor)
        
        query += " ORDER BY c.cvss_score DESC NULLS LAST"
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        cves = {}
        for row in rows:
            cve_id = row['cve_id']
            # version_in_range already handles version=None correctly (it
            # only matches rows with no version bounds at all); previously
            # this was guarded by `if version and ...`, which skipped the
            # range check entirely when no version was detected and let an
            # unversioned fingerprint match every bounded CVE for that
            # product, not just the unbounded ones.
            if not version_in_range(
                version,
                row['version_start'],
                row['version_end'],
                min_inclusive=bool(row['version_start_including']),
                max_inclusive=bool(row['version_end_including']),
            ):
                continue
            # "confirmed" means an actual detected version was checked
            # against a real bounded range; "low" means either no version
            # was detected, or the CVE record itself carries no version
            # bound (so it was matched purely on product name).
            confidence = (
                'confirmed'
                if version and (row['version_start'] or row['version_end'])
                else 'low'
            )
            if cve_id in cves:
                # Already matched via a different product/version row for
                # this CVE; each row is an independent vulnerable
                # configuration, so one match is enough, but prefer to
                # surface the more confident of the two if both occur.
                if confidence == 'confirmed':
                    cves[cve_id]['confidence'] = 'confirmed'
                continue
            cves[cve_id] = {
                'cve_id': cve_id,
                'description': row['description'],
                'severity': row['severity'],
                'cvss_score': row['cvss_score'],
                'published_date': row['published_date'],
                'references': json.loads(row['references'] or '[]'),
                'confidence': confidence,
                'kev': bool(row['kev']),
                'kev_date_added': row['kev_date_added'],
                'epss_score': row['epss_score'],
                'epss_percentile': row['epss_percentile'],
            }

        return list(cves.values())
        
    finally:
        conn.close()


def get_stats() -> Dict[str, Any]:
    """Get database statistics."""
    if not os.path.exists(CVE_DB_PATH):
        return {'error': 'Database not found'}
    
    conn = _connect()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT COUNT(*) FROM cve_entries")
        total_cves = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM cve_products")
        total_products = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT severity, COUNT(*) FROM cve_entries 
            WHERE severity IS NOT NULL
            GROUP BY severity
        """)
        severity_counts = dict(cursor.fetchall())
        
        cursor.execute("SELECT value FROM metadata WHERE key = 'last_updated'")
        last_updated = cursor.fetchone()
        metadata = read_cve_metadata(conn)

        cursor.execute("SELECT COUNT(*) FROM cve_entries WHERE kev = 1")
        kev_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM cve_entries WHERE epss_score IS NOT NULL")
        epss_count = cursor.fetchone()[0]

        return {
            'total_cves': total_cves,
            'total_products': total_products,
            'severity_counts': severity_counts,
            'last_updated': last_updated[0] if last_updated else None,
            'coverage_mode': metadata.get('coverage_mode'),
            'coverage_start': metadata.get('coverage_start'),
            'coverage_end': metadata.get('coverage_end'),
            'nvd_cursor': metadata.get('nvd_cursor'),
            'kev_count': kev_count,
            'epss_count': epss_count,
        }
        
    finally:
        conn.close()


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == 'update':
        days = int(sys.argv[2]) if len(sys.argv) > 2 else 30
        update_cve_database(days=days)
    elif len(sys.argv) > 1 and sys.argv[1] == 'stats':
        print(json.dumps(get_stats(), indent=2))
    elif len(sys.argv) > 1 and sys.argv[1] == 'query':
        product = sys.argv[2] if len(sys.argv) > 2 else 'nginx'
        version = sys.argv[3] if len(sys.argv) > 3 else None
        results = query_cves(product, version=version)
        print(json.dumps(results, indent=2))
    else:
        print("Usage: python cve_db_manager.py [update|stats|query]")
