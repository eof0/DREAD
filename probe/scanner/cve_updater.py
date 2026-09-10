"""
Legacy CVE updater entry points.

Scan-time updates use scanner.cve_db_manager (SQLite, incremental NVD).
This module keeps needs_update()/update_cve_db() for compatibility.
"""

from datetime import datetime, timedelta

from scanner.cve_db_manager import (
    cve_db_needs_update,
    update_cve_database,
    bootstrap_cve_state,
    DEFAULT_STALE_DAYS,
)

DEFAULT_UPDATE_DAYS = DEFAULT_STALE_DAYS


def needs_update(force: bool = False) -> bool:
    if force:
        return True
    return cve_db_needs_update(stale_days=DEFAULT_UPDATE_DAYS)


def update_cve_db(
    force: bool = False,
    incremental: bool = True,
    verbose: bool = False,
    bootstrap_days: int = 30,
) -> bool:
    """
    Update the SQLite CVE database. Never downloads the unfiltered full NVD
    corpus (~350k+ records); uses incremental lastMod or a pub-date window.
    """
    if not force and not needs_update(force):
        return False

    print("[*] Updating CVE database from NVD...")
    print("[*] Timeout per request: 60s | Results per page: 2000")

    bootstrap_cve_state()

    from scanner.update_state import get_state_timestamp

    state_ts = get_state_timestamp("cve", "last_modified")
    use_incremental = incremental and bool(state_ts) and not force

    if use_incremental:
        print("[*] Incremental CVE update (modified since last cursor)")
    else:
        print(
            f"[*] Windowed CVE update (published in last {bootstrap_days} days, "
            "not full NVD corpus)"
        )

    count = update_cve_database(
        days=bootstrap_days,
        incremental=use_incremental,
        force=force,
        verbose=verbose,
    )
    return count > 0
