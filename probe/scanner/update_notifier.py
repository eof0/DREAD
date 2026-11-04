import json
import os

from scanner.cve_db_manager import (
    cve_db_needs_update,
    update_cve_database,
    bootstrap_cve_state,
    get_stats,
)
from scanner.paths import CVE_META_PATH
from scanner.cve_db_bootstrap import update_with_snapshot_policy

META_PATH = CVE_META_PATH
REMINDER_DAYS = 14


def _load_meta():
    if not os.path.exists(META_PATH):
        return {}
    with open(META_PATH, "r") as f:
        return json.load(f)


def check_and_notify(auto_update: bool = True):
    """
    Runs at scan startup.

    Heavy NVD sync happens on GitHub Actions and is published as
    ``cve-db-latest``. Scan-time refresh only pulls that snapshot — it does
    not crawl NVD (that is reserved for explicit ``update-cve-db``).
    """

    if os.environ.get("DREAD_CVE_PRECHECKED", "").strip() == "1":
        return

    if not cve_db_needs_update():
        return

    print("\n" + "=" * 70)
    print("⚠ CVE DATABASE OUT OF DATE ⚠")
    print("=" * 70)

    if auto_update:
        try:
            print("[*] Refreshing CVE database from the published GitHub snapshot...")
            update_with_snapshot_policy(snapshot_only=True, verbose=False)
            print("=" * 70 + "\n")
            return
        except Exception as exc:
            print(f"[!] Auto CVE snapshot refresh failed: {exc}")

    meta = _load_meta()
    last_update = meta.get("last_update", "UNKNOWN")

    print(f"Last update: {last_update}")
    print("New vulnerabilities may be missing.")
    print("Run: dread update-cve-db   (or: probe update-cve-db)")
    print("Set NVD_API_KEY for faster NVD rate limits.")
    print("=" * 70 + "\n")
