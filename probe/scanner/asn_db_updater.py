import json
import os
import sys
from datetime import datetime, timezone

import requests

from scanner.paths import ASN_DB_PATH
from scanner.update_state import (
    get_section_value,
    get_state_timestamp,
    merge_section,
    set_state_timestamp,
)

# Warn / refresh after this many days without a successful sync.
ASN_DB_STALE_DAYS = 7

# All five Regional Internet Registries' delegated stats files. RIPE NCC
# alone only covers Europe/Middle East/Central Asia; ARIN and AFRINIC only
# publish the "-extended" variant, but its extra 8th field (opaque id) is
# harmless since the parser below only reads the first 7 pipe fields.
ASN_SOURCES: dict[str, str] = {
    "ripencc": "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest",
    "arin": "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "apnic": "https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest",
    "lacnic": "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest",
    "afrinic": "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
}

_STATE_LM = "source_last_modified"
_STATE_ETAG = "source_etag"


def _color_enabled() -> bool:
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR", "").strip()


def _red(msg: str) -> None:
    if _color_enabled():
        print(f"\033[1;31m{msg}\033[0m")
    else:
        print(msg)


def _green(msg: str) -> None:
    if _color_enabled():
        print(f"\033[1;32m{msg}\033[0m")
    else:
        print(msg)


def _yellow(msg: str) -> None:
    if _color_enabled():
        print(f"\033[1;33m{msg}\033[0m")
    else:
        print(msg)


def _info(msg: str) -> None:
    print(f"[*] {msg}")


def _parse_state_timestamp(value: str) -> datetime:
    cleaned = value.replace("Z", "")
    return datetime.fromisoformat(cleaned).replace(tzinfo=timezone.utc)


def _is_asn_update_required() -> tuple[bool, int | None]:
    last_updated = get_state_timestamp("asn", "last_updated")
    if not last_updated:
        return True, None
    age_days = (datetime.now(timezone.utc) - _parse_state_timestamp(last_updated)).days
    return age_days > ASN_DB_STALE_DAYS, age_days


def describe_asn_db_local_status() -> str:
    """
    Short status string for installers / diagnostics (no network).
    """
    if not os.path.isfile(ASN_DB_PATH):
        return "missing (never downloaded)"
    need, age = _is_asn_update_required()
    if need:
        if age is None:
            return "outdated (no sync record; refresh recommended)"
        return f"outdated (last sync ~{age} days ago; refresh after {ASN_DB_STALE_DAYS} days)"
    return f"ok (last sync {age} days ago, within {ASN_DB_STALE_DAYS} day window)"


def _head_source_identity(url: str) -> tuple[str | None, str | None]:
    """Return (Last-Modified, ETag) from an ASN source URL, if present."""
    try:
        h = requests.head(
            url,
            timeout=30,
            allow_redirects=True,
            headers={"Accept": "*/*"},
        )
        if h.status_code != 200:
            return None, None
        lm = h.headers.get("Last-Modified")
        etag = h.headers.get("ETag") or h.headers.get("Etag")
        return lm, etag
    except Exception:
        return None, None


def _stored_source_identity(registry: str) -> tuple[str | None, str | None]:
    lm = get_section_value("asn", f"{registry}_{_STATE_LM}")
    etag = get_section_value("asn", f"{registry}_{_STATE_ETAG}")
    if not isinstance(lm, str) or not lm:
        lm = None
    if not isinstance(etag, str) or not etag:
        etag = None
    return lm, etag


def _identities_match(
    old_lm: str | None,
    old_etag: str | None,
    new_lm: str | None,
    new_etag: str | None,
) -> bool:
    """
    ETag is a precise content hash; Last-Modified can be coarse (e.g.
    day-granularity) and can match even when the content changed. When both
    sides have an ETag, trust it exclusively -- don't let a stale-but-equal
    Last-Modified override a real ETag mismatch. Only fall back to
    Last-Modified when an ETag isn't available on both sides.
    """
    if old_etag and new_etag:
        return new_etag.strip() == old_etag.strip()
    if old_lm and new_lm:
        return new_lm.strip() == old_lm.strip()
    return False


def _touch_local_asn_metadata(verbose: bool = False) -> None:
    """Refresh local metadata when none of the upstream delegated files changed."""
    if not os.path.isfile(ASN_DB_PATH):
        return
    try:
        with open(ASN_DB_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return
    meta = data.get("metadata")
    if not isinstance(meta, dict):
        meta = {}
    meta["last_updated"] = datetime.now(timezone.utc).isoformat()
    meta["sources"] = list(ASN_SOURCES.values())
    meta.pop("source", None)
    meta["sync_note"] = "unchanged upstream delegated files; metadata refreshed"
    data["metadata"] = meta
    with open(ASN_DB_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    if verbose:
        print("[VERBOSE] Wrote refreshed metadata to local ASN DB (no re-download)")


def update_asn_db(verbose: bool = False, force: bool = False) -> None:
    should_update, age_days = _is_asn_update_required()

    if not force and not should_update:
        _green("DB is up to date")
        return

    missing_file = not os.path.isfile(ASN_DB_PATH)
    if should_update or missing_file:
        _red("DB is out of date")
    elif force:
        _info("Forcing ASN database refresh (--force)")

    _yellow("Updating DB...")

    parent = os.path.dirname(ASN_DB_PATH)
    if parent:
        os.makedirs(parent, exist_ok=True)

    if not force and os.path.isfile(ASN_DB_PATH):
        all_unchanged = True
        for registry, url in ASN_SOURCES.items():
            new_lm, new_etag = _head_source_identity(url)
            old_lm, old_etag = _stored_source_identity(registry)
            if not (new_lm or new_etag):
                if verbose:
                    print(f"[VERBOSE] {registry}: no Last-Modified/ETag returned; will re-download.")
                all_unchanged = False
                continue
            if not (old_lm or old_etag):
                if verbose:
                    print(f"[VERBOSE] {registry}: no stored identity yet; will download once.")
                all_unchanged = False
                continue
            if not _identities_match(old_lm, old_etag, new_lm, new_etag):
                all_unchanged = False
        if all_unchanged:
            if verbose:
                _info("All RIR delegated files unchanged on server; skipping download.")
            _touch_local_asn_metadata(verbose=verbose)
            set_state_timestamp("asn", "last_updated")
            _green("Updated DB")
            return

    asn_map: dict[str, dict] = {}
    lines_processed = 0
    lines_skipped = 0
    # Collected but not persisted to state until the write below succeeds --
    # otherwise a failure partway through this loop could record registries
    # already processed as "unchanged" next run while the data they'd have
    # produced was never actually written to ASN_DB_PATH.
    pending_identities: dict[str, dict] = {}

    for registry, url in ASN_SOURCES.items():
        if verbose:
            _info(f"Downloading ASN allocation data from {registry} ({url})")

        try:
            resp = requests.get(url, timeout=120)
            if resp.status_code != 200:
                print(f"[!] ASN update failed for {registry}: HTTP {resp.status_code}")
                print(f"[!] URL: {url}")
                print(f"[!] Response: {resp.text[:500]}")
                raise RuntimeError(
                    f"ASN source request failed for {registry} with HTTP {resp.status_code}"
                )
            lm = resp.headers.get("Last-Modified")
            etag = resp.headers.get("ETag") or resp.headers.get("Etag")
            pending_identities[registry] = {
                f"{registry}_{_STATE_LM}": lm,
                f"{registry}_{_STATE_ETAG}": etag,
            }
            if verbose:
                print(f"[VERBOSE] Downloaded {len(resp.text)} bytes from {registry}")
        except Exception as e:
            print(f"[!] Failed to download ASN data from {registry}: {e}")
            raise

        for line in resp.text.splitlines():
            if line.startswith("#"):
                lines_skipped += 1
                continue

            parts = line.split("|")
            if len(parts) < 7:
                lines_skipped += 1
                continue

            _registry_field, cc, rtype, start, value, date, status = parts[:7]

            if rtype != "asn":
                continue

            try:
                asn_start = int(start)
                # 'value' is the count of consecutive ASNs in this
                # allocation block, not just a single ASN at 'start' --
                # e.g. start=306 value=66 covers ASNs 306 through 371.
                asn_count = int(value)
            except ValueError:
                continue

            # ASN number blocks don't overlap across RIRs under normal
            # allocation, so this shouldn't collide; if it ever does, the
            # last-processed registry wins.
            for asn in range(asn_start, asn_start + max(asn_count, 1)):
                asn_map[str(asn)] = {
                    "registry": registry,
                    "country": cc,
                    "status": status,
                    "allocated": date,
                }
            lines_processed += 1

            if verbose and lines_processed % 10000 == 0:
                print(f"[VERBOSE] Processed {lines_processed} ASN records so far...")

    if verbose:
        print(f"[VERBOSE] Processed {lines_processed} lines total, skipped {lines_skipped} lines")
        print(f"[VERBOSE] Total ASNs in database: {len(asn_map)}")
        sample_asns = list(asn_map.items())[:5]
        print("[VERBOSE] Sample ASN entries:")
        for asn, entry in sample_asns:
            print(f"[VERBOSE]   ASN {asn}: {entry}")

    data = {
        "metadata": {
            "sources": list(ASN_SOURCES.values()),
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "total_asns": len(asn_map),
        },
        "asns": asn_map,
    }

    with open(ASN_DB_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    for registry_updates in pending_identities.values():
        merge_section("asn", registry_updates)
    set_state_timestamp("asn", "last_updated")
    _green("Updated DB")


def refresh_asn_db_before_scan(*, verbose: bool = False) -> None:
    """Refresh ASN data at scan start; continue scan if refresh fails."""
    if os.environ.get("DREAD_ASN_PRECHECKED", "").strip() == "1":
        if verbose:
            _info("ASN DB pre-check already completed by DREAD; skipping duplicate check.")
        return
    try:
        update_asn_db(verbose=verbose, force=False)
    except Exception as e:
        _red("ASN database refresh failed (continuing scan).")
        print(f"[!] {e}")
        _info("Try manually: dread update-db")
