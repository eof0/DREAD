from __future__ import annotations

import sys
from pathlib import Path

import pytest

_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))

import gzip

import scanner.cve_db_manager as cve_db_manager
from scanner.cve_db_manager import (
    NVD_SLEEP_NO_KEY,
    NVD_SLEEP_WITH_KEY,
    _extract_cpe_matches_from_node,
    _extract_cve_data,
    _nvd_inter_request_sleep,
    init_cve_database,
    query_cves,
    update_epss_data,
    update_kev_data,
)


class _FakeResponse:
    def __init__(self, *, json_data=None, content: bytes = b"", status_code: int = 200) -> None:
        self._json_data = json_data
        self.content = content
        self.status_code = status_code

    def json(self):
        return self._json_data

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise cve_db_manager.requests.HTTPError(f"HTTP {self.status_code}")


def _cpe_match(criteria: str, vulnerable: bool = True) -> dict:
    return {"vulnerable": vulnerable, "criteria": criteria}


def test_extract_cpe_matches_from_flat_node() -> None:
    node = {"cpeMatch": [_cpe_match("cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*")]}
    products = _extract_cpe_matches_from_node(node)
    assert products == [
        {
            "vendor": "nginx",
            "product": "nginx",
            "version_start": "1.18.0",
            "version_end": "1.18.0",
            # Exact-version CPE entry (no Including/Excluding fields):
            # treated as an inclusive single-version range so it can
            # actually match its own version once bounds are enforced.
            "version_start_including": 1,
            "version_end_including": 1,
        }
    ]


def test_extract_cpe_matches_recurses_into_children() -> None:
    # NVD configuration nodes can nest CPE matches under 'children' for
    # AND/OR logic ("product A AND (component B OR component C)"). A CVE
    # whose match only lives in a nested child has no top-level cpeMatch.
    node = {
        "operator": "AND",
        "cpeMatch": [],
        "children": [
            {"cpeMatch": [_cpe_match("cpe:2.3:a:apache:http_server:2.4.0:*:*:*:*:*:*:*")]},
            {
                "children": [
                    {"cpeMatch": [_cpe_match("cpe:2.3:a:apache:mod_ssl:2.8.0:*:*:*:*:*:*:*")]},
                ]
            },
        ],
    }
    products = _extract_cpe_matches_from_node(node)
    found = {(p["vendor"], p["product"]) for p in products}
    assert found == {("apache", "http_server"), ("apache", "mod_ssl")}


def test_extract_cpe_matches_skips_non_vulnerable_matches() -> None:
    node = {"cpeMatch": [_cpe_match("cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*", vulnerable=False)]}
    assert _extract_cpe_matches_from_node(node) == []


def test_extract_cve_data_finds_products_nested_under_children_only() -> None:
    cve_data = {
        "id": "CVE-2024-00001",
        "descriptions": [{"lang": "en", "value": "test"}],
        "references": [],
        "metrics": {},
        "configurations": [
            {
                "nodes": [
                    {
                        "operator": "AND",
                        "children": [
                            {"cpeMatch": [_cpe_match("cpe:2.3:a:apache:http_server:2.4.0:*:*:*:*:*:*:*")]},
                        ],
                    }
                ]
            }
        ],
    }
    normalized = _extract_cve_data(cve_data)
    assert normalized is not None
    assert [(p["vendor"], p["product"]) for p in normalized["products"]] == [
        ("apache", "http_server")
    ]


def test_nvd_inter_request_sleep_respects_documented_limits() -> None:
    # NVD: 5 req/30s without a key, 50 req/30s with one.
    assert _nvd_inter_request_sleep(None) == NVD_SLEEP_NO_KEY == 6.0
    assert _nvd_inter_request_sleep("some-key") == NVD_SLEEP_WITH_KEY
    assert NVD_SLEEP_WITH_KEY <= 0.6 + 0.1  # small safety margin over 30/50


def test_extract_cpe_matches_captures_excluding_bounds() -> None:
    # NVD commonly expresses "fixed in version X" as versionEndExcluding
    # (X itself is NOT vulnerable), not versionEndIncluding. The CPE
    # criteria version field is "*" for these range-based matches, so if
    # the Excluding fields aren't read, the upper bound is silently lost
    # and every later version stays "vulnerable" forever.
    node = {
        "cpeMatch": [
            {
                "vulnerable": True,
                "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                "versionStartIncluding": "2.4.0",
                "versionEndExcluding": "2.4.50",
            }
        ]
    }
    products = _extract_cpe_matches_from_node(node)
    assert len(products) == 1
    product = products[0]
    assert product["version_start"] == "2.4.0"
    assert product["version_end"] == "2.4.50"
    assert product["version_end_including"] == 0


def _query_cves_db(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    products: list[dict],
    cve_id: str = "CVE-2024-00001",
) -> Path:
    db_path = tmp_path / "cve.sqlite"
    monkeypatch.setattr(cve_db_manager, "CVE_DB_PATH", str(db_path))
    init_cve_database()
    conn = cve_db_manager._connect()
    try:
        conn.execute(
            "INSERT INTO cve_entries (cve_id, description, severity, cvss_score, \"references\") "
            "VALUES (?, 'desc', 'high', 7.5, '[]')",
            (cve_id,),
        )
        for prod in products:
            conn.execute(
                "INSERT INTO cve_products (cve_id, vendor, product, version_start, version_end, "
                "version_start_including, version_end_including) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    cve_id,
                    prod.get("vendor", "apache"),
                    prod.get("product", "apache_http_server"),
                    prod.get("version_start"),
                    prod.get("version_end"),
                    prod.get("version_start_including", 1),
                    prod.get("version_end_including", 1),
                ),
            )
        conn.commit()
    finally:
        conn.close()
    return db_path


def test_query_cves_compares_versions_numerically_not_lexicographically(monkeypatch, tmp_path: Path) -> None:
    # Range is 2.4.2 - 2.4.10 inclusive. 2.4.9 is numerically inside it,
    # but "2.4.9" > "2.4.10" as plain strings, so a lexicographic
    # comparison wrongly excludes it (false negative: a real
    # vulnerability goes unreported).
    _query_cves_db(
        tmp_path,
        monkeypatch,
        [{"version_start": "2.4.2", "version_end": "2.4.10"}],
    )
    matches = query_cves("apache", version="2.4.9")
    assert len(matches) == 1


def test_query_cves_does_not_flag_patched_version_past_digit_width_boundary(monkeypatch, tmp_path: Path) -> None:
    # Range is 2.4.2 - 2.4.9 inclusive (fixed in 2.4.10). "2.4.10" is
    # numerically past the vulnerable range and should NOT match, but
    # lexicographically "2.4.10" <= "2.4.9", so a naive string comparison
    # wrongly flags a patched version (false positive).
    _query_cves_db(
        tmp_path,
        monkeypatch,
        [{"version_start": "2.4.2", "version_end": "2.4.9"}],
    )
    matches = query_cves("apache", version="2.4.10")
    assert matches == []


def test_query_cves_respects_exclusive_upper_bound(monkeypatch, tmp_path: Path) -> None:
    # versionEndExcluding=2.4.50 means 2.4.50 itself is already patched.
    _query_cves_db(
        tmp_path,
        monkeypatch,
        [{"version_start": "2.4.0", "version_end": "2.4.50", "version_end_including": 0}],
    )
    assert query_cves("apache", version="2.4.49") != []
    assert query_cves("apache", version="2.4.50") == []


def test_update_kev_data_flags_known_cve(monkeypatch, tmp_path: Path) -> None:
    db_path = tmp_path / "cve.sqlite"
    monkeypatch.setattr(cve_db_manager, "CVE_DB_PATH", str(db_path))
    init_cve_database()
    conn = cve_db_manager._connect()
    try:
        conn.execute(
            "INSERT INTO cve_entries (cve_id, description, severity, cvss_score, \"references\") "
            "VALUES ('CVE-2024-00001', 'desc', 'high', 7.5, '[]')"
        )
        conn.commit()
    finally:
        conn.close()

    kev_payload = {
        "vulnerabilities": [
            {"cveID": "CVE-2024-00001", "dateAdded": "2024-02-01"},
            # A KEV entry for a CVE our local NVD data doesn't have yet
            # should be skipped, not inserted as a stub row.
            {"cveID": "CVE-2024-99999", "dateAdded": "2024-02-01"},
        ]
    }
    monkeypatch.setattr(
        cve_db_manager.requests,
        "get",
        lambda url, timeout=60: _FakeResponse(json_data=kev_payload),
    )

    updated = update_kev_data()
    assert updated == 1

    conn = cve_db_manager._connect()
    try:
        row = conn.execute(
            "SELECT kev, kev_date_added FROM cve_entries WHERE cve_id = 'CVE-2024-00001'"
        ).fetchone()
    finally:
        conn.close()
    assert row == (1, "2024-02-01")


def test_update_kev_data_clears_stale_flags(monkeypatch, tmp_path: Path) -> None:
    db_path = tmp_path / "cve.sqlite"
    monkeypatch.setattr(cve_db_manager, "CVE_DB_PATH", str(db_path))
    init_cve_database()
    conn = cve_db_manager._connect()
    try:
        conn.execute(
            "INSERT INTO cve_entries (cve_id, description, severity, cvss_score, \"references\", kev, kev_date_added) "
            "VALUES ('CVE-2024-00001', 'desc', 'high', 7.5, '[]', 1, '2023-01-01')"
        )
        conn.commit()
    finally:
        conn.close()

    monkeypatch.setattr(
        cve_db_manager.requests,
        "get",
        lambda url, timeout=60: _FakeResponse(json_data={"vulnerabilities": []}),
    )

    update_kev_data()

    conn = cve_db_manager._connect()
    try:
        row = conn.execute(
            "SELECT kev, kev_date_added FROM cve_entries WHERE cve_id = 'CVE-2024-00001'"
        ).fetchone()
    finally:
        conn.close()
    assert row == (0, None)


def test_update_epss_data_updates_known_cve_only(monkeypatch, tmp_path: Path) -> None:
    db_path = tmp_path / "cve.sqlite"
    monkeypatch.setattr(cve_db_manager, "CVE_DB_PATH", str(db_path))
    init_cve_database()
    conn = cve_db_manager._connect()
    try:
        conn.execute(
            "INSERT INTO cve_entries (cve_id, description, severity, cvss_score, \"references\") "
            "VALUES ('CVE-2024-00001', 'desc', 'high', 7.5, '[]')"
        )
        conn.commit()
    finally:
        conn.close()

    csv_body = (
        "#model_version:v2023.03.01,score_date:2024-01-01T00:00:00+0000\n"
        "cve,epss,percentile\n"
        "CVE-2024-00001,0.42,0.91\n"
        # A CVE we have no local record for is simply not applied.
        "CVE-2024-99999,0.10,0.20\n"
    )
    monkeypatch.setattr(
        cve_db_manager.requests,
        "get",
        lambda url, timeout=60: _FakeResponse(content=gzip.compress(csv_body.encode("utf-8"))),
    )

    updated = update_epss_data()
    assert updated == 1

    conn = cve_db_manager._connect()
    try:
        row = conn.execute(
            "SELECT epss_score, epss_percentile FROM cve_entries WHERE cve_id = 'CVE-2024-00001'"
        ).fetchone()
    finally:
        conn.close()
    assert row == (0.42, 0.91)


def test_query_cves_surfaces_kev_and_epss(monkeypatch, tmp_path: Path) -> None:
    db_path = _query_cves_db(
        tmp_path,
        monkeypatch,
        [{"version_start": "2.4.2", "version_end": "2.4.10"}],
    )
    conn = cve_db_manager._connect()
    try:
        conn.execute(
            "UPDATE cve_entries SET kev = 1, kev_date_added = '2024-02-01', "
            "epss_score = 0.9, epss_percentile = 0.99 WHERE cve_id = 'CVE-2024-00001'"
        )
        conn.commit()
    finally:
        conn.close()

    matches = query_cves("apache", version="2.4.9")
    assert len(matches) == 1
    assert matches[0]["kev"] is True
    assert matches[0]["kev_date_added"] == "2024-02-01"
    assert matches[0]["epss_score"] == 0.9
    assert matches[0]["epss_percentile"] == 0.99


def test_ensure_enrichment_columns_migrates_pre_existing_db(monkeypatch, tmp_path: Path) -> None:
    # Simulate a database built before the kev/epss columns existed.
    db_path = tmp_path / "cve.sqlite"
    monkeypatch.setattr(cve_db_manager, "CVE_DB_PATH", str(db_path))
    conn = cve_db_manager._connect()
    try:
        conn.execute(
            """
            CREATE TABLE cve_entries (
                cve_id TEXT PRIMARY KEY,
                description TEXT NOT NULL,
                severity TEXT,
                cvss_score REAL,
                cvss_vector TEXT,
                published_date TEXT,
                last_modified TEXT,
                "references" TEXT
            )
            """
        )
        conn.commit()
    finally:
        conn.close()

    init_cve_database()

    conn = cve_db_manager._connect()
    try:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(cve_entries)")}
    finally:
        conn.close()
    assert {"kev", "kev_date_added", "epss_score", "epss_percentile"} <= columns
