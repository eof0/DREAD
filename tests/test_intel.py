"""Tests for the Intel product: prioritization doctrine, store reads, CLI.

Follows the repo's temp-CVE-DB recipe (see tests/test_cve_db_manager.py): build a
real ``cve_entries`` schema in a tmp sqlite file, insert rows directly, and point
the store's DB path at it. No network, no monkeypatched frameworks beyond the DB
path.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest

_INTEL = Path(__file__).resolve().parents[1] / "intel"
sys.path.insert(0, str(_INTEL))

import prioritize  # noqa: E402
import store  # noqa: E402

import intel  # noqa: E402

# --- prioritize (pure) ------------------------------------------------------


def test_kev_is_act_now_regardless_of_scores():
    p = prioritize.prioritize(cvss=2.0, epss=0.001, kev=True)
    assert p.tier == prioritize.ACT_NOW
    assert "KEV" in p.reasons[0]


def test_high_epss_is_urgent_without_kev():
    p = prioritize.prioritize(cvss=3.0, epss=0.7, kev=False)
    assert p.tier == prioritize.URGENT


def test_critical_cvss_is_urgent_without_other_signals():
    p = prioritize.prioritize(cvss=9.8, epss=None, kev=False)
    assert p.tier == prioritize.URGENT


def test_elevated_epss_is_scheduled():
    p = prioritize.prioritize(cvss=None, epss=0.2, kev=False)
    assert p.tier == prioritize.SCHEDULED


def test_high_cvss_is_scheduled():
    p = prioritize.prioritize(cvss=7.5, epss=0.0, kev=False)
    assert p.tier == prioritize.SCHEDULED


def test_low_signal_is_low():
    p = prioritize.prioritize(cvss=3.1, epss=0.01, kev=False)
    assert p.tier == prioritize.LOW


def test_no_signal_but_present_is_low():
    p = prioritize.prioritize(cvss=None, epss=None, kev=False, found=True)
    assert p.tier == prioritize.LOW


def test_not_found_is_unknown():
    p = prioritize.prioritize(found=False)
    assert p.tier == prioritize.UNKNOWN
    assert p.rank == 0


def test_tier_is_most_urgent_signal():
    # Low CVSS but KEV -> act_now; the CVSS reason still appears, ranked lower.
    p = prioritize.prioritize(cvss=8.0, epss=0.6, kev=True)
    assert p.tier == prioritize.ACT_NOW
    assert p.reasons[0].startswith("CISA KEV")


def test_rank_orders_kev_first_then_epss_then_cvss():
    items = [
        ("CVE-LOW", prioritize.prioritize(cvss=3.0)),
        ("CVE-KEV", prioritize.prioritize(cvss=5.0, kev=True)),
        ("CVE-EPSS", prioritize.prioritize(cvss=6.0, epss=0.9)),
        ("CVE-CRIT", prioritize.prioritize(cvss=9.5)),
    ]
    ordered = [cid for cid, _ in prioritize.rank(items)]
    assert ordered[0] == "CVE-KEV"
    assert ordered[-1] == "CVE-LOW"
    # Both urgent; higher blended score (EPSS 0.9) ranks above bare critical CVSS.
    assert ordered.index("CVE-EPSS") < ordered.index("CVE-CRIT")


def test_rank_tiebreaks_deterministically_by_id():
    a = prioritize.prioritize(cvss=5.0)
    b = prioritize.prioritize(cvss=5.0)
    ordered = [cid for cid, _ in prioritize.rank([("CVE-B", b), ("CVE-A", a)])]
    assert ordered == ["CVE-A", "CVE-B"]


# --- store (temp DB) --------------------------------------------------------


def _make_db(tmp_path: Path, rows: list[dict]) -> str:
    """Build a minimal cve_entries table and insert the given rows."""
    db = tmp_path / "cve.sqlite"
    conn = sqlite3.connect(db)
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
            "references" TEXT,
            kev BOOLEAN DEFAULT 0,
            kev_date_added TEXT,
            epss_score REAL,
            epss_percentile REAL
        )
        """
    )
    for r in rows:
        conn.execute(
            "INSERT INTO cve_entries (cve_id, description, severity, cvss_score, "
            'cvss_vector, published_date, "references", kev, kev_date_added, '
            "epss_score, epss_percentile) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                r["cve_id"],
                r.get("description", "desc"),
                r.get("severity"),
                r.get("cvss_score"),
                r.get("cvss_vector"),
                r.get("published_date"),
                json.dumps(r["references"]) if r.get("references") else None,
                1 if r.get("kev") else 0,
                r.get("kev_date_added"),
                r.get("epss_score"),
                r.get("epss_percentile"),
            ),
        )
    conn.commit()
    conn.close()
    return str(db)


def test_fetch_record_decodes_and_flags(tmp_path):
    db = _make_db(
        tmp_path,
        [
            {
                "cve_id": "CVE-2021-44228",
                "description": "Log4Shell",
                "severity": "critical",
                "cvss_score": 10.0,
                "kev": True,
                "kev_date_added": "2021-12-10",
                "epss_score": 0.97,
                "epss_percentile": 0.999,
                "references": ["https://example.test/a", "https://example.test/b"],
            }
        ],
    )
    rec = store.fetch_record("cve-2021-44228", db_path=db)  # lower-case input
    assert rec.found is True
    assert rec.cve_id == "CVE-2021-44228"
    assert rec.kev is True
    assert rec.epss_score == 0.97
    assert rec.references == ["https://example.test/a", "https://example.test/b"]


def test_fetch_record_missing_returns_not_found(tmp_path):
    db = _make_db(tmp_path, [{"cve_id": "CVE-2020-0001"}])
    rec = store.fetch_record("CVE-9999-9999", db_path=db)
    assert rec.found is False
    assert rec.cve_id == "CVE-9999-9999"


def test_fetch_records_preserves_order_and_unknowns(tmp_path):
    db = _make_db(
        tmp_path,
        [{"cve_id": "CVE-2020-0001"}, {"cve_id": "CVE-2020-0002"}],
    )
    recs = store.fetch_records(["CVE-2020-0002", "CVE-9999-0000", "CVE-2020-0001"], db_path=db)
    assert [r.cve_id for r in recs] == [
        "CVE-2020-0002",
        "CVE-9999-0000",
        "CVE-2020-0001",
    ]
    assert [r.found for r in recs] == [True, False, True]


def test_missing_db_raises(tmp_path):
    with pytest.raises(store.CVEStoreMissing):
        store.fetch_record("CVE-2020-0001", db_path=str(tmp_path / "nope.sqlite"))


def test_coverage_stats_tier_breakdown(tmp_path):
    db = _make_db(
        tmp_path,
        [
            {"cve_id": "CVE-A", "kev": True, "cvss_score": 5.0},
            {"cve_id": "CVE-B", "cvss_score": 9.5},  # urgent (critical cvss)
            {"cve_id": "CVE-C", "epss_score": 0.6},  # urgent (high epss)
            {"cve_id": "CVE-D", "cvss_score": 7.2},  # scheduled (high cvss)
            {"cve_id": "CVE-E", "cvss_score": 2.0},  # low
        ],
    )
    stats = store.coverage_stats(db_path=db)
    assert stats["total_cves"] == 5
    assert stats["kev_count"] == 1
    assert stats["epss_scored"] == 1
    assert stats["tiers"]["act_now"] == 1
    assert stats["tiers"]["urgent"] == 2
    assert stats["tiers"]["scheduled"] == 1
    assert stats["tiers"]["low"] == 1


# --- CLI --------------------------------------------------------------------


def test_extract_cve_ids_dedups_and_uppercases():
    text = "see CVE-2021-44228 and cve-2021-44228, also CVE-2019-0708."
    assert intel.extract_cve_ids(text) == ["CVE-2021-44228", "CVE-2019-0708"]


def test_cli_cve_json(tmp_path, monkeypatch, capsys):
    db = _make_db(tmp_path, [{"cve_id": "CVE-2021-44228", "kev": True, "cvss_score": 10.0}])
    monkeypatch.setattr(store, "default_db_path", lambda: db)
    monkeypatch.setattr(sys, "argv", ["intel", "cve", "CVE-2021-44228", "--json"])
    rc = intel.main()
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["priority"] == "act_now"
    assert out["kev"] is True


def test_cli_cve_missing_returns_1(tmp_path, monkeypatch, capsys):
    db = _make_db(tmp_path, [{"cve_id": "CVE-2020-0001"}])
    monkeypatch.setattr(store, "default_db_path", lambda: db)
    monkeypatch.setattr(sys, "argv", ["intel", "cve", "CVE-9999-9999"])
    rc = intel.main()
    capsys.readouterr()
    assert rc == 1


def test_cli_triage_ranks_report(tmp_path, monkeypatch, capsys):
    db = _make_db(
        tmp_path,
        [
            {"cve_id": "CVE-2021-44228", "kev": True, "cvss_score": 10.0},
            {"cve_id": "CVE-2016-0001", "cvss_score": 4.0},
        ],
    )
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps({"findings": [{"cve": "CVE-2016-0001"}, {"cve": "cve-2021-44228"}]})
    )
    monkeypatch.setattr(store, "default_db_path", lambda: db)
    monkeypatch.setattr(sys, "argv", ["intel", "triage", str(report), "--json"])
    rc = intel.main()
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["cve_count"] == 2
    # KEV entry ranks first regardless of report order.
    assert out["triage"][0]["cve_id"] == "CVE-2021-44228"
    assert out["triage"][0]["priority"] == "act_now"


def test_cli_stats_missing_db_returns_3(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(store, "default_db_path", lambda: str(tmp_path / "nope.sqlite"))
    monkeypatch.setattr(sys, "argv", ["intel", "stats"])
    rc = intel.main()
    capsys.readouterr()
    assert rc == 3
