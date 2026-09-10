from __future__ import annotations

import json
import re
from pathlib import Path

from suite_run import (
    HISTORY_SCHEMA,
    append_history_run,
    load_history,
    new_run_id,
    slug_target,
    weighted_severity_index,
)


def test_slug_target_sanitizes_and_trims() -> None:
    assert slug_target("https://foo.example/bar") == "https_foo.example_bar"
    assert slug_target("a  b", max_len=3) == "a_b"


def test_weighted_severity_index() -> None:
    assert weighted_severity_index(None) == 0.0
    assert weighted_severity_index({}) == 0.0
    w = weighted_severity_index({"critical": 1, "high": 2})
    assert w == round(25.0 + 2 * 15.0, 2)


def test_new_run_id_shape() -> None:
    rid = new_run_id()
    assert re.match(r"^\d{8}T\d{6}Z_[0-9a-f]{8}$", rid)


def test_load_history_missing_file(tmp_path: Path) -> None:
    h = load_history(tmp_path)
    assert h["schema"] == HISTORY_SCHEMA
    assert h["runs"] == []


def test_append_history_run_multiple_entries(tmp_path: Path) -> None:
    suite = tmp_path / "out"
    suite.mkdir()
    report = {
        "rollups": {
            "total_findings": 2,
            "findings_by_severity": {"high": 2},
        }
    }
    for i in range(3):
        append_history_run(
            suite,
            run_id=f"id{i}",
            generated_at="2026-01-01T00:00:00Z",
            primary_target="example.com",
            report=report,
            run_dir_rel=f"run_{i}",
        )
    data = load_history(suite)
    assert len(data["runs"]) == 3
    last = data["runs"][-1]
    assert last["run_id"] == "id2"
    assert last["weighted_severity_index"] == weighted_severity_index({"high": 2})
    assert "updated_at" in data


def test_append_history_trims_to_cap(tmp_path: Path) -> None:
    suite = tmp_path / "cap"
    suite.mkdir()
    report = {
        "rollups": {"total_findings": 0, "findings_by_severity": {}},
    }
    n = 205
    for i in range(n):
        append_history_run(
            suite,
            run_id=f"r{i}",
            generated_at="t",
            primary_target="t",
            report=report,
            run_dir_rel=f"run_{i}",
        )
    data = load_history(suite)
    assert len(data["runs"]) == 200
    assert data["runs"][0]["run_id"] == "r5"
    assert data["runs"][-1]["run_id"] == "r204"


def test_history_json_roundtrip(tmp_path: Path) -> None:
    suite = tmp_path / "s"
    suite.mkdir()
    append_history_run(
        suite,
        run_id="r1",
        generated_at="t",
        primary_target="t",
        report={"rollups": {"total_findings": 0, "findings_by_severity": {}}},
        run_dir_rel="run_r1",
    )
    p = suite / "history.json"
    raw = json.loads(p.read_text(encoding="utf-8"))
    assert raw["schema"] == HISTORY_SCHEMA
    assert len(raw["runs"]) == 1
