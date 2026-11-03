import json

import pytest
from fastapi import HTTPException

from reports.api.app import _scan_finalize, _validate_target


def _suite(tmp_path, report):
    folder = tmp_path / "run_1" / "suite_report"
    folder.mkdir(parents=True)
    (folder / "dread_suite_report.json").write_text(json.dumps(report), encoding="utf-8")
    return tmp_path


def test_finalize_keeps_wholly_failed_scan_failed(tmp_path):
    job = _suite(tmp_path, {
        "rollups": {"partial": True},
        "sources": {"probe": {"scans": [{"statistics": {
            "status": "failed", "partial": True, "checks": {"successful": 0},
        }}]}},
    })
    assert _scan_finalize(job, 1)["status"] == "failed"


def test_finalize_uses_successful_checks_when_status_is_absent(tmp_path):
    job = _suite(tmp_path, {
        "rollups": {"partial": True},
        "sources": {"probe": {"scans": [{"statistics": {
            "partial": True, "checks": {"successful": 0},
        }}]}},
    })
    assert _scan_finalize(job, 1)["status"] == "failed"


def test_finalize_marks_partial_when_some_checks_succeeded(tmp_path):
    job = _suite(tmp_path, {
        "rollups": {"partial": True},
        "sources": {"probe": {"scans": [
            {"statistics": {"status": "failed", "partial": True, "checks": {"successful": 0}}},
            {"statistics": {"status": "partial", "partial": True, "checks": {"successful": 2}}},
        ]}},
    })
    assert _scan_finalize(job, 1)["status"] == "partial"


def test_validate_target_accepts_domains_and_adds_scheme():
    assert _validate_target("example.com") == "example.com"
    assert _validate_target("https://example.com/app") == "https://example.com/app"


@pytest.mark.parametrize("target", ["not a url", "ftp://example.com", "javascript:alert(1)"])
def test_validate_target_rejects_non_web_targets(target):
    with pytest.raises(HTTPException) as error:
        _validate_target(target)
    assert error.value.status_code == 422
