from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace


_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))


def _response(status: int, message: str = "") -> SimpleNamespace:
    headers = {"message": message} if message else {}
    return SimpleNamespace(status_code=status, headers=headers, url="https://nvd.test", text="")


def _patch_http(monkeypatch, manager, response):
    calls = []
    sleeps = []

    def fake_get(*args, **kwargs):
        calls.append(kwargs)
        return response

    monkeypatch.setattr(manager.requests, "get", fake_get)
    monkeypatch.setattr(manager.time, "sleep", sleeps.append)
    return calls, sleeps


def test_rejected_api_key_fails_fast_without_retrying(monkeypatch) -> None:
    import scanner.cve_db_manager as manager

    calls, sleeps = _patch_http(monkeypatch, manager, _response(404, "Invalid apiKey."))

    response = manager._nvd_get({}, {"apiKey": "bad"})

    assert response.status_code == 404
    assert len(calls) == 1
    assert sleeps == []


def test_plain_404_is_still_retried(monkeypatch) -> None:
    import scanner.cve_db_manager as manager

    calls, _ = _patch_http(monkeypatch, manager, _response(404))

    manager._nvd_get({}, {})

    assert len(calls) == manager.NVD_MAX_RETRIES


def test_rejected_key_detection_reads_nvd_message_header() -> None:
    import scanner.cve_db_manager as manager

    assert manager._nvd_rejected_key(_response(404, "Invalid apiKey."))
    assert not manager._nvd_rejected_key(_response(404))
    assert not manager._nvd_rejected_key(_response(503, "Invalid apiKey."))
