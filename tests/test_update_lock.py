from __future__ import annotations

import sys
from contextlib import nullcontext
from pathlib import Path
from unittest import mock

import pytest


_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))


def test_lock_is_reentrant_and_released_after_exception(tmp_path: Path) -> None:
    from scanner.update_lock import dread_update_lock

    lock_path = tmp_path / ".update.lock"
    with pytest.raises(RuntimeError):
        with dread_update_lock(lock_path=lock_path):
            with dread_update_lock(lock_path=lock_path):
                raise RuntimeError("boom")

    with dread_update_lock(lock_path=lock_path):
        assert lock_path.exists()


def test_lock_contention_fails_without_waiting(tmp_path: Path) -> None:
    from scanner.update_lock import UpdateLockError, dread_update_lock

    lock_path = tmp_path / ".update.lock"
    with dread_update_lock(lock_path=lock_path):
        with pytest.raises(UpdateLockError):
            with dread_update_lock(lock_path=lock_path, _allow_reentry=False):
                pass


def test_cve_update_uses_shared_lock(monkeypatch, tmp_path: Path) -> None:
    import scanner.cve_db_manager as manager
    import scanner.update_state as state

    monkeypatch.setattr(manager, "CVE_DB_PATH", str(tmp_path / "cve.sqlite"))
    monkeypatch.setattr(manager, "CVE_META_PATH", str(tmp_path / "meta.json"))
    monkeypatch.setattr(manager, "migrate_legacy_cve_database", lambda: False)
    monkeypatch.setattr(state, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(state, "STATE_PATH", tmp_path / "state" / "state.json")
    lock = mock.Mock(return_value=nullcontext())
    monkeypatch.setattr(manager, "dread_update_lock", lock)
    response = mock.Mock(status_code=200)
    response.json.return_value = {"vulnerabilities": [], "totalResults": 0}
    monkeypatch.setattr(manager, "_nvd_get", lambda *args, **kwargs: response)

    manager.update_cve_database(incremental=False)

    lock.assert_called_once_with()
