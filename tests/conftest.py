import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "probe"))


@pytest.fixture(autouse=True)
def isolated_update_lock(monkeypatch, tmp_path):
    from scanner import update_lock

    monkeypatch.setattr(update_lock, "DREAD_STATE_DIR", tmp_path / "state")
