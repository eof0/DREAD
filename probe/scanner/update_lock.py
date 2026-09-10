"""Cross-process serialization for mutable DREAD data updates."""

from __future__ import annotations

import fcntl
import os
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, TextIO

from scanner.paths import DREAD_STATE_DIR


class UpdateLockError(RuntimeError):
    pass


_guard = threading.RLock()
_held: dict[Path, tuple[TextIO, int, int]] = {}


@contextmanager
def dread_update_lock(
    timeout: float = 0.0,
    *,
    lock_path: Path | None = None,
    _allow_reentry: bool = True,
) -> Iterator[None]:
    path = (lock_path or (DREAD_STATE_DIR / ".update.lock")).resolve()
    owner = threading.get_ident()

    with _guard:
        current = _held.get(path)
        if _allow_reentry and current and current[2] == owner:
            _held[path] = (current[0], current[1] + 1, owner)
            reentrant = True
        else:
            reentrant = False

    if reentrant:
        try:
            yield
        finally:
            with _guard:
                handle, depth, held_owner = _held[path]
                _held[path] = (handle, depth - 1, held_owner)
        return

    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a+", encoding="utf-8")
    deadline = time.monotonic() + max(timeout, 0.0)
    while True:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except BlockingIOError as exc:
            if time.monotonic() >= deadline:
                handle.close()
                raise UpdateLockError(f"DREAD update already in progress: {path}") from exc
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))

    handle.seek(0)
    handle.truncate()
    handle.write(f"pid={os.getpid()}\n")
    handle.flush()
    with _guard:
        _held[path] = (handle, 1, owner)

    try:
        yield
    finally:
        with _guard:
            current = _held.get(path)
            if current and current[0] is handle:
                _held.pop(path, None)
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()
