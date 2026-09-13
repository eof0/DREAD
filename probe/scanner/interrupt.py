"""Press-a-key-to-stop control for a running scan (best-effort, POSIX TTY only).

Spawns a daemon thread that watches the terminal for a quit key ('q'). When pressed it
invokes the callback — which cancels the scan and lets the engine write the partial
report it has so far. It is a no-op when stdin is not an interactive TTY (piped input,
CI, a non-POSIX platform), so it never blocks or breaks a headless / subprocess run.
"""

from __future__ import annotations

import sys
import threading
from typing import Callable

_QUIT_KEYS = {"q", "Q"}


class KeypressCanceller:
    """Context manager: while active, pressing 'q' calls ``on_quit`` once."""

    def __init__(self, on_quit: Callable[[], None]):
        self._on_quit = on_quit
        self._stop = threading.Event()
        self._thread = None
        self._fd = None
        self._old = None
        self.enabled = self._can_listen()

    @staticmethod
    def _can_listen() -> bool:
        try:
            return bool(sys.stdin) and sys.stdin.isatty()
        except Exception:  # noqa: BLE001
            return False

    def __enter__(self) -> "KeypressCanceller":
        if self.enabled:
            import atexit
            atexit.register(self._restore)   # restore the TTY even if the scan raises
            self._thread = threading.Thread(target=self._run, name="dread-keywatch",
                                            daemon=True)
            self._thread.start()
        return self

    def __exit__(self, *exc) -> bool:
        self._stop.set()
        self._restore()
        return False

    def _restore(self) -> None:
        """Put the terminal back to cooked mode (idempotent, safe to call twice)."""
        if self._fd is None or self._old is None:
            return
        try:
            import termios
            termios.tcsetattr(self._fd, termios.TCSADRAIN, self._old)
        except Exception:  # noqa: BLE001
            pass
        self._old = None

    def _run(self) -> None:
        try:
            import select
            import termios
            import tty
        except Exception:  # noqa: BLE001 - non-POSIX: silently disable
            return
        fd = sys.stdin.fileno()
        try:
            self._fd, self._old = fd, termios.tcgetattr(fd)
        except Exception:  # noqa: BLE001
            return
        try:
            tty.setcbreak(fd)
            while not self._stop.is_set():
                ready, _, _ = select.select([sys.stdin], [], [], 0.25)
                if not ready:
                    continue
                ch = sys.stdin.read(1)
                if ch in _QUIT_KEYS:
                    try:
                        self._on_quit()
                    except Exception:  # noqa: BLE001
                        pass
                    break
        except Exception:  # noqa: BLE001 - never let the watcher crash the scan
            pass
        finally:
            self._restore()
