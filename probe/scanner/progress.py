"""Terminal progress for long-running scan and suite tasks."""

from __future__ import annotations

import sys
import time
from contextlib import contextmanager
from typing import Callable, Iterator

try:
    from rich.console import Console
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TaskProgressColumn,
        TextColumn,
        TimeElapsedColumn,
    )

    _RICH = True
except ImportError:
    _RICH = False

Advance = Callable[[int, str | None], None]
_SPINNER = "|/-\\"


@contextmanager
def task_progress(
    *,
    description: str,
    total: int,
    console: Console | None = None,
) -> Iterator[Advance]:
    if total <= 0:
        yield lambda _n=1, _detail=None: None
        return

    if _RICH and console is not None:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=32),
            TaskProgressColumn(),
            TextColumn("•"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
            refresh_per_second=8,
        ) as progress:
            task_id = progress.add_task(description, total=total)

            def advance(steps: int = 1, detail: str | None = None) -> None:
                if detail:
                    progress.update(task_id, description=f"{description} — {detail}")
                if steps:
                    progress.advance(task_id, steps)

            yield advance
        return

    completed = 0
    detail = ""
    started = time.monotonic()
    spin = 0

    def advance(steps: int = 1, detail_text: str | None = None) -> None:
        nonlocal completed, detail, spin
        if detail_text is not None:
            detail = detail_text
        if steps:
            completed = min(total, completed + steps)
        spin += 1
        elapsed = int(time.monotonic() - started)
        pct = (100 * completed) // total
        filled = pct // 5
        bar = "#" * filled + "-" * (20 - filled)
        suffix = f" — {detail}" if detail else ""
        line = f"\r{_SPINNER[spin % len(_SPINNER)]} {description} [{bar}] {completed}/{total} ({elapsed}s){suffix}"
        sys.stderr.write(line[:160])
        sys.stderr.flush()

    try:
        advance(0)
        yield advance
    finally:
        sys.stderr.write("\n")
        sys.stderr.flush()


@contextmanager
def heartbeat(label: str, *, quiet: bool = False) -> Iterator[Callable[[], None]]:
    if quiet:
        yield lambda: None
        return

    started = time.monotonic()
    spin = 0

    if _RICH:
        console = Console(stderr=True)
        with Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
            refresh_per_second=10,
        ) as progress:
            task_id = progress.add_task(label, total=None)

            def tick() -> None:
                elapsed = int(time.monotonic() - started)
                progress.update(task_id, description=f"{label} ({elapsed}s)")

            yield tick
        return

    def tick() -> None:
        nonlocal spin
        spin += 1
        elapsed = int(time.monotonic() - started)
        line = f"\r{_SPINNER[spin % len(_SPINNER)]} {label} ({elapsed}s)"
        sys.stderr.write(line)
        sys.stderr.flush()

    try:
        tick()
        yield tick
    finally:
        sys.stderr.write("\n")
        sys.stderr.flush()
