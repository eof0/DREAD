"""Safe subprocess execution and PATH detection for Cannon tools."""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class ToolResult:
    tool: str
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool


def which(binary: str) -> str | None:
    return shutil.which(binary)


def detect(binaries: Iterable[str]) -> dict[str, str | None]:
    return {b: which(b) for b in binaries}


def run(tool: str, argv: list[str], timeout: float = 120.0) -> ToolResult:
    start = time.monotonic()
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return ToolResult(
            tool,
            argv,
            -1,
            exc.stdout or "",
            exc.stderr or "",
            round(time.monotonic() - start, 2),
            True,
        )
    except OSError as exc:
        # Binary vanished between detection and launch (TOCTOU), or a PATH entry
        # is not executable. Surface it as a failed result so a kaboom plan keeps
        # running the remaining tools instead of aborting on an uncaught error.
        return ToolResult(
            tool,
            argv,
            -1,
            "",
            f"failed to launch {argv[0]}: {exc}",
            round(time.monotonic() - start, 2),
            False,
        )
    return ToolResult(
        tool,
        argv,
        proc.returncode,
        proc.stdout,
        proc.stderr,
        round(time.monotonic() - start, 2),
        False,
    )
