"""Load a .env file into the environment. Kept dependency-free on purpose."""

from __future__ import annotations

import os
from pathlib import Path


def load_env_file(path: str | Path) -> None:
    """Set each KEY=VALUE line from a .env file into os.environ; existing values win."""
    env_path = Path(path)
    if not env_path.is_file():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#") or "=" not in entry:
            continue
        key, _, value = entry.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
