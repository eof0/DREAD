from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_suite_json(report: dict[str, Any], output_dir: Path, base_name: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{base_name}.json"
    path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return path


# Keys that only make sense internally and never belong in a customer deliverable.
_INTERNAL_KEYS = ("raw_embed", "suite")


def write_technical_json(report: dict[str, Any], output_dir: Path, base_name: str) -> Path:
    """Customer technical JSON: the normalized report without internal-only keys."""
    slim = {k: v for k, v in report.items() if k not in _INTERNAL_KEYS}
    return write_suite_json(slim, output_dir, base_name)
