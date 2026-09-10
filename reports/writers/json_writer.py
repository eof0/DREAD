from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_suite_json(report: dict[str, Any], output_dir: Path, base_name: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{base_name}.json"
    path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return path
