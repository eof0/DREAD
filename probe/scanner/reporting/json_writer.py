import json
import os
from typing import Dict
from pathlib import Path


def write_json(report: Dict, output_dir: str, output_name: str) -> str:
    if not output_name:
        raise ValueError("output_name is required for JSON output")

    output_root = Path(output_dir).resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    output_path = output_root / f"{output_name}.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    assert output_path.exists(), f"Failed to write {output_path}"

    return str(output_path)
