"""Suite run manifest and history for dread --suite-out / Reports."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


MANIFEST_SCHEMA = "dread.suite_manifest/v1"
HISTORY_SCHEMA = "dread.suite_history/v1"


def new_run_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{ts}_{uuid.uuid4().hex[:8]}"


def slug_target(label: str, max_len: int = 48) -> str:
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in label.strip())
    safe = "_".join(x for x in safe.split("_") if x)
    return (safe[:max_len] or "target").strip("._")


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, default=str), encoding="utf-8")


def write_manifest(path: Path, body: dict[str, Any]) -> None:
    payload = {"schema": MANIFEST_SCHEMA, **body}
    write_json(path, payload)


def update_manifest(path: Path, **updates: Any) -> None:
    if path.is_file():
        data = json.loads(path.read_text(encoding="utf-8"))
    else:
        data = {"schema": MANIFEST_SCHEMA}
    data.update(updates)
    write_json(path, data)


def history_file(suite_base: Path) -> Path:
    return suite_base / "history.json"


def load_history(suite_base: Path) -> dict[str, Any]:
    p = history_file(suite_base)
    if not p.is_file():
        return {"schema": HISTORY_SCHEMA, "runs": []}
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "runs" not in data:
        return {"schema": HISTORY_SCHEMA, "runs": []}
    return data


def weighted_severity_index(fbs: dict[str, Any] | None) -> float:
    if not fbs:
        return 0.0
    w = {"critical": 25.0, "high": 15.0, "medium": 8.0, "low": 3.0, "info": 1.0}
    total = 0.0
    for k, v in fbs.items():
        if isinstance(v, int) and v >= 0:
            total += w.get(str(k).lower(), 1.0) * v
    return round(total, 2)


def append_history_run(
    suite_base: Path,
    *,
    run_id: str,
    generated_at: str,
    primary_target: str,
    report: dict[str, Any],
    run_dir_rel: str,
) -> None:
    """Append one entry; suite_base is the parent directory shared across runs (from --suite-out)."""
    roll = report.get("rollups") or {}
    fbs = roll.get("findings_by_severity") or {}
    entry = {
        "run_id": run_id,
        "generated_at": generated_at,
        "primary_target": primary_target,
        "total_findings": roll.get("total_findings", 0),
        "findings_by_severity": fbs,
        "weighted_severity_index": weighted_severity_index(fbs),
        "run_dir": run_dir_rel,
        "suite_report_json": f"{run_dir_rel.rstrip('/')}/suite_report/dread_suite_report.json",
    }
    data = load_history(suite_base)
    runs: list[Any] = list(data.get("runs") or [])
    runs.append(entry)
    # cap size for UI
    runs = runs[-200:]
    data["runs"] = runs
    data["schema"] = HISTORY_SCHEMA
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    write_json(history_file(suite_base), data)
