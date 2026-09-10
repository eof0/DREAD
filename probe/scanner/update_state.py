from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


STATE_DIR = Path.home() / ".dread"
STATE_PATH = STATE_DIR / "state.json"


def _iso_ms_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def load_state() -> Dict[str, Any]:
    if not STATE_PATH.exists():
        return {}
    with STATE_PATH.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        return {}
    return data


def save_state(state: Dict[str, Any]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp_path = STATE_PATH.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)
    tmp_path.replace(STATE_PATH)


def get_state_timestamp(section: str, key: str) -> str | None:
    state = load_state()
    section_obj = state.get(section, {})
    if isinstance(section_obj, dict):
        value = section_obj.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def set_state_timestamp(section: str, key: str, value: str | None = None) -> None:
    state = load_state()
    section_obj = state.get(section)
    if not isinstance(section_obj, dict):
        section_obj = {}
    section_obj[key] = value or _iso_ms_now()
    state[section] = section_obj
    save_state(state)


def merge_section(section: str, updates: Dict[str, Any]) -> None:
    """Merge keys into a state section without dropping existing keys."""
    state = load_state()
    section_obj = state.get(section)
    if not isinstance(section_obj, dict):
        section_obj = {}
    for k, v in updates.items():
        if v is None:
            section_obj.pop(k, None)
        else:
            section_obj[k] = v
    state[section] = section_obj
    save_state(state)


def get_section_value(section: str, key: str) -> Any | None:
    state = load_state()
    section_obj = state.get(section)
    if isinstance(section_obj, dict):
        return section_obj.get(key)
    return None
