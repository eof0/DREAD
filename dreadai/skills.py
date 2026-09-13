"""Discover and load security skills (Trail of Bits + secskills) for DreadAI.

These are Claude Code plugin skills — markdown methodology bundles for security work
(differential review, static analysis, attacking JWTs, exploiting SSRF, incident response,
...). DreadAI can't run the Claude Code harness, but a skill's instructions are just
on-disk markdown, so we expose them as read-on-demand expertise: the agent lists the
catalog, loads the relevant skill, and follows its methodology with DreadAI's own tools
(Probe, Scope, Spear, Intel, Cannon). This works for any backing model — Claude, a local
Qwen, or any cloud model — because it is plain tool output, not harness magic.

Roots default to the local plugin cache; override with DREADAI_SKILL_ROOTS (os.pathsep-
separated). Everything degrades gracefully to an empty catalog when nothing is installed.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Optional

_DEFAULT_ROOTS = (
    "~/.claude/plugins/cache/trailofbits",
    "~/.claude/plugins/cache/secskills-marketplace",
)


def skill_roots() -> List[Path]:
    """Directories to scan for plugin skills (DREADAI_SKILL_ROOTS overrides the default)."""
    env = os.environ.get("DREADAI_SKILL_ROOTS")
    raw = env.split(os.pathsep) if env else list(_DEFAULT_ROOTS)
    return [Path(p).expanduser() for p in raw if p.strip()]


def _version_key(name: str) -> tuple:
    """Sort key so '4.6.0' beats '1.4.3' (non-numeric segments sort as 0)."""
    return tuple(int(p) if p.isdigit() else 0 for p in name.split("."))


def _latest_version_dir(plugin_dir: Path) -> Optional[Path]:
    versions = [d for d in plugin_dir.iterdir() if d.is_dir()]
    if not versions:
        return None
    return max(versions, key=lambda d: _version_key(d.name))


def _parse_frontmatter(text: str) -> Dict[str, str]:
    """Pull simple `key: value` pairs from a leading `---`-delimited YAML block."""
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end == -1:
        return {}
    meta: Dict[str, str] = {}
    for line in text[3:end].splitlines():
        if ":" not in line or line.lstrip().startswith("#"):
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip().strip('"').strip("'").strip()
        if key and value and key not in meta:
            meta[key] = value
    return meta


def discover_skills(roots: Optional[List[Path]] = None) -> Dict[str, Dict[str, str]]:
    """Catalog every installed skill as ``{"<plugin>:<name>": {name, plugin, description, path}}``.

    For a plugin with multiple cached versions, only the latest version's skills are kept.
    """
    catalog: Dict[str, Dict[str, str]] = {}
    for root in (roots if roots is not None else skill_roots()):
        if not root.is_dir():
            continue
        for plugin_dir in sorted(p for p in root.iterdir() if p.is_dir()):
            version_dir = _latest_version_dir(plugin_dir)
            if version_dir is None:
                continue
            skills_dir = version_dir / "skills"
            if not skills_dir.is_dir():
                continue
            for skill_md in sorted(skills_dir.glob("*/SKILL.md")):
                try:
                    meta = _parse_frontmatter(skill_md.read_text(encoding="utf-8", errors="replace"))
                except OSError:
                    continue
                name = meta.get("name") or skill_md.parent.name
                plugin = plugin_dir.name
                catalog[f"{plugin}:{name}"] = {
                    "name": name,
                    "plugin": plugin,
                    "description": meta.get("description", ""),
                    "path": str(skill_md),
                }
    return catalog


def _resolve(skill: str, catalog: Dict[str, Dict[str, str]]) -> Optional[str]:
    """Resolve a full 'plugin:name' id or a bare 'name' to a catalog key."""
    if skill in catalog:
        return skill
    # Bare name: first plugin (sorted) that provides it.
    matches = [k for k in sorted(catalog) if k.split(":", 1)[1] == skill]
    return matches[0] if matches else None


def load_skill(skill: str, roots: Optional[List[Path]] = None,
               max_chars: int = 20000) -> Dict:
    """Return a skill's SKILL.md instructions (truncated if large) plus its supporting files.

    ``skill`` may be a full ``"plugin:name"`` id or a bare skill name. On a miss, returns
    an ``{"error", "did_you_mean"}`` dict rather than raising, so it is safe as a tool result.
    """
    catalog = discover_skills(roots)
    key = _resolve(skill, catalog)
    if key is None:
        wanted = skill.split(":", 1)[-1].lower()
        near = [k for k in sorted(catalog) if wanted[:5] and wanted[:5] in k.lower()][:8]
        return {
            "error": f"No security skill matching {skill!r}. Use list_security_skills first.",
            "did_you_mean": near,
        }
    entry = catalog[key]
    path = Path(entry["path"])
    text = path.read_text(encoding="utf-8", errors="replace")
    truncated = len(text) > max_chars
    if truncated:
        text = text[:max_chars] + (
            f"\n\n[... truncated at {max_chars} chars; read the full file at {path} "
            "or its supporting files for the rest ...]")
    supporting = sorted(
        f.name for f in path.parent.iterdir()
        if f.is_file() and f.name != "SKILL.md")
    return {
        "id": key,
        "plugin": entry["plugin"],
        "description": entry["description"],
        "path": str(path),
        "content": text,
        "truncated": truncated,
        "supporting_files": supporting,
    }
