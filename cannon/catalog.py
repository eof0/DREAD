"""Catalog of external tools Cannon can drive against an authorized target.

The catalog is data, not code: it loads from tools.json so tools can be added or
tuned without editing Python. Argv templates carry conservative defaults on
purpose; a "heavy" template holds the higher-intensity variant used by kaboom's
load and staged modes. A stress tool that defaults to maximum load is a foot-gun.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

DEFAULT_CONFIG = Path(__file__).with_name("tools.json")


@dataclass(frozen=True)
class Tool:
    name: str
    binary: str
    category: str  # "load" | "recon"
    description: str
    argv: tuple[str, ...]
    heavy: tuple[str, ...] | None = None
    # Package name per manager when it differs from the binary (e.g. ab -> apache on pacman).
    packages: dict[str, str] | None = None


def load_catalog(path: str | Path | None = None) -> tuple[Tool, ...]:
    entries = json.loads(Path(path or DEFAULT_CONFIG).read_text())
    if not isinstance(entries, list):
        raise ValueError("catalog must be a JSON array of tool objects")
    tools = []
    for e in entries:
        if not isinstance(e, dict):
            raise ValueError("each catalog entry must be a JSON object")
        tools.append(
            Tool(
                name=e["name"],
                binary=e["binary"],
                category=e["category"],
                description=e["description"],
                argv=tuple(e["argv"]),
                heavy=tuple(e["heavy"]) if e.get("heavy") else None,
                packages=e.get("packages"),
            )
        )
    return tuple(tools)


_CATALOG_CACHE: tuple[Tool, ...] | None = None


def _default_catalog() -> tuple[Tool, ...]:
    # Parse the bundled catalog lazily and once, so merely importing this module
    # (as cannon.py and its subcommands do) never depends on tools.json being
    # valid — only an operation that actually needs the default does.
    global _CATALOG_CACHE
    if _CATALOG_CACHE is None:
        _CATALOG_CACHE = load_catalog()
    return _CATALOG_CACHE


def __getattr__(name: str) -> tuple[Tool, ...]:
    # PEP 562: expose CATALOG as a lazy module attribute instead of an eager global.
    if name == "CATALOG":
        return _default_catalog()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def by_name(name: str, catalog: tuple[Tool, ...] | None = None) -> Tool | None:
    for tool in catalog if catalog is not None else _default_catalog():
        if tool.name == name:
            return tool
    return None


def build_argv(tool: Tool, target: str, heavy: bool = False) -> list[str]:
    template = tool.heavy if heavy and tool.heavy else tool.argv
    return [tool.binary] + [arg.replace("{target}", target) for arg in template]
