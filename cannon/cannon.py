#!/usr/bin/env python3
"""Cannon - authorized stress testing and external tool orchestration."""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys

import catalog
import packages
import runner

VERSION = "0.1.0"

AUTHORIZATION_NOTICE = (
    "Cannon drives active, potentially disruptive tools against a target. "
    "Run it only against systems you own or are explicitly authorized to test. "
    "Pass --authorized to confirm you have permission."
)


def _load_catalog(config):
    try:
        return catalog.load_catalog(config)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Invalid tools catalog: {exc}", file=sys.stderr)
        return None


def _reject_target(target: str) -> bool:
    # A hostname or URL never begins with '-'. Such a value would be parsed by the
    # underlying tool as an option (e.g. nmap -oN, curl --output), so refuse it
    # rather than let it inject flags into the command line.
    if target.startswith("-"):
        print(
            f"Refusing target {target!r}: targets cannot begin with '-'.",
            file=sys.stderr,
        )
        return True
    return False


def _exit_code(result) -> int:
    # A run is a failure if it timed out or the tool itself exited non-zero, so a
    # calling script or the dread orchestrator can tell a failed run from a
    # clean one. Details (the real returncode) stay in the text/JSON output.
    return 1 if result.timed_out or result.returncode != 0 else 0


def cmd_info(_: argparse.Namespace) -> int:
    print(
        """Cannon

Stress testing and orchestration of external tools already installed on this
system, driven against an authorized target. Detects available tooling, then
runs a chosen tool with conservative defaults and captured output.

Active runs require --authorized. The "kaboom" trigger fires several tools at
once in one of three modes: all (every available tool once), load (escalate the
load tools), or staged (recon first, then escalated load).

Use only against systems you own or are explicitly authorized to test.
"""
    )
    return 0


def cmd_version(_: argparse.Namespace) -> int:
    print(f"Cannon {VERSION}")
    return 0


def _install_hint(guidance: dict) -> str:
    if guidance.get("command"):
        return f"install: {guidance['command']}"
    if guidance.get("manager"):
        return f"not in {guidance['manager']}; install it manually and re-check"
    return "no supported package manager found; install it manually and re-check"


def _tool_json(tool: catalog.Tool, path: str | None) -> dict:
    entry = {
        "name": tool.name,
        "binary": tool.binary,
        "category": tool.category,
        "description": tool.description,
        "available": path is not None,
        "path": path,
    }
    if path is None:
        entry["install"] = packages.install_guidance(tool.binary, tool.packages)
    return entry


def cmd_tools(args: argparse.Namespace) -> int:
    cat = _load_catalog(args.config)
    if cat is None:
        return 2
    found = runner.detect(tool.binary for tool in cat)
    if args.json:
        print(json.dumps([_tool_json(t, found[t.binary]) for t in cat], indent=2))
        return 0
    for tool in cat:
        available = found[tool.binary] is not None
        mark = "available" if available else "missing"
        print(f"  [{mark:9}] {tool.name:6} {tool.category:6} {tool.description}")
        if not available:
            print(f"             {_install_hint(packages.install_guidance(tool.binary, tool.packages))}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    if not args.authorized:
        print(AUTHORIZATION_NOTICE, file=sys.stderr)
        return 2
    if _reject_target(args.target):
        return 2
    cat = _load_catalog(args.config)
    if cat is None:
        return 2
    tool = catalog.by_name(args.tool, cat)
    if tool is None:
        print(f"Unknown tool: {args.tool}. See 'cannon tools'.", file=sys.stderr)
        return 2
    if runner.which(tool.binary) is None:
        print(f"{tool.binary} is not installed on this system.", file=sys.stderr)
        print(_install_hint(packages.install_guidance(tool.binary, tool.packages)), file=sys.stderr)
        return 3
    result = runner.run(tool.name, catalog.build_argv(tool, args.target), timeout=args.timeout)
    if args.json:
        print(json.dumps(dataclasses.asdict(result), indent=2))
        return _exit_code(result)
    suffix = " (timed out)" if result.timed_out else ""
    print(f"{tool.name} exited {result.returncode} in {result.duration}s{suffix}")
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    return _exit_code(result)


KABOOM_MODES = ("all", "load", "staged")


def kaboom_plan(mode, catalog_tools, found):
    order = {"all": ("recon", "load"), "load": ("load",), "staged": ("recon", "load")}[mode]
    plan = []
    for category in order:
        for tool in catalog_tools:
            if tool.category == category and found.get(tool.binary):
                heavy = mode in ("load", "staged") and tool.category == "load"
                plan.append((tool, heavy))
    return plan


def _choose_mode() -> str | None:
    # Menu and prompt go to stderr so --json output on stdout stays parseable.
    print("Cannon kaboom modes:", file=sys.stderr)
    print("  1) all     run every available tool once", file=sys.stderr)
    print("  2) load    escalate the load tools for a stress burst", file=sys.stderr)
    print("  3) staged  recon first, then escalated load", file=sys.stderr)
    print("Select mode [1-3]: ", end="", file=sys.stderr, flush=True)
    try:
        choice = input().strip()
    except EOFError:
        return None
    return {"1": "all", "2": "load", "3": "staged"}.get(choice)


def cmd_kaboom(args: argparse.Namespace) -> int:
    if not args.authorized:
        print(AUTHORIZATION_NOTICE, file=sys.stderr)
        return 2
    if _reject_target(args.target):
        return 2
    cat = _load_catalog(args.config)
    if cat is None:
        return 2
    found = runner.detect(tool.binary for tool in cat)
    mode = args.mode or _choose_mode()
    if mode not in KABOOM_MODES:
        print("Cancelled.", file=sys.stderr)
        return 2
    plan = kaboom_plan(mode, cat, found)
    if not plan:
        print("No cataloged tools are installed. See 'cannon tools'.", file=sys.stderr)
        return 3
    results = []
    for tool, heavy in plan:
        result = runner.run(
            tool.name, catalog.build_argv(tool, args.target, heavy), timeout=args.timeout
        )
        results.append(result)
        if not args.json:
            suffix = " (timed out)" if result.timed_out else ""
            tag = "heavy" if heavy else "default"
            print(f"{tool.name} [{tag}] exited {result.returncode} in {result.duration}s{suffix}")
    if args.json:
        print(json.dumps([dataclasses.asdict(r) for r in results], indent=2))
    return 1 if any(_exit_code(r) for r in results) else 0


def main() -> int:
    p = argparse.ArgumentParser(
        prog="cannon",
        description="Cannon - authorized stress testing and tool orchestration.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("info", help="Product overview").set_defaults(func=cmd_info)
    sub.add_parser("version", help="Version").set_defaults(func=cmd_version)

    t = sub.add_parser("tools", help="List cataloged tools and local availability")
    t.add_argument("--config", help="Path to a tools catalog JSON (defaults to bundled)")
    t.add_argument("--json", action="store_true", help="Emit JSON")
    t.set_defaults(func=cmd_tools)

    r = sub.add_parser("run", help="Run one cataloged tool against a target")
    r.add_argument("tool", help="Tool name from 'cannon tools'")
    r.add_argument("target", help="Target host or URL you are authorized to test")
    r.add_argument("--authorized", action="store_true", help="Confirm you have permission")
    r.add_argument("--config", help="Path to a tools catalog JSON (defaults to bundled)")
    r.add_argument("--timeout", type=float, default=120.0, help="Seconds before the run is killed")
    r.add_argument("--json", action="store_true", help="Emit JSON")
    r.set_defaults(func=cmd_run)

    k = sub.add_parser("kaboom", help="Fire multiple tools at a target: all, load, or staged")
    k.add_argument("target", help="Target host or URL you are authorized to test")
    k.add_argument("--authorized", action="store_true", help="Confirm you have permission")
    k.add_argument("--mode", choices=KABOOM_MODES, help="Skip the menu and pick a mode directly")
    k.add_argument("--config", help="Path to a tools catalog JSON (defaults to bundled)")
    k.add_argument("--timeout", type=float, default=120.0, help="Seconds before each run is killed")
    k.add_argument("--json", action="store_true", help="Emit JSON")
    k.set_defaults(func=cmd_kaboom)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
