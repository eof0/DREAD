#!/usr/bin/env python3
"""Spear — internal assessment & automated penetration agent. Scaffold only."""

from __future__ import annotations

import argparse
import sys


def cmd_info(_: argparse.Namespace) -> int:
    print(
        """Spear (scaffold)

Goal: authorized internal network / host vulnerability assessment and
automated penetration workflows that mimic an actor already inside the perimeter.

Findings feed Graph, Reports, and DreadAI (verification / gap fill).
Use only on systems you own or have explicit permission to test.
Not implemented yet.
"""
    )
    return 0


def cmd_version(_: argparse.Namespace) -> int:
    print("Spear 0.0.0 (scaffold)")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(
        prog="spear",
        description="Spear — internal assessment agent (early scaffold).",
    )
    sub = p.add_subparsers(dest="command", required=True)
    i = sub.add_parser("info", help="Product overview")
    i.set_defaults(func=cmd_info)
    v = sub.add_parser("version", help="Scaffold version")
    v.set_defaults(func=cmd_version)
    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
