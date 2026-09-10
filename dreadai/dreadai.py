#!/usr/bin/env python3
"""
DreadAI — orchestration across the DREAD suite.

Monitors suite health, runs checks other products omit, integrates third-party
tools, and verifies accuracy of consolidated reporting (with Reports).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

# Repo root (parent of dreadai/)
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from products import SUITE_VERSION, format_suite_overview  # noqa: E402


def cmd_info(_: argparse.Namespace) -> int:
    print(
        """DreadAI — verification today; broader orchestration on the roadmap

Implemented:
  • verify   Structural checks on Probe scan JSON or Reports unified suite JSON
  • suite    Same overview as `dread products`
  • version  Suite version string

Roadmap (suite-wide):
  • Monitor orchestration across Probe, Scope, Watch, Graph,
    Intel, Reports, Spear, and Cannon
  • Policy hooks and gap-oriented probes; third-party scanner integration
  • Deeper cross-checks feeding Reports accuracy

Subcommands:
  info       This text
  version    Suite version
  suite      Print full product suite overview (same as `dread products`)
  verify     Sanity-check Probe or Reports (unified suite) JSON
"""
    )
    return 0


def cmd_version(_: argparse.Namespace) -> int:
    print(f"DreadAI (DREAD {SUITE_VERSION}) — verify + suite; see dreadai info")
    return 0


def cmd_suite(_: argparse.Namespace) -> int:
    print(format_suite_overview())
    return 0


def _severity_bucket(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    return value.lower() in (
        "critical",
        "high",
        "medium",
        "low",
        "info",
        "none",
    )


def _verify_suite_json(data: dict[str, Any], path: Path) -> int:
    issues: list[str] = []
    for key in ("run_id", "generated_at", "rollups", "findings", "sources"):
        if key not in data:
            issues.append(f"missing required key: {key!r}")
    roll = data.get("rollups") or {}
    if not isinstance(roll, dict):
        issues.append("'rollups' must be an object")
    else:
        if "total_findings" not in roll:
            issues.append("missing rollups.total_findings")
        fbs = roll.get("findings_by_severity") or {}
        if fbs and not isinstance(fbs, dict):
            issues.append("rollups.findings_by_severity must be an object")
        findings = data.get("findings")
        if isinstance(findings, list) and isinstance(fbs, dict):
            summed = sum(v for v in fbs.values() if isinstance(v, int))
            if summed != len(findings):
                issues.append(
                    f"findings count ({len(findings)}) != "
                    f"sum(rollups.findings_by_severity) ({summed})"
                )

    findings = data.get("findings")
    if findings is not None and not isinstance(findings, list):
        issues.append("'findings' must be an array")

    if issues:
        print("[!] Suite report verification failed:", file=sys.stderr)
        for line in issues:
            print(f"    - {line}", file=sys.stderr)
        return 1

    n = len(findings) if isinstance(findings, list) else 0
    print(f"[+] Reports unified suite JSON OK: {path.name} ({n} normalized finding(s))")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Validate Probe scan JSON or Reports unified suite JSON."""
    raw_path = Path(args.report_json)
    path = raw_path if raw_path.is_absolute() else _REPO_ROOT / raw_path
    if not path.is_file():
        print(f"[!] Not a file: {path}", file=sys.stderr)
        return 1

    try:
        raw_text = path.read_text(encoding="utf-8")
        data = json.loads(raw_text)
    except json.JSONDecodeError as e:
        print(f"[!] Invalid JSON: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"[!] Cannot read file: {e}", file=sys.stderr)
        return 1

    if not isinstance(data, dict):
        print("[!] Report root must be a JSON object.", file=sys.stderr)
        return 1

    if data.get("report_type") == "unified_suite" or data.get(
        "reports_schema_version"
    ):
        return _verify_suite_json(data, path)

    issues: list[str] = []

    required_keys = ("scan_id", "target", "findings", "statistics")
    for key in required_keys:
        if key not in data:
            issues.append(f"missing required key: {key!r}")

    findings = data.get("findings")
    if findings is not None and not isinstance(findings, list):
        issues.append("'findings' must be an array")

    stats = data.get("statistics")
    if stats is not None:
        if not isinstance(stats, dict):
            issues.append("'statistics' must be an object")
        else:
            fbs = stats.get("findings_by_severity")
            if fbs is not None:
                if not isinstance(fbs, dict):
                    issues.append("'statistics.findings_by_severity' must be an object")
                else:
                    for k, v in fbs.items():
                        if not _severity_bucket(k):
                            issues.append(
                                f"unexpected severity bucket in statistics: {k!r}"
                            )
                        if not isinstance(v, int) or v < 0:
                            issues.append(
                                f"invalid count for severity {k!r}: expected non-negative int"
                            )

    if isinstance(findings, list) and isinstance(stats, dict):
        fbs = stats.get("findings_by_severity")
        if isinstance(fbs, dict):
            summed = sum(v for v in fbs.values() if isinstance(v, int))
            n_findings = len(findings)
            if summed != n_findings:
                issues.append(
                    f"findings count ({n_findings}) != sum(findings_by_severity) ({summed})"
                )

    if findings:
        for i, item in enumerate(findings[:50]):
            if not isinstance(item, dict):
                issues.append(f"findings[{i}] must be an object")
                continue
            if "severity" in item and not _severity_bucket(item["severity"]):
                issues.append(f"findings[{i}].severity unknown value: {item['severity']!r}")

    if issues:
        print("[!] Verification failed:", file=sys.stderr)
        for line in issues:
            print(f"    - {line}", file=sys.stderr)
        return 1

    n = len(findings) if isinstance(findings, list) else 0
    print(f"[+] Probe report OK: {path.name} ({n} finding(s))")
    return 0


def cmd_chat(args: argparse.Namespace) -> int:
    """Drive the suite through the DreadAI agent from a single prompt."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("[!] ANTHROPIC_API_KEY is not set.", file=sys.stderr)
        return 2
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from agent import ask

    print(ask(args.prompt))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="dreadai",
        description=(
            "DreadAI — suite orchestration (roadmap) and report verification "
            f"(Probe / unified suite JSON; suite {SUITE_VERSION})."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_info = sub.add_parser("info", help="Describe DreadAI and subcommands")
    p_info.set_defaults(func=cmd_info)

    p_ver = sub.add_parser("version", help="Show scaffold version")
    p_ver.set_defaults(func=cmd_version)

    p_suite = sub.add_parser(
        "suite",
        help="List all DREAD products (shared registry)",
    )
    p_suite.set_defaults(func=cmd_suite)

    p_verify = sub.add_parser(
        "verify",
        help="Validate Probe scan JSON or Reports unified suite JSON",
    )
    p_verify.add_argument(
        "report_json",
        help="Path to report .json (Probe scan or dread_suite_report)",
    )
    p_verify.set_defaults(func=cmd_verify)

    p_chat = sub.add_parser("chat", help="Ask the DreadAI agent to scan, correlate, and report")
    p_chat.add_argument("prompt", help="What you want DreadAI to do")
    p_chat.set_defaults(func=cmd_chat)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
