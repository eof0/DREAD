#!/usr/bin/env python3
"""
Reports — unified reporting across the DREAD suite.

Aggregates Probe (and optional Scope) outputs into one JSON + PDF +
interactive dashboard. Per-product reports remain; this is the grand-scale view.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Ensure local imports resolve when run as script (reports modules + repo root for products)
_ROOT = Path(__file__).resolve().parent
_REPO_ROOT = _ROOT.parent
for _p in (_ROOT, _REPO_ROOT):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from products import SUITE_VERSION  # noqa: E402
from suite_build import run_build  # noqa: E402
from suite_schema import REPORTS_SCHEMA_VERSION  # noqa: E402


def cmd_info(_: argparse.Namespace) -> int:
    print(
        """Reports — unified suite reporting (MVP)

Consumes:
  • One or more Probe *.json scan reports
  • Optional Scope discovery JSON (--scope)

Produces (per build):
  • Master JSON — full suite object (includes raw_embed for drill-down)
  • PDF — executive summary + severity rollups + findings table
  • Dashboard — React SPA (Vite) with charts + searchable findings table

Example:
  python reports.py build -o ./suite_out \\
      --probe ../probe/scan_results/a.json \\
      --scope ../scope_out.json \\
      --formats json,pdf,dashboard

Dashboard requires Node once:  cd reports/dashboard && npm ci && npm run build
Or pass --try-npm to let `build` attempt npm ci && npm run build automatically.
"""
    )
    return 0


def cmd_version(_: argparse.Namespace) -> int:
    print(
        f"Reports (DREAD suite {SUITE_VERSION}, schema {REPORTS_SCHEMA_VERSION})"
    )
    return 0


def cmd_build(args: argparse.Namespace) -> int:
    output_dir = Path(args.output).resolve()
    probe = [Path(p).resolve() for p in (args.probe or [])]
    scope = Path(args.scope).resolve() if args.scope else None

    inc_raw = [x.strip().lower() for x in args.include.split(",") if x.strip()]
    inc_set = set(inc_raw if inc_raw else ["probe", "scope"])

    fmt_raw = [x.strip().lower() for x in args.formats.split(",") if x.strip()]
    formats = frozenset(fmt_raw if fmt_raw else ["json", "pdf", "dashboard"])

    invalid = formats - {"json", "pdf", "html", "dashboard"}
    if invalid:
        print(f"[!] Unknown format(s): {', '.join(invalid)}", file=sys.stderr)
        return 1

    if "probe" in inc_set and not probe:
        print("[*] No --probe files; excluding probe from this build.", file=sys.stderr)
        inc_set.discard("probe")
    if "scope" in inc_set and not scope:
        print("[*] No --scope; excluding scope from this build.", file=sys.stderr)
        inc_set.discard("scope")

    if not inc_set:
        print("[!] Nothing left to include after resolving inputs.", file=sys.stderr)
        return 1

    include = frozenset(inc_set)

    name = args.name.strip() or "dread_suite_report"
    title = args.title.strip()

    dashboard_src = (_ROOT / "dashboard").resolve()

    msgs, errs = run_build(
        output_dir=output_dir,
        base_name=name,
        title=title,
        probe_paths=probe,
        scope_path=scope,
        include=include,
        formats=formats,
        dashboard_src=dashboard_src,
        try_npm_build=args.try_npm,
    )

    for m in msgs:
        print(m)
    for e in errs:
        print(f"[!] {e}", file=sys.stderr)

    return 1 if errs else 0


def main() -> int:
    p = argparse.ArgumentParser(
        prog="reports",
        description="Reports — suite-level JSON, PDF, and HTML dashboard.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    i = sub.add_parser("info", help="Overview and examples")
    i.set_defaults(func=cmd_info)

    v = sub.add_parser("version", help="Version")
    v.set_defaults(func=cmd_version)

    b = sub.add_parser("build", help="Aggregate sources and write artifacts")
    b.add_argument(
        "-o",
        "--output",
        required=True,
        help="Output directory for suite_report files + dashboard/",
    )
    b.add_argument(
        "--probe",
        action="append",
        help="Path to Probe JSON (repeatable)",
    )
    b.add_argument("--scope", help="Path to Scope discovery JSON")
    b.add_argument(
        "--include",
        default="probe,scope",
        help="Comma list: probe, scope (default both if inputs present)",
    )
    b.add_argument(
        "--formats",
        default="json,pdf,dashboard",
        help="Comma list: json, pdf, html, dashboard",
    )
    b.add_argument(
        "--name",
        default="dread_suite_report",
        help="Base filename without extension",
    )
    b.add_argument(
        "--title",
        default="",
        help='Report title (default: "Recon/Vuln Analysis - Report Findings - <date>")',
    )
    b.add_argument(
        "--try-npm",
        action="store_true",
        help="If dashboard/dist is missing, run npm ci && npm run build in dashboard/",
    )
    b.set_defaults(func=cmd_build)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
