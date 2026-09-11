#!/usr/bin/env python3
"""Intel — vulnerability intelligence and CVE triage over the local store.

Probe builds and enriches the CVE database (NVD + CISA KEV + FIRST EPSS). Intel
is the read-side that turns those signals into a prioritized triage view,
distinct from any per-product scan:

  intel cve CVE-2021-44228        one CVE, full record + computed priority
  intel triage findings.json      rank every CVE id found in a file/report
  intel stats                     store-wide intel coverage

Priority follows the KEV-first doctrine in intel.prioritize.
"""

from __future__ import annotations

import argparse
import json
import re
import sys

import prioritize
import store

VERSION = "0.1.0"

# CVE ids anywhere in free text or JSON: CVE-YYYY-NNNN(+). Case-insensitive so a
# report using lower-case still matches; normalized to upper-case downstream.
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def extract_cve_ids(text: str) -> list[str]:
    """Every distinct CVE id in a blob of text, in first-seen order."""
    seen = dict.fromkeys(m.upper() for m in _CVE_RE.findall(text or ""))
    return list(seen)


def _priority_for(record: store.IntelRecord) -> prioritize.Priority:
    return prioritize.prioritize(
        cvss=record.cvss_score,
        epss=record.epss_score,
        epss_percentile=record.epss_percentile,
        kev=record.kev,
        found=record.found,
    )


def _record_json(record: store.IntelRecord, priority: prioritize.Priority) -> dict:
    return {
        "cve_id": record.cve_id,
        "found": record.found,
        "priority": priority.tier,
        "priority_reasons": list(priority.reasons),
        "severity": record.severity,
        "cvss_score": record.cvss_score,
        "cvss_vector": record.cvss_vector,
        "kev": record.kev,
        "kev_date_added": record.kev_date_added,
        "epss_score": record.epss_score,
        "epss_percentile": record.epss_percentile,
        "published_date": record.published_date,
        "description": record.description,
        "references": record.references,
    }


def cmd_info(_: argparse.Namespace) -> int:
    print(
        """Intel — vulnerability intelligence and CVE triage.

Reads the local DREAD CVE store (built and enriched by Probe: NVD data plus
CISA KEV "exploited in the wild" flags and FIRST EPSS exploit-probability
scores) and turns those signals into a prioritized triage view.

  cve <id>     look up one CVE with its full record and computed priority
  triage <f>   rank every CVE id found in a file (a report, a list, any text)
  stats        store-wide coverage: totals, KEV/EPSS counts, tier breakdown

Priority is KEV-first: a CVE CISA lists as actively exploited is act_now
regardless of score; otherwise high EPSS or critical CVSS is urgent, elevated
EPSS or high CVSS is scheduled, and the rest is low.

Run 'dread update-cve-db' first if the store is empty.
"""
    )
    return 0


def cmd_version(_: argparse.Namespace) -> int:
    print(f"Intel {VERSION}")
    return 0


def _print_record(record: store.IntelRecord, priority: prioritize.Priority) -> None:
    if not record.found:
        print(f"{record.cve_id}: not in local store (priority: {priority.tier})")
        print("  Run 'dread update-cve-db' to refresh, then retry.")
        return
    print(f"{record.cve_id}  [{priority.tier.upper()}]")
    sev = record.severity or "unrated"
    cvss = f"{record.cvss_score:.1f}" if record.cvss_score is not None else "n/a"
    print(f"  Severity: {sev}   CVSS: {cvss}")
    if record.kev:
        added = f" (added {record.kev_date_added})" if record.kev_date_added else ""
        print(f"  CISA KEV: exploited in the wild{added}")
    if record.epss_score is not None:
        pct = (
            f", {round(record.epss_percentile * 100)}th percentile"
            if record.epss_percentile is not None
            else ""
        )
        print(f"  EPSS: {record.epss_score:.2f}{pct}")
    if record.published_date:
        print(f"  Published: {record.published_date}")
    print(f"  Why: {'; '.join(priority.reasons)}")
    if record.description:
        print(f"  {record.description.strip()}")
    for ref in record.references[:3]:
        print(f"  ref: {ref}")


def cmd_cve(args: argparse.Namespace) -> int:
    try:
        record = store.fetch_record(args.cve_id)
    except store.CVEStoreMissing as exc:
        print(str(exc), file=sys.stderr)
        return 3
    priority = _priority_for(record)
    if args.json:
        print(json.dumps(_record_json(record, priority), indent=2))
    else:
        _print_record(record, priority)
    # A CVE that isn't in the store is a lookup miss, not a clean hit.
    return 0 if record.found else 1


def _read_input(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


def cmd_triage(args: argparse.Namespace) -> int:
    try:
        text = _read_input(args.file)
    except OSError as exc:
        print(f"Cannot read {args.file}: {exc}", file=sys.stderr)
        return 2

    cve_ids = extract_cve_ids(text)
    if not cve_ids:
        print(f"No CVE ids found in {args.file}.", file=sys.stderr)
        return 2

    try:
        records = store.fetch_records(cve_ids)
    except store.CVEStoreMissing as exc:
        print(str(exc), file=sys.stderr)
        return 3

    graded = [(r, _priority_for(r)) for r in records]
    ordered = prioritize.rank((r.cve_id, p) for r, p in graded)
    by_id = {r.cve_id: (r, p) for r, p in graded}

    if args.top is not None:
        ordered = ordered[: args.top]

    if args.json:
        payload = {
            "input": args.file,
            "cve_count": len(cve_ids),
            "triage": [_record_json(*by_id[cid]) for cid, _ in ordered],
        }
        print(json.dumps(payload, indent=2))
        return 0

    print(f"Triage of {len(cve_ids)} CVE(s) from {args.file}:")
    print()
    for cid, priority in ordered:
        record, _ = by_id[cid]
        cvss = f"{record.cvss_score:.1f}" if record.cvss_score is not None else "  -"
        epss = f"{record.epss_score:.2f}" if record.epss_score is not None else "   -"
        kev = "KEV" if record.kev else "   "
        print(
            f"  [{priority.tier:9}] {cid:18}  CVSS {cvss:>4}  "
            f"EPSS {epss:>4}  {kev}  {priority.reasons[0]}"
        )
    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    try:
        stats = store.coverage_stats()
    except store.CVEStoreMissing as exc:
        print(str(exc), file=sys.stderr)
        return 3
    if args.json:
        print(json.dumps(stats, indent=2))
        return 0
    print(f"CVE store: {stats['db_path']}")
    print(f"  Total CVEs:    {stats['total_cves']}")
    print(f"  CISA KEV:      {stats['kev_count']}")
    print(f"  EPSS scored:   {stats['epss_scored']}")
    print("  Triage tiers:")
    for tier in ("act_now", "urgent", "scheduled", "low"):
        print(f"    {tier:10} {stats['tiers'][tier]}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(
        prog="intel",
        description="Intel — vulnerability intelligence and CVE triage.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("info", help="Product overview").set_defaults(func=cmd_info)
    sub.add_parser("version", help="Version").set_defaults(func=cmd_version)

    c = sub.add_parser("cve", help="Look up one CVE with its computed priority")
    c.add_argument("cve_id", help="CVE id, e.g. CVE-2021-44228")
    c.add_argument("--json", action="store_true", help="Emit JSON")
    c.set_defaults(func=cmd_cve)

    t = sub.add_parser("triage", help="Rank every CVE id found in a file or report")
    t.add_argument("file", help="Path to a report/list/text file, or '-' for stdin")
    t.add_argument("--top", type=int, help="Show only the N most urgent")
    t.add_argument("--json", action="store_true", help="Emit JSON")
    t.set_defaults(func=cmd_triage)

    s = sub.add_parser("stats", help="Store-wide intel coverage")
    s.add_argument("--json", action="store_true", help="Emit JSON")
    s.set_defaults(func=cmd_stats)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
