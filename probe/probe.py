#!/usr/bin/env python3
"""
Probe - Modular Security Vulnerability Scanner

Usage:
    probe scan <target> [options]
    probe update-asn-db
    probe update-cve-db
    probe profiles
"""

import argparse
import sys

from scanner.engine import ScanEngine
from scanner.config import ScanConfig, SCAN_PROFILES
from scanner.auth import parse_cookie_string, parse_header_lines
from scanner.asn_db_updater import update_asn_db
from scanner.cve_db_manager import update_cve_database, update_kev_epss, get_stats
from scanner.cve_db_bootstrap import update_with_snapshot_policy


def _apply_auth_args(args, config_kwargs: dict) -> None:
    """Translate --auth-* / -H flags into ScanConfig auth kwargs."""
    bearer = getattr(args, "auth_bearer", None)
    basic = getattr(args, "auth_basic", None)
    cookie = getattr(args, "auth_cookie", None)

    if bearer:
        config_kwargs["auth"] = {"type": "bearer", "credentials": {"token": bearer}}
    elif basic:
        if ":" not in basic:
            raise SystemExit("[!] --auth-basic must be in the form USER:PASS")
        user, _, password = basic.partition(":")
        config_kwargs["auth"] = {
            "type": "basic",
            "credentials": {"username": user, "password": password},
        }
    if cookie:
        config_kwargs["cookies"] = parse_cookie_string(cookie)

    b_bearer = getattr(args, "auth_b_bearer", None)
    b_cookie = getattr(args, "auth_b_cookie", None)
    if b_bearer:
        config_kwargs["auth_secondary"] = {
            "type": "bearer",
            "credentials": {"token": b_bearer},
        }
    elif b_cookie:
        config_kwargs["auth_secondary"] = {
            "type": "cookie",
            "credentials": {},
            "cookies": parse_cookie_string(b_cookie),
        }

    headers = parse_header_lines(getattr(args, "headers", None))
    if headers:
        config_kwargs["extra_headers"] = headers


def cmd_scan(args) -> int:
    """Execute scan command."""
    formats = []
    if args.format:
        raw = args.format.strip().lower()
        if raw == "all":
            formats = ["json", "md", "pdf"]
        else:
            formats = [f.strip() for f in raw.split(",") if f.strip()]

    allowed = {"json", "md", "pdf", "html"}
    invalid = [fmt for fmt in formats if fmt not in allowed]
    if invalid:
        print(f"[!] Unsupported format(s): {', '.join(invalid)}", file=sys.stderr)
        return 1

    config_kwargs = {
        "target_url": args.target,
        "output_name": args.output,
        "output_formats": formats or ["json", "md", "pdf"],
        "profile": args.profile,
        "verbose": getattr(args, "verbose", False),
    }
    
    if args.depth is not None:
        config_kwargs["depth"] = args.depth
    if args.max_urls is not None:
        config_kwargs["max_urls"] = args.max_urls
    if args.rate_limit is not None:
        config_kwargs["rate_limit"] = args.rate_limit
    if args.workers is not None:
        config_kwargs["parallel_workers"] = args.workers
    if getattr(args, "plugins", None):
        config_kwargs["enabled_plugins"] = [
            p.strip() for p in args.plugins.split(",") if p.strip()
        ]
    if getattr(args, "output_dir", None):
        config_kwargs["output_dir"] = str(args.output_dir).strip()

    _apply_auth_args(args, config_kwargs)

    config = ScanConfig(**config_kwargs)
    engine = ScanEngine(config)

    try:
        report = engine.run_scan()
        return 0
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"[!] Scan failed: {e}", file=sys.stderr)
        return 1


def cmd_profiles(args) -> int:
    """List available scan profiles."""
    print("\nAvailable Scan Profiles:")
    print("=" * 60)
    
    for name, profile in SCAN_PROFILES.items():
        print(f"\n{name}")
        print(f"  Description: {profile['description']}")
        print(f"  Depth: {profile['depth']}")
        print(f"  Max URLs: {profile['max_urls']}")
        print(f"  Rate Limit: {profile['rate_limit']}s")
        print(f"  Workers: {profile['parallel_workers']}")
        print(f"  Plugins: {', '.join(profile['enabled_plugins'])}")
    
    print("\nUsage: probe scan <target> --profile <name>")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="probe",
        description="Probe - Modular Security Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    probe scan example.com
    probe scan example.com --profile quick
    probe scan example.com --depth 3 --format json,md
    probe update-asn-db
    probe profiles
        """
    )

    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Run a security scan")
    scan_parser.add_argument(
        "target",
        help="Target domain, IP address, or URL to scan",
    )
    scan_parser.add_argument(
        "-o", "--output",
        help="Base output name for report files",
    )
    scan_parser.add_argument(
        "--output-dir",
        dest="output_dir",
        metavar="DIR",
        help="Directory for artifacts (default: REPORTS under repository root)",
    )
    scan_parser.add_argument(
        "--format",
        default="json,md,pdf,html",
        help="Comma-separated formats: json,md,pdf,html (default: all)",
    )
    scan_parser.add_argument(
        "--profile",
        choices=list(SCAN_PROFILES.keys()),
        help="Use a predefined scan profile",
    )
    scan_parser.add_argument(
        "--depth",
        type=int,
        help="Crawl depth (overrides profile)",
    )
    scan_parser.add_argument(
        "--max-urls",
        type=int,
        help="Maximum URLs to crawl (overrides profile)",
    )
    scan_parser.add_argument(
        "--rate-limit",
        type=float,
        help="Request rate limit in seconds (overrides profile)",
    )
    scan_parser.add_argument(
        "--workers",
        type=int,
        help="Parallel worker threads (overrides profile)",
    )
    scan_parser.add_argument(
        "--plugins",
        "-p",
        help=(
            "Comma-separated plugins to run (overrides profile list). "
            "e.g. fingerprinting,security_headers,tls_analysis"
        ),
    )
    scan_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output - show every URL, plugin execution, and check",
    )
    auth_group = scan_parser.add_argument_group("authentication")
    auth_group.add_argument(
        "--auth-bearer",
        metavar="TOKEN",
        help="Send 'Authorization: Bearer TOKEN' on every request (primary identity)",
    )
    auth_group.add_argument(
        "--auth-basic",
        metavar="USER:PASS",
        help="HTTP Basic auth for the primary identity",
    )
    auth_group.add_argument(
        "--auth-cookie",
        metavar="COOKIES",
        help='Cookie string for the primary identity, e.g. "session=abc; csrf=xyz"',
    )
    auth_group.add_argument(
        "--auth-b-bearer",
        metavar="TOKEN",
        dest="auth_b_bearer",
        help="Bearer token for a SECOND identity, enabling two-identity IDOR checks",
    )
    auth_group.add_argument(
        "--auth-b-cookie",
        metavar="COOKIES",
        dest="auth_b_cookie",
        help="Cookie string for the second identity",
    )
    auth_group.add_argument(
        "-H", "--header",
        action="append",
        dest="headers",
        metavar="'K: V'",
        help="Extra header on every request (repeatable)",
    )

    asn_db_parser = subparsers.add_parser(
        "update-asn-db",
        help=(
            "Update ASN database (public IP allocations). "
            "Skips full download when the RIPE delegated file is unchanged."
        ),
    )
    asn_db_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose progress",
    )
    asn_db_parser.add_argument(
        "--force",
        action="store_true",
        help="Always download and rebuild (ignore unchanged-source short-circuit)",
    )

    cve_parser = subparsers.add_parser(
        "update-cve-db",
        help="Update CVE database from NVD",
    )
    cve_parser.add_argument(
        "--days",
        type=int,
        default=None,
        help="Build a publication-window mirror directly from NVD",
    )
    cve_parser.add_argument(
        "--years",
        type=int,
        default=None,
        help="Bootstrap CVEs published in the last N years (overrides --days)",
    )
    cve_parser.add_argument(
        "--full",
        action="store_true",
        help="Rebuild the full local mirror directly from NVD",
    )
    cve_parser.add_argument(
        "--raw-full",
        action="store_true",
        help="Best-effort unfiltered NVD crawl; offset resumption is not deterministic",
    )
    cve_parser.add_argument(
        "--snapshot-only",
        action="store_true",
        help="Install the published snapshot without contacting NVD afterward",
    )
    cve_parser.add_argument(
        "--no-snapshot",
        action="store_true",
        help="Use direct NVD synchronization without downloading a snapshot",
    )
    cve_parser.add_argument(
        "--kev-epss-only",
        action="store_true",
        help="Only refresh CISA KEV / FIRST EPSS enrichment, skip the NVD sync",
    )
    cve_parser.add_argument(
        "--skip-kev-epss",
        action="store_true",
        help="Skip CISA KEV / FIRST EPSS enrichment during this update",
    )

    cve_stats_parser = subparsers.add_parser(
        "cve-stats",
        help="Show CVE database statistics",
    )

    subparsers.add_parser(
        "profiles",
        help="List available scan profiles",
    )

    args = parser.parse_args()

    verbose = getattr(args, "verbose", False)

    if args.command == "update-asn-db":
        update_asn_db(verbose=args.verbose, force=getattr(args, "force", False))
        return 0

    elif args.command == "update-cve-db":
        try:
            raw_full = getattr(args, "raw_full", False)
            full_sync = getattr(args, "full", False) or raw_full
            years = getattr(args, "years", None)
            days = getattr(args, "days", None)
            snapshot_only = getattr(args, "snapshot_only", False)
            kev_epss_only = getattr(args, "kev_epss_only", False)
            skip_kev_epss = getattr(args, "skip_kev_epss", False)
            direct = full_sync or years is not None or days is not None or getattr(args, "no_snapshot", False)
            if snapshot_only and direct:
                raise ValueError("--snapshot-only cannot be combined with direct-NVD options")
            if kev_epss_only and skip_kev_epss:
                raise ValueError("--kev-epss-only cannot be combined with --skip-kev-epss")
            if kev_epss_only and (direct or snapshot_only):
                raise ValueError("--kev-epss-only cannot be combined with NVD sync options")

            if kev_epss_only:
                counts = update_kev_epss(verbose=verbose)
                print(
                    f"[+] KEV/EPSS enrichment updated: "
                    f"{counts['kev_updated']} KEV, {counts['epss_updated']} EPSS"
                )
                return 0

            if direct:
                count = update_cve_database(
                    days=days if days is not None else 30,
                    years=years,
                    full_sync=full_sync,
                    raw_full_sync=raw_full,
                    force=full_sync,
                    verbose=verbose,
                )
            else:
                count = update_with_snapshot_policy(
                    snapshot_only=snapshot_only,
                    verbose=verbose,
                )
            if snapshot_only:
                print("[+] CVE database snapshot installed")
                return 0
            if not skip_kev_epss:
                counts = update_kev_epss(verbose=verbose)
                print(
                    f"[+] KEV/EPSS enrichment updated: "
                    f"{counts['kev_updated']} KEV, {counts['epss_updated']} EPSS"
                )
            print(f"[+] CVE database updated with {count} entries")
            return 0
        except Exception as e:
            print(f"[!] CVE update failed: {e}", file=sys.stderr)
            return 1

    elif args.command == "cve-stats":
        try:
            stats = get_stats()
            print("\nCVE Database Statistics")
            print("=" * 40)
            print(f"Total CVEs: {stats.get('total_cves', 0)}")
            print(f"Total Products: {stats.get('total_products', 0)}")
            print(f"Coverage: {stats.get('coverage_mode', 'unknown')}")
            print(f"NVD Cursor: {stats.get('nvd_cursor', 'Never')}")
            print(f"Last Updated: {stats.get('last_updated', 'Never')}")
            print(f"CISA KEV flagged: {stats.get('kev_count', 0)}")
            print(f"EPSS scored: {stats.get('epss_count', 0)}")
            print("\nBy Severity:")
            for sev, count in stats.get('severity_counts', {}).items():
                print(f"  {sev.upper()}: {count}")
            return 0
        except Exception as e:
            print(f"[!] Failed to get stats: {e}", file=sys.stderr)
            return 1

    elif args.command == "profiles":
        return cmd_profiles(args)

    elif args.command == "scan":
        return cmd_scan(args)
    
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
