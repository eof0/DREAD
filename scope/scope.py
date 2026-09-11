#!/usr/bin/env python3
"""
Scope - Attack Surface Discovery

Discovers:
- Subdomains (DNS, certificate transparency)
- IP ranges (ASN lookup)
- Cloud assets (S3, CloudFront, etc.)
- Related domains

Usage:
    python scope.py discover example.com
    python scope.py discover example.com --output json
"""

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

# Ensure local discovery/output packages resolve regardless of CWD or -m invocation
_SCOPE_ROOT = Path(__file__).resolve().parent
if str(_SCOPE_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCOPE_ROOT))

from discovery.subdomain import SubdomainDiscovery, normalize_target_hostname
from discovery.cloud_assets import CloudDiscovery
from discovery.ip_intel import IPIntel
from output.formatter import OutputFormatter


def discover_domain(domain: str, options: dict, quiet: bool = False) -> dict:
    """
    Full attack surface discovery for a domain.
    
    Args:
        domain: Target domain
        options: Dict with subdomains, cloud, ip_intel booleans
        quiet: If True, don't print progress messages
    
    Returns structured discovery results.
    """
    host = normalize_target_hostname(domain)
    results = {
        "domain": host or domain.strip(),
        "discovery": {},
        "input": domain.strip(),
    }

    def _log(message: str) -> None:
        if not quiet:
            print(message, file=sys.stderr)

    _log("[Phase 1] Attack Surface Discovery (Scope)")
    
    if not host:
        _log("[!] Empty or invalid target after normalization; skipping discovery phases.")
        return results

    # Subdomain discovery
    if options.get("subdomains", True):
        _log(f"[*] Discovering subdomains for {host}...")
        t0 = time.time()
        sub = SubdomainDiscovery()

        def _subdomain_progress(stage: str, source: str, payload: dict[str, Any]) -> None:
            if stage == "source_start":
                _log(f"[+] Running subdomain source: {source}")
            elif stage == "source_progress":
                _log(f"[*] Found {payload.get('count', 0)} subdomains so far...")
            elif stage == "source_done":
                _log(f"[*] {source} completed in {payload.get('elapsed', 0.0):.2f}s")

        results["discovery"]["subdomains"] = sub.discover(
            host,
            progress_callback=_subdomain_progress,
        )
        sd = results["discovery"]["subdomains"] or {}
        all_unique = sd.get("all_unique", []) or []
        elapsed = time.time() - t0
        if all_unique:
            _log(f"[+] Subdomain discovery complete: {len(all_unique)} total")
            _log(f"[*] Subdomain phase completed in {elapsed:.2f}s")

            # Dangling-CNAME takeover check over the discovered names (best-effort).
            try:
                from discovery.takeover import run_takeover_scan

                _log("[*] Checking discovered subdomains for takeover risk...")
                takeovers = run_takeover_scan(all_unique)
                results["discovery"]["subdomain_takeover"] = takeovers
                if takeovers:
                    _log(f"[!] Potential subdomain takeover(s): {len(takeovers)}")
                    for t in takeovers:
                        _log(f"    - {t['subdomain']} -> {t['cname']} ({t['service']})")
            except Exception as e:
                _log(f"[!] Takeover check skipped: {e}")
        else:
            _log("[!] No subdomains discovered (possible API failure or restrictive target)")
    
    # Cloud asset discovery
    if options.get("cloud", True):
        _log("[*] Scanning for cloud assets...")
        t0 = time.time()
        cloud = CloudDiscovery()
        results["discovery"]["cloud_assets"] = cloud.scan(host)
        ca = results["discovery"]["cloud_assets"] or {}
        total_assets = 0
        for v in ca.values():
            if isinstance(v, list):
                total_assets += len(v)
        elapsed = time.time() - t0
        _log(
            f"[*] Cloud asset scan complete: {total_assets} candidate assets "
            f"in {elapsed:.1f}s",
        )
    
    # IP intelligence
    if options.get("ip_intel", True):
        _log("[*] Gathering IP intelligence...")
        t0 = time.time()
        ip = IPIntel()
        results["discovery"]["ip_ranges"] = ip.get_ip_ranges(host)
        ir = results["discovery"]["ip_ranges"] or {}
        resolutions = ir.get("resolutions", []) or []
        asn_info = ir.get("asn_info", []) or []
        elapsed = time.time() - t0
        _log(
            f"[*] IP intelligence complete: {len(resolutions)} resolutions, "
            f"{len(asn_info)} ASN records in {elapsed:.1f}s",
        )
    
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Scope - Attack Surface Discovery",
        prog="scope"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Discover command
    discover_parser = subparsers.add_parser("discover", help="Discover attack surface")
    discover_parser.add_argument("domain", help="Target domain")
    discover_parser.add_argument("--output", "-o", choices=["json", "yaml", "table"],
                                 default="table", help="Output format")
    discover_parser.add_argument("--no-subdomains", action="store_true",
                                 help="Skip subdomain discovery")
    discover_parser.add_argument("--no-cloud", action="store_true",
                                 help="Skip cloud asset discovery")
    discover_parser.add_argument("--no-ip", action="store_true",
                                 help="Skip IP intelligence")
    discover_parser.add_argument("--outfile", "-f", help="Output file")
    discover_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show progress output even when using JSON output",
    )
    discover_parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress progress on stderr (stdout payload is unchanged)",
    )
    
    # List sources command
    sources_parser = subparsers.add_parser("sources", help="List data sources")
    
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        return 1
    
    if args.command == "sources":
        print("Scope Data Sources:")
        print("  - Certificate Transparency logs (crt.sh)")
        print("  - DNS enumeration (passive + active)")
        print("  - ASN/IP range lookups")
        print("  - Cloud provider APIs (S3, Azure, GCP)")
        print("  - Web archive (Wayback Machine)")
        return 0
    
    if args.command == "discover":
        options = {
            "subdomains": not args.no_subdomains,
            "cloud": not args.no_cloud,
            "ip_intel": not args.no_ip,
        }
        
        # stderr progress for all output modes by default (JSON included) so runs do not
        # look hung. Use --quiet to silence stderr.
        quiet = args.quiet
        results = discover_domain(args.domain, options, quiet=quiet)
        
        # Format output
        formatter = OutputFormatter()
        if args.output == "json":
            output = formatter.to_json(results)
        elif args.output == "yaml":
            try:
                output = formatter.to_yaml(results)
            except RuntimeError as e:
                print(f"[!] {e}", file=sys.stderr)
                return 1
        else:
            output = formatter.to_table(results)
        
        print(output)
        
        # Save to file if requested
        if args.outfile:
            with open(args.outfile, "w") as f:
                f.write(output)
            if not quiet:
                print(f"\n[+] Results saved to {args.outfile}", file=sys.stderr)
        
        return 0
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
