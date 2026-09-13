#!/usr/bin/env python3
"""
DREAD — multi-product security suite

Products (see `python dread.py products`):
  Probe   — web vulnerability scanner
  Scope   — attack surface / asset discovery
  Watch   — continuous monitoring (web, internal, cloud)
  Graph   — attack path analysis
  Intel   — vulnerability intelligence
  Reports  — central reporting platform
  Spear   — internal network assessment / automated pentest agent
  Cannon  - authorized stress testing and external tool orchestration
  DreadAI      — orchestration, gap testing, third-party tools, report verification

Shortcuts:
    python dread.py version
    python dread.py products [--json]
    python dread.py scan example.com
    python dread.py scan example.com --suite-out ./suite_runs \\
        --suite-report --suite-verify
    python dread.py discover example.com   # Scope
    python dread.py light-scan example.com # Probe only
    python dread.py probe scan example.com
    python dread.py dreadai verify report.json
    python dread.py update-db
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from products import (
    SUITE_PRODUCTS,
    SUITE_VERSION,
    format_suite_overview,
    product_by_cli,
    script_path,
)
from suite_run import (
    append_history_run,
    new_run_id,
    slug_target,
    update_manifest,
    write_json,
    write_manifest,
)

DREAD_DIR = Path(__file__).parent.resolve()
_SCOPE = product_by_cli("scope")
_PROBE = product_by_cli("probe")
_DREADAI = product_by_cli("dreadai")
if _SCOPE is None or _PROBE is None:
    raise RuntimeError("products.SUITE_PRODUCTS must define scope and probe")
SCOPE_PATH = script_path(_SCOPE)
PROBE_PATH = script_path(_PROBE)
DREADAI_PATH = script_path(_DREADAI) if _DREADAI else None
REPORTS_PATH = DREAD_DIR / "reports" / "reports.py"


def _run_with_heartbeat(
    cmd: list[str],
    *,
    cwd: Path,
    label: str,
    quiet: bool,
    capture_stdout: bool,
    capture_stderr: bool,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    """Run a child process and print periodic status while it is still running."""
    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd),
        stdout=subprocess.PIPE if capture_stdout else None,
        stderr=subprocess.PIPE if capture_stderr else None,
        text=True,
        env=env,
    )
    started = time.monotonic()
    next_tick = started + 5.0
    while proc.poll() is None:
        if not quiet and time.monotonic() >= next_tick:
            elapsed = int(time.monotonic() - started)
            print(f"[*] {label} still running... {elapsed}s elapsed", file=sys.stderr)
            next_tick += 5.0
        time.sleep(0.2)
    stdout_data, stderr_data = proc.communicate()
    return subprocess.CompletedProcess(
        args=cmd,
        returncode=proc.returncode if proc.returncode is not None else 1,
        stdout=stdout_data,
        stderr=stderr_data,
    )


def _hostname_from_scan_target(raw: str) -> str:
    """Bare hostname from a URL or domain string (for www vs apex logic)."""
    value = (raw or "").strip().lower()
    if not value:
        return ""
    if "://" not in value:
        value = f"https://{value}"
    return (urlparse(value).hostname or "").strip().rstrip(".")


def _dedupe_scan_targets(targets: list[str]) -> list[str]:
    """
    Keep the first target per host:port. Scope returns bare hostnames while the
    user may pass a URL, so "https://example.com" and "example.com" must count
    as one target or the same site gets crawled and scanned twice.
    """
    seen: set[tuple[str, int | None]] = set()
    unique: list[str] = []
    for raw in targets:
        value = (raw or "").strip().lower()
        if "://" not in value:
            value = f"https://{value}"
        try:
            port = urlparse(value).port
        except ValueError:
            port = None
        key = (_hostname_from_scan_target(raw), None if port in (80, 443) else port)
        if key in seen:
            continue
        seen.add(key)
        unique.append(raw)
    return unique


def _target_supports_discovery(target: str) -> bool:
    """
    Whether external attack-surface discovery (subdomain enumeration, cloud assets)
    is meaningful for a target. It is NOT for localhost, IP literals, .local/.localhost
    names, or single-label hosts — enumerating "subdomains of localhost" just wastes
    time and pollutes the report with phantom hosts.
    """
    import ipaddress

    host = _hostname_from_scan_target(target)
    if not host:
        return False
    if host in ("localhost",) or host.endswith((".localhost", ".local")):
        return False
    stripped = host.strip("[]")
    try:
        ipaddress.ip_address(stripped)
        return False  # bare IP address
    except ValueError:
        pass
    # A registrable domain needs at least one dot (a label + a TLD).
    return "." in host


def _omit_redundant_www_when_user_chose_apex(primary: str, targets: list[str]) -> list[str]:
    """
    If the user targets the apex host (not www), omit www.<apex> from follow-on
    scans. Many sites only redirect www → apex; scanning www separately adds
    noise and can fail where the apex works.
    """
    ph = _hostname_from_scan_target(primary)
    if not ph or ph.startswith("www."):
        return targets
    www_only = f"www.{ph}"
    return [t for t in targets if _hostname_from_scan_target(t) != www_only]


def _parse_scope_discovery_json(raw: str) -> dict:
    """Parse Scope JSON from stdout; tolerate surrounding whitespace."""
    text = (raw or "").strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                pass
        raise


def run_scope(
    domain: str,
    output_format: str = "json",
    verbose: bool = False,
    quiet: bool = False,
) -> dict:
    """Run Scope discovery; returns parsed dict for JSON, or {} on failure."""
    cmd = [
        sys.executable,
        str(SCOPE_PATH),
        "discover",
        domain,
        "--output",
        output_format,
    ]
    if quiet:
        cmd.append("--quiet")
    elif not quiet:
        cmd.append("--verbose")

    result = _run_with_heartbeat(
        cmd,
        cwd=SCOPE_PATH.parent,
        label="Scope discovery",
        quiet=quiet,
        capture_stdout=True,
        capture_stderr=quiet,
    )
    if quiet and result.stderr:
        sys.stderr.write(result.stderr)

    if result.returncode != 0:
        print(
            f"[!] Scope failed (exit {result.returncode}).",
            file=sys.stderr,
        )
        return {}

    if output_format == "json":
        try:
            return _parse_scope_discovery_json(result.stdout)
        except json.JSONDecodeError as e:
            print(f"[!] Failed to parse Scope JSON: {e}", file=sys.stderr)
            snippet = (result.stdout or "")[:500]
            print(f"[!] Raw output (truncated): {snippet!r}", file=sys.stderr)
            return {}
    return {}


def run_probe(
    target: str,
    plugins: list | None = None,
    report_format: str | None = None,
    quiet: bool = False,
    output_name: str | None = None,
    output_dir: str | None = None,
    verbose: bool = False,
    skip_asn_refresh: bool = False,
    staged_output: bool = False,
    profile: str | None = None,
    depth: int | None = None,
    max_urls: int | None = None,
    render_js: bool = False,
    offensive: bool = False,
    ports: str | None = None,
    proxy: str | None = None,
    proxy_file: str | None = None,
    password_spray: bool = False,
) -> subprocess.CompletedProcess:
    """Run Probe scan. When quiet is False, stdout/stderr stream live to the terminal.

    staged_output: output_dir is a temp dir merged and deleted by the caller, so
    Probe should not list those soon-to-vanish paths as its artifacts.
    """
    cmd = [sys.executable, str(PROBE_PATH), "scan", target]

    if verbose:
        cmd.append("-v")
    if plugins:
        cmd.extend(["--plugins", ",".join(plugins)])
    if profile:
        cmd.extend(["--profile", profile])
    if depth is not None:
        cmd.extend(["--depth", str(depth)])
    if max_urls is not None:
        cmd.extend(["--max-urls", str(max_urls)])
    if render_js:
        cmd.append("--render-js")
    if offensive:
        cmd.append("--offensive")
    if ports:
        cmd.extend(["--ports", str(ports)])
    if proxy:
        cmd.extend(["--proxy", str(proxy)])
    if proxy_file:
        cmd.extend(["--proxy-file", str(proxy_file)])
    if password_spray:
        cmd.append("--password-spray")
    if report_format:
        cmd.extend(["--format", report_format])
    if output_name:
        cmd.extend(["-o", output_name])
    if output_dir:
        cmd.extend(["--output-dir", output_dir])

    env = None
    if skip_asn_refresh or staged_output:
        env = dict(os.environ)
    if skip_asn_refresh:
        env["DREAD_ASN_PRECHECKED"] = "1"
    if staged_output:
        env["DREAD_STAGED_OUTPUT"] = "1"

    if quiet:
        return _run_with_heartbeat(
            cmd,
            cwd=PROBE_PATH.parent,
            label=f"Probe scan ({target})",
            quiet=True,
            capture_stdout=True,
            capture_stderr=True,
            env=env,
        )

    return _run_with_heartbeat(
        cmd,
        cwd=PROBE_PATH.parent,
        label=f"Probe scan ({target})",
        quiet=False,
        capture_stdout=False,
        capture_stderr=False,
        env=env,
    )


def run_asn_precheck(verbose: bool = False, quiet: bool = False) -> int:
    """Run ASN DB check/update before suite scan."""
    cmd = [sys.executable, str(PROBE_PATH), "update-asn-db"]
    if verbose:
        cmd.append("-v")
    r = _run_with_heartbeat(
        cmd,
        cwd=PROBE_PATH.parent,
        label="ASN DB pre-check",
        quiet=quiet,
        capture_stdout=quiet,
        capture_stderr=quiet,
    )
    if quiet and r.stdout:
        sys.stdout.write(r.stdout)
    if quiet and r.stderr:
        sys.stderr.write(r.stderr)
    return r.returncode


def _merge_report_formats(user_format: str | None, require_json: bool) -> str | None:
    parts: list[str] = []
    seen: set[str] = set()
    raw = (user_format or "").strip()
    if raw:
        for x in raw.split(","):
            x = x.strip().lower()
            if x and x not in seen:
                seen.add(x)
                parts.append(x)
    if require_json and "json" not in seen:
        parts.insert(0, "json")
        seen.add("json")
    return ",".join(parts) if parts else None


def _run_suite_reports(
    *,
    run_dir: Path,
    probe_paths: list[Path],
    scope_path: Path | None,
    formats: str,
    try_npm: bool,
    quiet: bool,
    out_dir: Path | None = None,
) -> int:
    out = out_dir if out_dir is not None else run_dir / "suite_report"
    cmd: list[str] = [
        sys.executable,
        str(REPORTS_PATH),
        "build",
        "-o",
        str(out),
        "--name",
        "dread_suite_report",
        "--formats",
        formats,
    ]
    inc: list[str] = []
    if probe_paths:
        inc.append("probe")
        for p in probe_paths:
            cmd.extend(["--probe", str(p.resolve())])
    if scope_path and scope_path.is_file():
        inc.append("scope")
        cmd.extend(["--scope", str(scope_path.resolve())])
    if not inc:
        print("[!] suite-report: no artifacts to aggregate.", file=sys.stderr)
        return 1
    cmd.extend(["--include", ",".join(inc)])
    if try_npm:
        cmd.append("--try-npm")
    kwargs: dict = {"cwd": str(DREAD_DIR)}
    if quiet:
        kwargs["capture_output"] = True
        kwargs["text"] = True
    r = subprocess.run(cmd, **kwargs)
    if quiet and r.stderr:
        sys.stderr.write(r.stderr)
    return r.returncode


def _run_suite_verify(suite_json: Path, quiet: bool) -> int:
    if not DREADAI_PATH:
        print("[!] DreadAI path unknown; skip verify.", file=sys.stderr)
        return 0
    cmd = [sys.executable, str(DREADAI_PATH), "verify", str(suite_json.resolve())]
    kwargs: dict = {"cwd": str(DREAD_DIR)}
    if quiet:
        kwargs["capture_output"] = True
        kwargs["text"] = True
    r = subprocess.run(cmd, **kwargs)
    if quiet and r.stdout:
        sys.stdout.write(r.stdout)
    if quiet and r.stderr:
        sys.stderr.write(r.stderr)
    return r.returncode


def _copy_history_to_dashboard(suite_base: Path, dashboard_dir: Path) -> None:
    hist = suite_base / "history.json"
    if hist.is_file() and dashboard_dir.is_dir():
        shutil.copyfile(hist, dashboard_dir / "history.json")


def full_scan(target: str, args: argparse.Namespace) -> int:
    """
    Full security assessment:
    1. Scope: Discover attack surface
    2. Probe: Scan discovered assets
    """
    quiet = getattr(args, "quiet", False)
    suite_base_opt = getattr(args, "suite_out", None)
    suite_base = Path(suite_base_opt).resolve() if suite_base_opt else None
    suite_report_flag = getattr(args, "suite_report", False)
    suite_verify_flag = getattr(args, "suite_verify", False)
    suite_try_npm = getattr(args, "suite_try_npm", False)
    suite_formats = getattr(args, "suite_report_formats", "json,pdf,dashboard")

    if suite_report_flag and not suite_base_opt:
        print("[!] --suite-report requires --suite-out DIR", file=sys.stderr)
        return 2
    if suite_verify_flag and not suite_report_flag:
        print("[!] --suite-verify requires --suite-report", file=sys.stderr)
        return 2

    run_dir: Path | None = None
    run_id: str | None = None
    manifest_path: Path | None = None
    scope_file: Path | None = None
    probe_artifacts: list[Path] = []
    is_temp_work_dir = False

    if suite_base:
        run_id = new_run_id()
        run_dir = suite_base / f"run_{run_id}"
        run_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = run_dir / "manifest.json"
        write_manifest(
            manifest_path,
            {
                "run_id": run_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "primary_target": target,
                "paths": {
                    "scope_discovery": "scope_discovery.json",
                    "probe_reports": [],
                },
            },
        )
    else:
        # Default path: stage per-host JSON in a temp dir, merge into one report,
        # then delete the temp dir so the tree is never littered with per-host files.
        run_id = new_run_id()
        run_dir = Path(tempfile.mkdtemp(prefix="dread_scan_"))
        is_temp_work_dir = True

    if not quiet:
        print("=" * 60)
        print(f"DREAD Full Security Scan: {target}")
        print("=" * 60)
        print()

    # Pre-flight: ASN database freshness/update (before Scope)
    asn_rc = run_asn_precheck(
        verbose=bool(getattr(args, "verbose", False)),
        quiet=quiet,
    )
    asn_prechecked = asn_rc == 0
    if asn_rc != 0 and not quiet:
        print(
            "[!] ASN DB pre-check failed; continuing scan and allowing Probe fallback.",
            file=sys.stderr,
        )

    # Phase 1: Discovery
    verbose = bool(getattr(args, "verbose", False))

    # Skip external discovery for localhost/IP/single-host targets — there are no
    # subdomains or cloud assets to find, and enumerating "subdomains of localhost"
    # both wastes time and floods the report with 0-finding phantom hosts.
    if _target_supports_discovery(target):
        if not quiet:
            print("[Phase 1] Attack Surface Discovery (Scope)")
            print("-" * 60)
        discovery = run_scope(
            target,
            output_format="json",
            verbose=verbose,
            quiet=quiet,
        )
    else:
        if not quiet:
            print("[Phase 1] Attack Surface Discovery — skipped "
                  f"(local/IP target has no external surface): {target}")
            print("-" * 60)
        discovery = {}

    if run_dir and discovery:
        scope_file = run_dir / "scope_discovery.json"
        write_json(scope_file, discovery)
    if run_dir and manifest_path:
        bsd_name = "scope_discovery.json" if (scope_file and scope_file.is_file()) else None
        update_manifest(
            manifest_path,
            paths={"scope_discovery": bsd_name, "probe_reports": []},
        )

    if not discovery:
        if not quiet:
            print("[!] Discovery failed, falling back to direct scan")
        targets_to_scan = [target]
    else:
        subdomains = discovery.get("discovery", {}).get("subdomains", {})
        all_unique = subdomains.get("all_unique", [])

        # Primary goes first so it survives dedupe; filtering before the cap keeps
        # the primary's own host from using up a --max-subdomains slot.
        max_subdomains = getattr(args, "max_subdomains", 10)
        targets_to_scan = _dedupe_scan_targets(
            _omit_redundant_www_when_user_chose_apex(target, [target, *all_unique])
        )[: 1 + max_subdomains]

        if not quiet:
            print(f"\n[+] Discovered {len(all_unique)} subdomains")
            print(
                f"[+] Will scan {len(targets_to_scan)} target(s) "
                f"(primary + up to {max_subdomains} from list)"
            )

    if not quiet:
        print()

    # Phase 2: Scanning
    if not quiet:
        print("[Phase 2] Vulnerability Scanning (Probe)")
        print("-" * 60)

    plugins = None
    if getattr(args, "plugins", None):
        plugins = [p.strip() for p in args.plugins.split(",") if p.strip()]

    user_format = getattr(args, "format", None) or None
    if user_format is not None:
        user_format = user_format.strip() or None
    report_format = _merge_report_formats(user_format, require_json=bool(run_dir))

    runs_root_str = str(run_dir.resolve()) if run_dir else None
    rel_names: list[str] = []

    failures = 0
    for i, scan_target in enumerate(targets_to_scan, 1):
        if not quiet:
            print(f"\n[{i}/{len(targets_to_scan)}] Scanning {scan_target}...")
        out_name = (
            f"probe_{i:02d}_{slug_target(scan_target)}"
            if run_dir
            else None
        )
        proc = run_probe(
            scan_target,
            plugins=plugins,
            report_format=report_format,
            quiet=quiet,
            output_name=out_name,
            output_dir=runs_root_str,
            verbose=verbose,
            skip_asn_refresh=asn_prechecked,
            staged_output=is_temp_work_dir,
            profile=getattr(args, "profile", None),
            depth=getattr(args, "depth", None),
            max_urls=getattr(args, "max_urls", None),
            render_js=bool(getattr(args, "render_js", False)),
            offensive=bool(getattr(args, "offensive", False)),
            ports=getattr(args, "ports", None),
            proxy=getattr(args, "proxy", None),
            proxy_file=getattr(args, "proxy_file", None),
            password_spray=bool(getattr(args, "password_spray", False)),
        )
        if proc.returncode != 0:
            failures += 1
            if quiet:
                print(
                    proc.stderr or proc.stdout or "(no output)",
                    file=sys.stderr,
                )
        elif run_dir and out_name:
            jp = run_dir / f"{out_name}.json"
            if jp.is_file():
                probe_artifacts.append(jp)
                rel_names.append(f"{out_name}.json")
                if manifest_path:
                    update_manifest(
                        manifest_path,
                        paths={
                            "scope_discovery": "scope_discovery.json"
                            if scope_file and scope_file.is_file()
                            else None,
                            "probe_reports": rel_names,
                        },
                    )

    if not quiet:
        print()
        print("=" * 60)
        print("Scan Complete")
        print("=" * 60)
        print(f"Targets scanned: {len(targets_to_scan)}")
        print()
        print("Discovered assets:")

    if discovery:
        subdomains = discovery.get("discovery", {}).get("subdomains", {})
        if not quiet:
            print(f"  - Subdomains: {len(subdomains.get('all_unique', []))}")

        cloud = discovery.get("discovery", {}).get("cloud_assets", {})
        cloud_count = sum(
            len(v) for v in cloud.values() if isinstance(v, list)
        )
        if not quiet:
            print(f"  - Cloud assets: {cloud_count}")
    elif not quiet:
        print("  - (discovery unavailable)")

    if quiet:
        print(
            f"[DREAD] full-scan finished: {len(targets_to_scan)} target(s), "
            f"{failures} failure(s).",
            file=sys.stderr,
        )

    if failures and not quiet:
        print(f"\n[!] {failures} scan(s) failed (see output above).", file=sys.stderr)

    exit_code = 1 if failures else 0

    if suite_base and run_dir and suite_report_flag:
        bs_path = scope_file if scope_file and scope_file.is_file() else None
        brc = _run_suite_reports(
            run_dir=run_dir,
            probe_paths=probe_artifacts,
            scope_path=bs_path,
            formats=suite_formats,
            try_npm=suite_try_npm,
            quiet=quiet,
        )
        if brc != 0:
            print("[!] Reports suite build failed.", file=sys.stderr)
            exit_code = 1
        else:
            suite_json = run_dir / "suite_report" / "dread_suite_report.json"
            if suite_json.is_file():
                try:
                    report_obj = json.loads(suite_json.read_text(encoding="utf-8"))
                    append_history_run(
                        suite_base,
                        run_id=report_obj.get("run_id", run_id or ""),
                        generated_at=report_obj.get("generated_at", ""),
                        primary_target=target,
                        report=report_obj,
                        run_dir_rel=run_dir.name,
                    )
                except (OSError, json.JSONDecodeError) as e:
                    print(f"[!] Could not update suite history: {e}", file=sys.stderr)
                dash = run_dir / "suite_report" / "dashboard"
                _copy_history_to_dashboard(suite_base, dash)
            else:
                print(
                    "[!] Expected suite JSON missing after Reports; check PDF/dashboard errors.",
                    file=sys.stderr,
                )
                exit_code = 1
            if (
                suite_verify_flag
                and suite_json.is_file()
                and DREADAI_PATH
            ):
                vrc = _run_suite_verify(suite_json, quiet=quiet)
                if vrc != 0:
                    print("[!] DreadAI verify reported issues (see above).", file=sys.stderr)
                    exit_code = 1

            if manifest_path and suite_json.is_file():
                update_manifest(
                    manifest_path,
                    suite_report={
                        "output_dir": "suite_report",
                        "master_json": "suite_report/dread_suite_report.json",
                        "dashboard_index": "suite_report/dashboard/index.html",
                    },
                )
    elif is_temp_work_dir and run_dir and probe_artifacts:
        merged_dir = DREAD_DIR / "REPORTS" / f"dread_scan_{run_id}"
        brc = _run_suite_reports(
            run_dir=run_dir,
            out_dir=merged_dir,
            probe_paths=probe_artifacts,
            scope_path=scope_file if scope_file and scope_file.is_file() else None,
            formats="json,html,pdf",
            try_npm=False,
            quiet=quiet,
        )
        if brc != 0:
            print("[!] Merged report build failed.", file=sys.stderr)
            exit_code = 1
        elif not quiet:
            print()
            print("=" * 60)
            print("REPORTS READY")
            print("=" * 60)
            exec_html = merged_dir / "executive_summary.html"
            tech_html = merged_dir / "technical_report.html"
            if exec_html.is_file():
                print(f"  [+] For the client (plain English):  {exec_html}")
            if tech_html.is_file():
                print(f"  [+] For IT / security (full detail): {tech_html}")
            print(f"      All formats in: {merged_dir}")

    if is_temp_work_dir and run_dir:
        shutil.rmtree(run_dir, ignore_errors=True)

    return exit_code


def main() -> int:
    quiet_help = (
        "Less noise: skip suite banners in full-scan; Scope stderr suppressed; "
        "Probe output captured (full-scan/scan echoes it on failure only when quiet)."
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help=quiet_help,
    )
    common.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose output: show every check, URL, and plugin execution.",
    )

    parser = argparse.ArgumentParser(
        description="DREAD - Complete Security Assessment Suite",
        prog="dread",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help=f"{quiet_help} Can also appear after subcommand.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose output: show every check, URL, and plugin execution.",
    )

    subparsers = parser.add_subparsers(dest="command", metavar="<command>", help="Commands")

    products_parser = subparsers.add_parser(
        "products",
        help="List every suite product, status, and summary",
    )
    products_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the suite registry as JSON (for scripts and CI)",
    )

    subparsers.add_parser(
        "version",
        help="Print DREAD suite version string",
    )

    scan_parser = subparsers.add_parser(
        "scan",
        help="Complete assessment (default): discovery + vulnerability scanning",
        parents=[common],
    )
    scan_parser.add_argument("target", help="Target domain")
    scan_parser.add_argument(
        "--max-subdomains",
        "-m",
        type=int,
        default=10,
        help="Maximum subdomains to scan (default: 10)",
    )
    scan_parser.add_argument(
        "--plugins",
        "-p",
        help="Comma-separated Probe plugins (passed through to probe scan)",
    )
    scan_parser.add_argument(
        "--profile",
        help="Probe scan profile: quick, standard, safe-active, full, infrastructure",
    )
    scan_parser.add_argument(
        "--depth",
        type=int,
        help="Crawl depth per host (overrides profile)",
    )
    scan_parser.add_argument(
        "--max-urls",
        type=int,
        help="Maximum URLs to crawl per host (overrides profile)",
    )
    scan_parser.add_argument(
        "--render-js",
        action="store_true",
        help="Render pages in a headless browser to crawl JavaScript/SPA sites "
             "(needs Playwright + Chromium; implied by --profile full)",
    )
    scan_parser.add_argument(
        "--offensive",
        action="store_true",
        help="Aggressive mode for targets you own/are authorized to hammer: full "
             "profile, browser-driven fetch/XHR fuzzing, far more probes, throttles off.",
    )
    scan_parser.add_argument(
        "--ports",
        metavar="SPEC",
        help="Restrict port scanning to this scope (e.g. 3007, 80,443, 1-1000) so a "
             "scan of one port does not wander to others.",
    )
    scan_parser.add_argument(
        "--proxy",
        metavar="URL",
        help="Optional. Route scan traffic through a proxy (http(s)/socks5, optional "
             "user:pass@). Comma-separated values rotate round-robin.",
    )
    scan_parser.add_argument(
        "--proxy-file",
        metavar="PATH",
        help="Optional. File of proxy URLs (one per line) to rotate through.",
    )
    scan_parser.add_argument(
        "--password-spray",
        action="store_true",
        help="Opt-in: after the scan, try a small default-credentials list against any "
             "discovered login form (authorized targets only). Off by default.",
    )
    scan_parser.add_argument(
        "--format",
        "-F",
        metavar="FMT",
        help=(
            "Probe report formats: json, md, pdf, html, all or comma-separated "
            "(default: probe's default if omitted)"
        ),
    )
    scan_parser.add_argument(
        "--suite-out",
        metavar="DIR",
        help=(
            "Write this run under DIR/run_<id>/ (Scope JSON, Probe artifacts, manifest.json)"
        ),
    )
    scan_parser.add_argument(
        "--suite-report",
        action="store_true",
        help=(
            "After scans, build Reports (master JSON + PDF + dashboard) under run dir"
        ),
    )
    scan_parser.add_argument(
        "--suite-verify",
        action="store_true",
        help="Run DreadAI verify on the suite JSON after --suite-report (Reports must succeed)",
    )
    scan_parser.add_argument(
        "--suite-report-formats",
        default="json,pdf,dashboard",
        help="Forwarded to reports build --formats (default: json,pdf,dashboard)",
    )
    scan_parser.add_argument(
        "--suite-try-npm",
        action="store_true",
        help="Forward --try-npm to reports if dashboard dist is missing",
    )

    full_parser = subparsers.add_parser(
        "full-scan",
        parents=[common],
    )
    full_parser.add_argument("target", help=argparse.SUPPRESS)
    full_parser.add_argument("--max-subdomains", "-m", type=int, default=10, help=argparse.SUPPRESS)
    full_parser.add_argument("--plugins", "-p", help=argparse.SUPPRESS)
    full_parser.add_argument("--format", "-F", metavar="FMT", help=argparse.SUPPRESS)
    full_parser.add_argument("--suite-out", metavar="DIR", help=argparse.SUPPRESS)
    full_parser.add_argument("--suite-report", action="store_true", help=argparse.SUPPRESS)
    full_parser.add_argument("--suite-verify", action="store_true", help=argparse.SUPPRESS)
    full_parser.add_argument("--suite-report-formats", default="json,pdf,dashboard", help=argparse.SUPPRESS)
    full_parser.add_argument("--suite-try-npm", action="store_true", help=argparse.SUPPRESS)

    discover_parser = subparsers.add_parser(
        "recon",
        help="Attack surface discovery only",
        parents=[common],
    )
    discover_parser.add_argument("target", help="Target domain")
    discover_parser.add_argument(
        "--output",
        "-o",
        choices=["json", "yaml", "table"],
        default="table",
    )
    discover_alias = subparsers.add_parser(
        "discover",
        parents=[common],
    )
    discover_alias.add_argument("target", help=argparse.SUPPRESS)
    discover_alias.add_argument(
        "--output", "-o", choices=["json", "yaml", "table"], default="table",
        help=argparse.SUPPRESS,
    )

    probe_scan_parser = subparsers.add_parser(
        "hunt",
        help="Web vulnerability scan only",
        parents=[common],
    )
    probe_scan_parser.add_argument("target", help="Target URL/domain")
    probe_scan_parser.add_argument(
        "--plugins",
        "-p",
        help="Comma-separated plugin list",
    )
    probe_scan_parser.add_argument(
        "--format",
        "-F",
        metavar="FMT",
        help=(
            "Report formats: json, md, pdf, html, all or comma-separated "
            "(default: probe default if omitted)"
        ),
    )
    for _alias in ("light-scan", "probe-scan"):
        _p = subparsers.add_parser(_alias, parents=[common])
        _p.add_argument("target", help=argparse.SUPPRESS)
        _p.add_argument("--plugins", "-p", help=argparse.SUPPRESS)
        _p.add_argument("--format", "-F", metavar="FMT", help=argparse.SUPPRESS)

    asn_db_parser = subparsers.add_parser(
        "update-asn-db",
        help=(
            "Refresh Probe ASN allocation DB (HEAD check; skips full download if unchanged)"
        ),
        parents=[common],
    )
    asn_db_parser.add_argument(
        "--force",
        action="store_true",
        help="Always download and rebuild the delegated file from RIPE",
    )
    update_db_parser = subparsers.add_parser(
        "update-db",
        help="Update Probe ASN database",
        parents=[common],
    )
    update_db_parser.add_argument(
        "--force",
        action="store_true",
        help="Always download and rebuild the delegated file from RIPE",
    )
    cve_db_parser = subparsers.add_parser(
        "update-cve-db",
        help="Update Probe CVE database from NVD",
        parents=[common],
    )
    cve_db_parser.add_argument(
        "--days",
        type=int,
        default=None,
        help="Build a publication-window mirror directly from NVD",
    )
    cve_db_parser.add_argument(
        "--years",
        type=int,
        default=None,
        help="Bootstrap CVEs published in the last N years (overrides --days)",
    )
    cve_db_parser.add_argument(
        "--full",
        action="store_true",
        help="Rebuild the full local mirror directly from NVD",
    )
    cve_db_parser.add_argument(
        "--raw-full",
        action="store_true",
        help="Best-effort unfiltered NVD crawl",
    )
    cve_db_parser.add_argument(
        "--snapshot-only",
        action="store_true",
        help="Install the published snapshot without contacting NVD afterward",
    )
    cve_db_parser.add_argument(
        "--no-snapshot",
        action="store_true",
        help="Use direct NVD synchronization without downloading a snapshot",
    )
    subparsers.add_parser(
        "cve-stats",
        help="Show Probe CVE database statistics",
        parents=[common],
    )
    subparsers.add_parser(
        "profiles",
        help="List Probe scan profiles",
        parents=[common],
    )

    for spec in SUITE_PRODUCTS:
        subparsers.add_parser(
            spec.cli_name,
            help=f"{spec.display_name} [{spec.status}]",
        ).add_argument(
            "product_args",
            nargs=argparse.REMAINDER,
            help=argparse.SUPPRESS,
        )

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 1

    quiet = bool(getattr(args, "quiet", False))

    if args.command == "products":
        if getattr(args, "json", False):
            print(
                json.dumps(
                    [dataclasses.asdict(p) for p in SUITE_PRODUCTS],
                    indent=2,
                )
            )
        else:
            print(format_suite_overview())
        return 0

    if args.command == "version":
        print(f"DREAD {SUITE_VERSION}")
        return 0

    if args.command in {"update-asn-db", "update-db"}:
        cmd = [sys.executable, str(PROBE_PATH), "update-asn-db"]
        if getattr(args, "verbose", False):
            cmd.append("-v")
        if getattr(args, "force", False):
            cmd.append("--force")
        return subprocess.run(cmd, cwd=str(PROBE_PATH.parent)).returncode
    if args.command == "update-cve-db":
        cmd = [sys.executable, str(PROBE_PATH), "update-cve-db"]
        if getattr(args, "days", None) is not None:
            cmd.extend(["--days", str(args.days)])
        if getattr(args, "years", None) is not None:
            cmd.extend(["--years", str(args.years)])
        if getattr(args, "full", False):
            cmd.append("--full")
        for flag in ("raw_full", "snapshot_only", "no_snapshot"):
            if getattr(args, flag, False):
                cmd.append(f"--{flag.replace('_', '-')}")
        return subprocess.run(cmd, cwd=str(PROBE_PATH.parent)).returncode
    if args.command == "cve-stats":
        cmd = [sys.executable, str(PROBE_PATH), "cve-stats"]
        return subprocess.run(cmd, cwd=str(PROBE_PATH.parent)).returncode
    if args.command == "profiles":
        cmd = [sys.executable, str(PROBE_PATH), "profiles"]
        return subprocess.run(cmd, cwd=str(PROBE_PATH.parent)).returncode

    delegate_names = {p.cli_name for p in SUITE_PRODUCTS}
    if args.command in delegate_names:
        spec = product_by_cli(args.command)
        assert spec is not None
        script = script_path(spec)
        child = [a for a in (getattr(args, "product_args", None) or []) if a]
        return subprocess.run(
            [sys.executable, str(script)] + child,
            cwd=str(script.parent),
        ).returncode

    if args.command in {"scan", "full-scan"}:
        return full_scan(args.target, args)

    if args.command in {"recon", "discover"}:
        cmd = [
            sys.executable,
            str(SCOPE_PATH),
            "discover",
            args.target,
            "--output",
            args.output,
        ]
        if not quiet:
            cmd.append("--verbose")
        if quiet:
            cmd.append("--quiet")
        out = subprocess.PIPE if quiet else None
        err = subprocess.PIPE if quiet else None
        r = subprocess.run(
            cmd,
            cwd=str(SCOPE_PATH.parent),
            stdout=out,
            stderr=err,
            text=True,
        )
        if quiet and r.stdout:
            sys.stdout.write(r.stdout)
        if quiet and r.stderr:
            sys.stderr.write(r.stderr)
        return r.returncode

    if args.command in {"hunt", "light-scan", "probe-scan"}:
        verbose = bool(getattr(args, "verbose", False))
        cmd = [sys.executable, str(PROBE_PATH), "scan", args.target]
        if verbose:
            cmd.append("-v")
        if args.plugins:
            cmd.extend(["--plugins", args.plugins])
        fmt = getattr(args, "format", None)
        if fmt and fmt.strip():
            cmd.extend(["--format", fmt.strip()])
        if quiet:
            r = subprocess.run(
                cmd,
                cwd=str(PROBE_PATH.parent),
                capture_output=True,
                text=True,
            )
            if r.stdout:
                sys.stdout.write(r.stdout)
            if r.stderr:
                sys.stderr.write(r.stderr)
            return r.returncode
        return subprocess.run(cmd, cwd=str(PROBE_PATH.parent)).returncode

    return 0


def _bootstrap_env_and_venv() -> None:
    """Make `./dread.py` and the installed `dread` launcher behave the same.

    Load .env (so keys like NVD_API_KEY are present) and re-exec under the project
    venv when invoked with a different interpreter, so system python missing deps is
    never a problem. Set DREAD_NO_REEXEC=1 to opt out.
    """
    from env_loader import load_env_file

    repo = Path(__file__).resolve().parent
    load_env_file(repo / ".env")
    venv_dir = repo / ".venv"
    venv_py = venv_dir / "bin" / "python"
    if not venv_py.exists():
        venv_py = venv_dir / "bin" / "python3"
    if (
        venv_py.exists()
        and Path(sys.prefix).resolve() != venv_dir.resolve()
        and not os.environ.get("DREAD_NO_REEXEC")
    ):
        os.execv(str(venv_py), [str(venv_py), str(repo / "dread.py"), *sys.argv[1:]])


if __name__ == "__main__":
    _bootstrap_env_and_venv()
    sys.exit(main())
