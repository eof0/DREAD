from scanner.config import ScanConfig
from scanner.auth import build_handler
from scanner.crawler import Crawler
from scanner.analysis.attack_chain_engine import build_attack_chains
from scanner.analysis.findings import group_findings
from scanner.analysis.prioritization import prioritize_findings
from scanner.reporting.reporter import Reporter

from typing import List, Dict, Any
import importlib
import time
from datetime import datetime
import json
import os
import re
from urllib.parse import urlparse
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import logging

try:
    from rich.console import Console
    from rich.table import Table
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from scanner.update_notifier import check_and_notify
from scanner.asn_db_updater import refresh_asn_db_before_scan


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def _pending_plugin_status(pending, future_to_task, now=None) -> str:
    now = time.monotonic() if now is None else now
    names = sorted({future_to_task[future][0].get_name() for future in pending})
    oldest = min(future_to_task[future][2] for future in pending)
    return f"{', '.join(names)} ({int(now - oldest)}s elapsed)"


class ColoredConsole:
    """Wrapper for console output with optional color support."""
    
    def __init__(self):
        self.rich_console = Console() if RICH_AVAILABLE else None
        self._severity_colors = {
            'critical': 'bold red',
            'high': 'red',
            'medium': 'yellow',
            'low': 'blue',
            'info': 'dim',
        }
    
    def print(self, message: str, style: str = None):
        """Print message with optional styling."""
        if self.rich_console:
            self.rich_console.print(message, style=style)
        else:
            print(message)
    
    def info(self, message: str):
        """Print info message."""
        if self.rich_console:
            self.rich_console.print(f"[*] {message}", style="cyan")
        else:
            print(f"[*] {message}")
    
    def success(self, message: str):
        """Print success message."""
        if self.rich_console:
            self.rich_console.print(f"[+] {message}", style="green")
        else:
            print(f"[+] {message}")
    
    def warning(self, message: str):
        """Print warning message."""
        if self.rich_console:
            self.rich_console.print(f"[!] {message}", style="yellow")
        else:
            print(f"[!] {message}")

    def wait_hint(self, message: str = "Please wait... still processing."):
        """Print a yellow wait hint during long-running operations."""
        self.warning(message)
    
    def error(self, message: str):
        """Print error message."""
        if self.rich_console:
            self.rich_console.print(f"[✗] {message}", style="bold red")
        else:
            print(f"[✗] {message}")

    def asn_db_refresh_hint(self, stale_message: str) -> None:
        """Show ASN refresh guidance."""
        cmd = "dread update-db"
        alt = "dread probe update-asn-db"
        if self.rich_console:
            self.rich_console.print(f"[!] {stale_message}", style="bold red")
            self.rich_console.print(
                "[*] Public IP delegation data may be stale until you refresh.",
                style="dim",
            )
            self.rich_console.print("    Run ", style="dim", end="")
            self.rich_console.print(cmd, style="bold green", end="")
            self.rich_console.print("  (same as ", style="dim", end="")
            self.rich_console.print(alt, style="green", end="")
            self.rich_console.print(")", style="dim")
        else:
            print(f"\033[31m[!] {stale_message}\033[0m")
            print(
                f"[*] Run \033[1m\033[32m{cmd}\033[0m "
                f"(same as \033[32m{alt}\033[0m)"
            )
    
    def plugin_result(self, plugin_name: str, count: int):
        """Print plugin finding result."""
        if self.rich_console:
            color = "red" if count > 0 else "green"
            self.rich_console.print(
                f"  [!] {plugin_name}: Found {count} issue(s)",
                style=color
            )
        else:
            print(f"  [!] {plugin_name}: Found {count} issue(s)")
    
    def print_summary_table(self, report: Dict):
        """Print formatted summary table."""
        stats = report.get("statistics", {})
        risk = stats.get("risk", {})
        vuln_total = stats.get('total_findings', 0)
        warning_total = stats.get('warning_findings', 0)
        info_total = stats.get('informational_findings', 0)
        edge_total = stats.get('edge_infrastructure_findings', 0)
        total_with_edge = stats.get('total_findings_with_edge', vuln_total + edge_total)
        
        if self.rich_console:
            table = Table(
                title="Scan Summary",
                box=box.DOUBLE_EDGE,
                show_header=True,
                header_style="bold cyan"
            )
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="white")
            
            table.add_row("Scan ID", report['scan_id'])
            table.add_row("Target", report['target'])
            table.add_row("Duration", f"{stats.get('duration_seconds')} seconds")
            table.add_row("URLs Scanned", str(stats.get('urls_scanned')))
            table.add_row(
                "Risk Score",
                f"{stats.get('overall_risk_score')} (raw: {risk.get('raw_score', 0)})"
            )
            table.add_row("Risk Level", risk.get('level', 'unknown').upper())
            
            self.rich_console.print(table)
            
            sev_table = Table(title="Vulnerabilities", box=box.SIMPLE)
            sev_table.add_column("Severity", style="bold")
            sev_table.add_column("Count", justify="right")
            
            for severity, count in stats.get("findings_by_severity", {}).items():
                if count > 0:
                    style = self._severity_colors.get(severity, 'white')
                    sev_table.add_row(severity.upper(), str(count), style=style)
            
            self.rich_console.print(sev_table)
            
            if info_total > 0:
                self.rich_console.print(
                    f"\nInformational Findings: {info_total}  "
                    f"(listed for awareness — not counted as vulnerabilities)",
                    style="dim"
                )
            if edge_total > 0:
                self.rich_console.print(
                    f"Edge Infrastructure Findings: {edge_total}  "
                    f"(included as INFO — not counted as vulnerabilities)",
                    style="dim"
                )
            self.rich_console.print(
                f"\nTotal Vulnerabilities: {vuln_total}  "
                f"(+ {warning_total} hardening/warnings, {info_total} informational, "
                f"{edge_total} edge infrastructure)",
                style="bold"
            )
        else:
            print("\n" + "=" * 70)
            print("SCAN SUMMARY")
            print("=" * 70)
            print(f"Scan ID: {report['scan_id']}")
            print(f"Target: {report['target']}")
            print(f"Duration: {stats.get('duration_seconds')} seconds")
            print(f"URLs Scanned: {stats.get('urls_scanned')}")
            print(
                "Overall Risk Score: "
                f"{stats.get('overall_risk_score')} "
                f"(raw: {risk.get('raw_score', 0)})"
            )

            print("\nVulnerabilities by Severity:")
            for severity, count in stats.get("findings_by_severity", {}).items():
                if count > 0:
                    print(f"  {severity.upper()}: {count}")

            print(f"\nTotal Vulnerabilities: {vuln_total}")
            if warning_total > 0:
                print(f"Hardening / Warnings (INFO): {warning_total}  (not counted as vulnerabilities)")
            if info_total > 0:
                print(f"Informational (INFO): {info_total}  (not counted as vulnerabilities)")
            if edge_total > 0:
                print(f"Edge Infrastructure (INFO): {edge_total}  "
                      f"(not counted as vulnerabilities)")


class ScanEngine:
    """
    Probe Scan Engine with parallel plugin execution and robust error handling.

    Features:
    - Parallel plugin execution using ThreadPoolExecutor
    - Graceful plugin crash handling
    - Colored console output
    - Comprehensive logging
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self.verbose = getattr(config, 'verbose', False)
        self.request_handler = build_handler(
            config.rate_limit,
            self.verbose,
            auth=getattr(config, "auth", None),
            cookies=getattr(config, "cookies", None),
            headers=getattr(config, "extra_headers", None),
        )
        secondary_auth = getattr(config, "auth_secondary", None)
        if secondary_auth:
            self.request_handler.secondary = build_handler(
                config.rate_limit,
                self.verbose,
                auth=secondary_auth,
                cookies=secondary_auth.get("cookies"),
            )
        self.crawler = Crawler(
            config.target_url,
            config.depth,
            config.max_urls,
            verbose=self.verbose
        )
        self.plugins = []
        self.findings = []
        self.scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.console = ColoredConsole()
        self.max_workers = getattr(config, 'parallel_workers', 8)

    def load_plugins(self):
        """Load and initialize all enabled plugins."""
        plugin_map = {
            "fingerprinting": "plugins.fingerprinting.FingerprintingPlugin",
            "security_headers": "plugins.security_headers.SecurityHeadersPlugin",
            "sensitive_files": "plugins.sensitive_files.SensitiveFilesPlugin",
            "wordpress_scan": "plugins.wordpress_scan.WordPressScanPlugin",
            "access_control": "plugins.access_control.AccessControlPlugin",
            "web_vulnerabilities": "plugins.web_vulnerabilities.WebVulnerabilitiesPlugin",
            "cve_correlation": "plugins.cve_correlation.CVECorrelationPlugin",
            "network_scanner": "plugins.network_scanner.NetworkScannerPlugin",
            "tls_analysis": "plugins.tls_analysis.TLSAnalysisPlugin",
            "infrastructure": "plugins.infrastructure_intel.InfrastructureIntelPlugin",
        }

        for plugin_name in self.config.enabled_plugins:
            if plugin_name in plugin_map:
                try:
                    module_path, class_name = plugin_map[plugin_name].rsplit(".", 1)
                    module = importlib.import_module(module_path)
                    plugin_class = getattr(module, class_name)
                    plugin = plugin_class()
                    self.plugins.append(plugin)
                    self.console.success(f"Loaded plugin: {plugin.get_name()}")
                    if self.verbose:
                        self.console.info(f"  Plugin description: {plugin.get_description()}")
                except Exception as e:
                    self.console.error(f"Failed to load plugin {plugin_name}: {e}")
                    logger.error(f"Plugin load failed: {plugin_name}", exc_info=True)

    def _safe_plugin_scan(self, plugin, url_info: Dict[str, Any]) -> tuple:
        """
        Execute plugin scan with comprehensive error handling.

        Returns:
            Tuple of (plugin_name, findings_list, error_message)
        """
        plugin_name = plugin.get_name()
        try:
            if url_info.get("response") is None:
                return (plugin_name, [], None)
            if self.verbose:
                self.console.info(f"[VERBOSE] Running plugin '{plugin_name}' on {url_info['url']}")
            logger.debug(f"Running plugin {plugin_name} on {url_info['url']}")
            findings = plugin.scan(url_info, self.request_handler)
            
            if findings is None:
                logger.warning(f"Plugin {plugin_name} returned None, converting to empty list")
                findings = []
            
            return (plugin_name, findings, None)
            
        except Exception as e:
            logger.error(f"Plugin {plugin_name} crashed on {url_info['url']}: {e}", exc_info=True)
            return (plugin_name, [], str(e))

    def run_scan(self):
        """
        Execute full scan workflow with parallel plugin execution.
        
        Returns:
            Complete scan report dictionary
        """
        self.console.info(f"Starting scan: {self.scan_id}")
        self.console.info(f"Target: {self.config.target_url}")

        check_and_notify()
        refresh_asn_db_before_scan(verbose=self.verbose)

        start_time = time.time()

        self.load_plugins()
        
        if not self.plugins:
            self.console.error("No plugins loaded - scan cannot continue")
            raise RuntimeError("No plugins loaded")

        self.console.info("Phase 1: Crawling target...")
        if self.verbose:
            self.console.info(f"[VERBOSE] Crawl config: depth={self.config.depth}, max_urls={self.config.max_urls}")
        urls = self.crawler.crawl(self.request_handler)
        
        if not urls:
            self.console.warning("No URLs discovered during crawling")

        self.console.info(f"Phase 2: Running {len(self.plugins)} plugins on {len(urls)} URLs...")
        
        total_tasks = len(urls) * len(self.plugins)
        completed_tasks = 0
        failed_plugins = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_task = {}
            for url_info in urls:
                for plugin in self.plugins:
                    future = executor.submit(self._safe_plugin_scan, plugin, url_info)
                    future_to_task[future] = (plugin, url_info, time.monotonic())
            
            pending = set(future_to_task.keys())
            while pending:
                done, pending = wait(
                    pending,
                    timeout=5.0,
                    return_when=FIRST_COMPLETED,
                )

                if not done:
                    status = _pending_plugin_status(pending, future_to_task)
                    self.console.wait_hint(f"Still running: {status}")
                    self.console.info(
                        f"Progress: {completed_tasks}/{total_tasks} tasks complete "
                        f"({len(pending)} still running)"
                    )
                    continue

                for future in done:
                    plugin, url_info, _ = future_to_task[future]
                    completed_tasks += 1

                    try:
                        plugin_name, findings, error = future.result()

                        if error:
                            failed_plugins.append((plugin_name, url_info['url'], error))
                            self.console.error(
                                f"[{completed_tasks}/{total_tasks}] {plugin_name} failed on {url_info['url']}: {error}"
                            )
                        else:
                            self.findings.extend(findings)
                            if findings:
                                self.console.plugin_result(plugin_name, len(findings))
                                if self.verbose:
                                    for finding in findings:
                                        self.console.info(f"    [FINDING] {finding.severity.upper()}: {finding.title}")
                                logger.info(f"{plugin_name} found {len(findings)} issues on {url_info['url']}")
                            else:
                                if self.verbose:
                                    self.console.info(f"  [{completed_tasks}/{total_tasks}] {plugin_name} on {url_info['url']}: No issues")
                                logger.debug(f"{plugin_name} found no issues on {url_info['url']}")

                        if completed_tasks % 10 == 0 or completed_tasks == total_tasks:
                            self.console.info(
                                f"Progress: {completed_tasks}/{total_tasks} tasks complete"
                            )

                    except Exception as e:
                        logger.error(f"Unexpected error processing task: {e}", exc_info=True)

        if failed_plugins:
            self.console.warning(f"{len(failed_plugins)} plugin executions failed")
            for plugin_name, url, error in failed_plugins[:5]:
                logger.error(f"  - {plugin_name} on {url}: {error}")

        duration = time.time() - start_time

        grouped_findings = group_findings([f.to_dict() for f in self.findings])
        self.console.info("Building attack chains...")
        attack_chains = build_attack_chains(
            [
                finding
                for finding in grouped_findings
                if finding.get("metadata", {}).get("classification") != "warning"
            ]
        )

        self.console.info("Generating report...")
        report = self._generate_report(duration, attack_chains, grouped_findings)
        output_name = self.config.output_name or self._default_output_name()
        
        try:
            artifacts = Reporter.write(
                report=report,
                output_name=output_name,
                formats=self.config.output_formats,
                output_dir=self.config.output_dir,
            )
        except Exception as e:
            logger.error(f"Report generation failed: {e}", exc_info=True)
            raise RuntimeError(f"Report generation failed: {e}")

        if not artifacts:
            raise RuntimeError("Report generation produced no artifacts")

        self._print_summary(report)
        self.console.success("Artifacts written:")
        for artifact in artifacts:
            self.console.print(f"  - {artifact}", style="green")

        return report

    def _generate_report(
        self,
        duration: float,
        attack_chains: List[Dict],
        grouped_findings: List[Dict] | None = None,
    ) -> Dict:
        if grouped_findings is None:
            grouped_findings = group_findings([f.to_dict() for f in self.findings])
        prioritized = prioritize_findings(grouped_findings)
        all_findings = prioritized["findings"]

        # Separate observations and edge infrastructure from vulnerabilities.
        # Only findings with a real severity (low..critical) that are not edge
        # infrastructure and not informational "warning" observations count as
        # vulnerabilities. info-severity findings are still reported, just not
        # counted or scored.
        edge_findings = [f for f in all_findings if f.get("edge_infrastructure")]
        warning_findings = [
            f for f in all_findings
            if not f.get("edge_infrastructure")
            and f.get("metadata", {}).get("classification") == "warning"
        ]
        info_findings = [
            f for f in all_findings
            if not f.get("edge_infrastructure")
            and f.get("metadata", {}).get("classification") != "warning"
            and f.get("severity") == "info"
        ]
        vuln_findings = [
            f for f in all_findings
            if not f.get("edge_infrastructure")
            and f.get("metadata", {}).get("classification") != "warning"
            and f.get("severity") != "info"
        ]

        # Edge findings are always informational-only
        for f in edge_findings:
            f["severity"] = "info"
            f["adjusted_risk_score"] = 0.0

        findings_by_severity = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        for finding in vuln_findings:
            findings_by_severity[finding["severity"]] += 1

        # Risk score from vulnerabilities only (edge findings contribute 0)
        adjusted_risk = sum(f.get("adjusted_risk_score", 0) for f in vuln_findings)
        raw_risk = sum(f.get("raw_risk_score", 0) for f in vuln_findings)
        normalized_risk = min(adjusted_risk, 100.0)
        risk_level = self._risk_level(normalized_risk, len(vuln_findings))

        # Recompute prioritized dict values for vuln-only
        prioritized["raw_risk_score"] = round(raw_risk, 2)
        prioritized["adjusted_risk_score"] = round(adjusted_risk, 2)
        prioritized["findings"] = all_findings

        return {
            "scan_id": self.scan_id,
            "target": self.config.target_url,
            "timestamp": datetime.now().isoformat(),
            "findings": all_findings,
            "attack_chains": attack_chains,
            "statistics": {
                "urls_scanned": len(self.crawler.visited_urls),
                "duration_seconds": round(duration, 2),
                "findings_by_severity": findings_by_severity,
                "total_findings": len(vuln_findings),
                "warning_findings": len(warning_findings),
                "informational_findings": len(info_findings),
                "edge_infrastructure_findings": len(edge_findings),
                "total_findings_with_edge": len(all_findings),
                "overall_risk_score": round(normalized_risk, 2),
                "risk": {
                    "level": risk_level,
                    "raw_score": raw_risk,
                    "adjusted_score": adjusted_risk,
                    "normalized_score": round(normalized_risk, 2),
                },
            },
        }

    def _default_output_name(self) -> str:
        parsed = urlparse(self.config.target_url)
        base = parsed.netloc or parsed.path or self.config.target_url
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", base).strip("._-")
        if not safe:
            safe = "scan"
        return f"{safe}_{self.scan_id}"

    @staticmethod
    def _risk_level(score: float, total_findings: int) -> str:
        if total_findings == 0:
            return "none"
        if score >= 75:
            return "critical"
        if score >= 50:
            return "high"
        if score >= 25:
            return "medium"
        if score >= 10:
            return "low"
        return "info"

    def _print_summary(self, report: Dict):
        """Print formatted scan summary."""
        self.console.print_summary_table(report)
