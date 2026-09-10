"""DreadAI agent: a LangGraph agent that drives the DREAD suite."""

from __future__ import annotations

import os
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
_PROBE = _REPO / "probe"
_REPORTS = _REPO / "reports"
_CANNON = _REPO / "cannon"
for _p in (_REPO, _PROBE, _REPORTS, _CANNON):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from langchain_anthropic import ChatAnthropic
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent

MODEL = os.environ.get("DREADAI_MODEL", "claude-sonnet-5")

SYSTEM = (
    "You are DreadAI, the security orchestration agent for DREAD, a professional-grade "
    "security assessment suite. You run vulnerability scans and penetration testing against "
    "authorized targets, correlate CVE intelligence, verify or rule out findings, and produce "
    "assessment reports. Use the available tools to carry out the operator's request, chaining "
    "them as a security professional would: scan, confirm what is real, and report. Operate only "
    "against targets the operator states they are authorized to test."
)


@tool
def scan_target(target: str, profile: str = "quick") -> dict:
    """Run a Probe scan against an authorized target and return a summary.

    profile is one of the Probe scan profiles. "quick" is the lightest.
    """
    from scanner.config import SCAN_PROFILES, ScanConfig
    from scanner.engine import ScanEngine

    if profile not in SCAN_PROFILES:
        return {"error": f"unknown profile {profile!r}", "profiles": sorted(SCAN_PROFILES)}
    try:
        report = ScanEngine(ScanConfig(target_url=target, profile=profile)).run_scan()
    except Exception as exc:
        return {"error": str(exc), "target": target}
    stats = report.get("statistics", {})
    return {
        "scan_id": report.get("scan_id"),
        "target": report.get("target", target),
        "total_findings": stats.get("total_findings"),
        "findings_by_severity": stats.get("findings_by_severity", {}),
    }


@tool
def fetch_cve(cve_id: str) -> dict:
    """Look up one CVE by id in the local DREAD CVE store."""
    from scanner.cve_db_manager import get_cve_by_id

    try:
        entry = get_cve_by_id(cve_id)
    except FileNotFoundError as exc:
        return {"cve_id": cve_id, "error": str(exc)}
    if entry is None:
        return {"cve_id": cve_id, "found": False}
    return {"found": True, **entry}


def _probe(url: str) -> dict:
    import requests

    resp = requests.get(url, timeout=15)
    return {"status": resp.status_code, "body": resp.text}


@tool
def verify_vulnerability(url: str, evidence: str) -> dict:
    """Confirm a finding by re-fetching its URL and checking the evidence still appears."""
    try:
        probe = _probe(url)
    except Exception as exc:
        return {"url": url, "error": str(exc)}
    present = evidence in probe["body"]
    return {"url": url, "status": probe["status"], "evidence_present": present, "confirmed": present}


@tool
def rule_out_false_positive(url: str, evidence: str) -> dict:
    """Judge a candidate finding as a false positive when its evidence no longer holds."""
    try:
        probe = _probe(url)
    except Exception as exc:
        return {"url": url, "error": str(exc)}
    present = evidence in probe["body"]
    return {"url": url, "status": probe["status"], "false_positive": not present}


@tool
def generate_report(target: str, findings: list[dict]) -> dict:
    """Write a unified suite JSON report for the given findings and return its path."""
    from datetime import datetime, timezone

    from writers.json_writer import write_suite_json

    by_severity: dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        by_severity[sev] = by_severity.get(sev, 0) + 1
    report = {
        "report_type": "unified_suite",
        "run_id": f"dreadai_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sources": ["dreadai"],
        "target": target,
        "findings": findings,
        "rollups": {"total_findings": len(findings), "findings_by_severity": by_severity},
    }
    path = write_suite_json(report, _REPO / "reports", report["run_id"])
    return {"report_path": str(path), "total_findings": len(findings)}


@tool
def run_pentest(target: str, tools: list[str] | None = None, heavy: bool = False) -> dict:
    """Wield Cannon against an authorized target: DREAD's active pentest engine.

    DreadAI drives Cannon directly, past the fixed menu a human operator is limited to.
    Pass `tools` to run specific cataloged tools by name, or leave empty to run every
    installed tool. Set heavy to escalate the load tools. Call again to adapt on results.
    """
    import catalog as bc_catalog
    import runner as bc_runner

    if target.startswith("-"):
        return {"error": f"refusing target {target!r}: cannot begin with '-'"}
    cat = bc_catalog.load_catalog()
    chosen = (
        [t for t in (bc_catalog.by_name(name, cat) for name in tools) if t is not None]
        if tools
        else list(cat)
    )
    results = []
    for tool_entry in chosen:
        if bc_runner.which(tool_entry.binary) is None:
            results.append({"tool": tool_entry.name, "skipped": "not installed"})
            continue
        argv = bc_catalog.build_argv(tool_entry, target, heavy=heavy and tool_entry.category == "load")
        outcome = bc_runner.run(tool_entry.name, argv)
        results.append({
            "tool": tool_entry.name,
            "returncode": outcome.returncode,
            "timed_out": outcome.timed_out,
            "duration": outcome.duration,
            "stdout": outcome.stdout[-2000:],
        })
    return {"target": target, "heavy": heavy, "results": results}


TOOLS = [scan_target, fetch_cve, verify_vulnerability, rule_out_false_positive, generate_report, run_pentest]


def build_agent():
    return create_react_agent(ChatAnthropic(model=MODEL), TOOLS, prompt=SYSTEM)


def ask(prompt: str) -> str:
    result = build_agent().invoke({"messages": [("user", prompt)]})
    return result["messages"][-1].content
