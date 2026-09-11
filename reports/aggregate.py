"""Load Probe / Scope artifacts and build a unified suite report dict."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_TITLE_PREFIX = "Recon/Vuln Analysis - Report Findings"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _report_date(generated_at: str) -> str:
    """Cover-page date ("September 11, 2026") in the generating machine's local time."""
    dt = datetime.fromisoformat(generated_at).astimezone()
    return f"{dt:%B} {dt.day}, {dt.year}"


def _load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: root must be an object")
    return data


def ingest_probe_paths(paths: list[Path]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for p in paths:
        out.append(_load_json(p))
    return out


def ingest_scope(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    return _load_json(path)


VULNERABILITY_SEVERITIES = ("critical", "high", "medium", "low")
_RISK_ORDER = ("none", "info", "low", "medium", "high", "critical")


def _classify(finding: dict[str, Any]) -> str:
    """
    Same rule as probe's engine._generate_report: edge infrastructure, "warning"
    class and info-severity findings are observations (reported, never counted as
    vulnerabilities); everything else is a vulnerability.
    """
    if finding.get("edge_infrastructure"):
        return "observation"
    if (finding.get("metadata") or {}).get("classification") == "warning":
        return "observation"
    if str(finding.get("severity", "info")).lower() == "info":
        return "observation"
    return "vulnerability"


def _normalize_probe_finding(
    scan_id: str,
    idx: int,
    finding: dict[str, Any],
    source_label: str,
) -> dict[str, Any]:
    sev = str(finding.get("severity", "info")).lower()
    return {
        "id": f"probe:{scan_id}:{idx}",
        "source_product": "probe",
        "source_artifact": source_label,
        "source_scan_id": scan_id,
        "severity": sev,
        "classification": _classify(finding),
        "title": finding.get("title", ""),
        "url": finding.get("url", ""),
        "plugin_name": finding.get("plugin_name", ""),
        "description": finding.get("description", "")[:2000],
        "remediation": finding.get("remediation", ""),
        "evidence": finding.get("evidence") or {},
        "affected_endpoints": finding.get("affected_endpoints") or [],
        "attack_scenario": finding.get("attack_scenario", ""),
        "defense_strategy": finding.get("defense_strategy", ""),
        "mitigation_plan": finding.get("mitigation_plan", ""),
        "risk_score": finding.get("risk_score"),
        "adjusted_risk_score": finding.get("adjusted_risk_score"),
    }


def _overall_risk(scans: list[dict[str, Any]]) -> str:
    """Worst per-scan risk level as computed by probe; never recomputed here."""
    levels = [
        str(((s.get("statistics") or {}).get("risk") or {}).get("level", "none")).lower()
        for s in scans
    ]
    ranked = [lvl for lvl in levels if lvl in _RISK_ORDER]
    return max(ranked, key=_RISK_ORDER.index, default="none")


def build_unified_report(
    *,
    reports_schema_version: str,
    run_id: str,
    title: str,
    probe_reports: list[tuple[str, dict[str, Any]]],
    scope_report: dict[str, Any] | None,
    include_probe: bool,
    include_scope: bool,
) -> dict[str, Any]:
    """
    probe_reports: list of (label, payload) e.g. file stem + loaded json
    """
    findings: list[dict[str, Any]] = []
    findings_by_severity: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    findings_by_plugin: dict[str, int] = {}

    sources: dict[str, Any] = {
        "probe": {"included": include_probe, "scans": []},
        "scope": {"included": bool(include_scope and scope_report), "summary": None},
    }

    # Overlapping scans (e.g. two names for the same host) return the same finding
    # more than once; the customer should see each issue exactly once.
    seen_findings: set[tuple[str, str, str, str]] = set()

    if include_probe:
        for label, rep in probe_reports:
            scan_id = str(rep.get("scan_id", "unknown"))
            targets = rep.get("target", "")
            stats = rep.get("statistics") or {}
            sources["probe"]["scans"].append(
                {
                    "artifact": label,
                    "scan_id": scan_id,
                    "target": targets,
                    "statistics": stats,
                    "finding_count": len(rep.get("findings") or []),
                }
            )
            for i, f in enumerate(rep.get("findings") or []):
                if not isinstance(f, dict):
                    continue
                nf = _normalize_probe_finding(scan_id, i, f, label)
                key = (nf["severity"], nf["plugin_name"], nf["title"], nf["url"])
                if key in seen_findings:
                    continue
                seen_findings.add(key)
                findings.append(nf)
                sev = nf["severity"]
                if sev in findings_by_severity:
                    findings_by_severity[sev] += 1
                else:
                    findings_by_severity["info"] += 1
                plug = nf["plugin_name"] or "unknown"
                findings_by_plugin[plug] = findings_by_plugin.get(plug, 0) + 1

    if include_scope and scope_report:
        disc = scope_report.get("discovery") or {}
        sub = disc.get("subdomains") or {}
        cloud = disc.get("cloud_assets") or {}
        takeovers = disc.get("subdomain_takeover") or []
        sources["scope"]["summary"] = {
            "domain": scope_report.get("domain"),
            "subdomain_count": len(sub.get("all_unique") or []),
            "cloud_bucket_counts": {
                k: len(v) for k, v in cloud.items() if isinstance(v, list)
            },
            "subdomain_takeover_count": len(takeovers),
        }
        # A dangling-CNAME takeover is a real, high-impact vulnerability; promote each
        # into the findings register so it counts and appears in both reports.
        for i, t in enumerate(takeovers):
            if not isinstance(t, dict):
                continue
            sev = str(t.get("severity", "high")).lower()
            findings.append({
                "id": f"scope:takeover:{i}",
                "source_product": "scope",
                "source_artifact": "scope",
                "source_scan_id": "scope",
                "severity": sev,
                "classification": "vulnerability",
                "title": f"Subdomain takeover: {t.get('subdomain', '')}",
                "url": t.get("subdomain", ""),
                "plugin_name": "subdomain_takeover",
                "description": t.get("detail", "")[:2000],
                "remediation": (
                    "Remove the dangling DNS record or reclaim the target resource at "
                    f"{t.get('service', 'the provider')} before an attacker registers it."
                ),
                "evidence": {"cname": t.get("cname", ""), "service": t.get("service", "")},
                "affected_endpoints": [t.get("subdomain", "")],
                "attack_scenario": "", "defense_strategy": "", "mitigation_plan": "",
                "risk_score": None, "adjusted_risk_score": None,
            })
            if sev in findings_by_severity:
                findings_by_severity[sev] += 1
            findings_by_plugin["subdomain_takeover"] = findings_by_plugin.get("subdomain_takeover", 0) + 1

    vulnerabilities = [f for f in findings if f["classification"] == "vulnerability"]
    checks_performed = list(
        dict.fromkeys(
            check
            for _, rep in (probe_reports if include_probe else [])
            for check in (rep.get("statistics") or {}).get("checks_performed") or []
        )
    )
    generated_at = _utc_now_iso()
    target = next(
        (s["target"] for s in sources["probe"]["scans"] if s["target"]),
        (sources["scope"]["summary"] or {}).get("domain") or "",
    )

    return {
        "reports_schema_version": reports_schema_version,
        "suite": "DREAD",
        "report_type": "unified_suite",
        "title": title or f"{DEFAULT_TITLE_PREFIX} - {_report_date(generated_at)}",
        "target": target,
        "checks_performed": checks_performed,
        "run_id": run_id,
        "generated_at": generated_at,
        "sources": sources,
        "rollups": {
            "total_findings": len(findings),
            "findings_by_severity": findings_by_severity,
            "vulnerability_count": len(vulnerabilities),
            "observation_count": len(findings) - len(vulnerabilities),
            "vulnerabilities_by_severity": {
                sev: sum(1 for f in vulnerabilities if f["severity"] == sev)
                for sev in VULNERABILITY_SEVERITIES
            },
            "overall_risk": _overall_risk(sources["probe"]["scans"]),
            "findings_by_plugin": dict(
                sorted(findings_by_plugin.items(), key=lambda kv: -kv[1])
            ),
        },
        "findings": findings,
        "raw_embed": {
            "probe": [r for _, r in probe_reports] if include_probe else [],
            "scope": scope_report if include_scope else None,
        },
    }


def aggregate_from_cli_inputs(
    *,
    probe_paths: list[Path],
    scope_path: Path | None,
    include: frozenset[str],
    report_title: str,
    schema_version: str,
) -> dict[str, Any]:
    run_id = str(uuid.uuid4())
    include_bp = "probe" in include and bool(probe_paths)
    include_bs = "scope" in include and scope_path is not None

    bp_payloads: list[tuple[str, dict[str, Any]]] = []
    if probe_paths:
        for p in probe_paths:
            bp_payloads.append((p.stem, _load_json(p)))

    bs_payload = ingest_scope(scope_path) if scope_path else None

    return build_unified_report(
        reports_schema_version=schema_version,
        run_id=run_id,
        title=report_title,
        probe_reports=bp_payloads,
        scope_report=bs_payload,
        include_probe=include_bp,
        include_scope=bool(include_bs and bs_payload),
    )
