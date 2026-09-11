from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from writers import cloud_storage_checked

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
_SEVERITY_COLOR = {
    "critical": "#b02a37",
    "high": "#c8582b",
    "medium": "#b8860b",
    "low": "#3f7d58",
    "info": "#3a6ea5",
}


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def _rank(severity: str) -> int:
    try:
        return _SEVERITY_ORDER.index(severity.lower())
    except ValueError:
        return len(_SEVERITY_ORDER)


def write_suite_html(report: dict[str, Any], output_dir: Path, base_name: str) -> Path:
    """Render the customer-facing report as one self-contained, print-friendly HTML file."""
    output_dir.mkdir(parents=True, exist_ok=True)
    html_path = output_dir / f"{base_name}.html"

    roll = report.get("rollups") or {}
    fbs = roll.get("findings_by_severity") or {}
    vuln_count = roll.get("vulnerability_count", 0)
    obs_count = roll.get("observation_count", 0)

    def _sorted(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return sorted(
            items,
            key=lambda f: (_rank(str(f.get("severity", "info"))), str(f.get("plugin_name", ""))),
        )

    all_findings = report.get("findings") or []
    vulnerabilities = _sorted([f for f in all_findings if f.get("classification") == "vulnerability"])
    observations = _sorted([f for f in all_findings if f.get("classification") != "vulnerability"])
    title = _esc(report.get("title") or "Recon/Vuln Analysis - Report Findings")
    target = _esc(report.get("target") or "")
    subtitle = f'<p class="subtitle">{target}</p>' if target else ""

    vbs = roll.get("vulnerabilities_by_severity") or {}
    chips = "".join(
        f'<span class="chip sev-{s}">{s}: {vbs.get(s, fbs.get(s, 0))}</span>'
        for s in ("critical", "high", "medium", "low")
    )

    # Customer-facing: describe what was assessed, never which internal tool did it.
    src = report.get("sources") or {}
    scope_blocks: list[str] = []
    bp = src.get("probe") or {}
    if bp.get("included"):
        rows = "".join(
            f"<tr><td class='mono'>{_esc(s.get('target'))}</td><td>{_esc(s.get('finding_count'))}</td></tr>"
            for s in (bp.get("scans") or [])
        )
        scope_blocks.append(
            "<h3>Hosts tested</h3><table class='src'><thead><tr><th>Host</th>"
            f"<th>Findings</th></tr></thead><tbody>{rows}</tbody></table>"
        )
    bs = src.get("scope") or {}
    if bs.get("included"):
        summ = bs.get("summary") or {}
        buckets = cloud_storage_checked(summ)
        scope_blocks.append(
            f"<h3>Attack surface discovery</h3><p>Subdomains discovered: "
            f"<strong>{_esc(summ.get('subdomain_count', 0))}</strong>. Cloud storage checked: {_esc(buckets)}.</p>"
        )
    scope_html = "".join(scope_blocks) or "<p class='empty'>No assessment scope recorded.</p>"

    def _finding_block(f: dict[str, Any]) -> str:
        sev = str(f.get("severity", "info")).lower()
        endpoints = f.get("affected_endpoints") or ([f.get("url")] if f.get("url") else [])
        ep_html = "".join(f"<li class='mono'>{_esc(e)}</li>" for e in endpoints) or "<li>none recorded</li>"
        evidence = f.get("evidence") or {}
        ev_html = ""
        if evidence:
            rows = "".join(
                f"<tr><td>{_esc(k)}</td><td class='mono'>{_esc(v)}</td></tr>"
                for k, v in evidence.items()
                if v not in (None, "", [], {})
            )
            if rows:
                ev_html = (
                    "<div><h5>Evidence</h5><table class='ev'><tbody>"
                    f"{rows}</tbody></table></div>"
                )
        return (
            f'<article class="finding sev-border-{sev}">'
            f'<div class="finding-head"><span class="badge sev-{sev}">{_esc(sev)}</span>'
            f'<span class="plugin">{_esc(f.get("plugin_name") or "scanner")}</span></div>'
            f'<h4>{_esc(f.get("title") or "Untitled finding")}</h4>'
            f'<p>{_esc(f.get("description") or "No description provided.")}</p>'
            f'<div class="meta"><div><h5>Remediation</h5>'
            f'<p>{_esc(f.get("remediation") or "Review and remediate the affected behavior.")}</p></div>'
            f'<div><h5>Affected endpoints</h5><ul>{ep_html}</ul></div>{ev_html}</div></article>'
        )

    vulns_html = "".join(_finding_block(f) for f in vulnerabilities) or (
        "<p class='empty'>No vulnerabilities were identified.</p>"
    )
    obs_html = "".join(_finding_block(f) for f in observations) or (
        "<p class='empty'>No observations recorded.</p>"
    )

    checks = report.get("checks_performed") or []
    checks_html = (
        "<h2>Checks performed</h2><p class='lead'>The following categories of checks were "
        "run during this assessment:</p><ul class='checks'>"
        + "".join(f"<li class='mono'>{_esc(c)}</li>" for c in checks)
        + "</ul>"
        if checks
        else ""
    )

    sev_css = "".join(f".sev-{s}{{background:{c};}}" for s, c in _SEVERITY_COLOR.items())
    border_css = "".join(
        f".sev-border-{s}{{border-left-color:{c};}}" for s, c in _SEVERITY_COLOR.items()
    )

    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  :root {{ color-scheme: light; }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; background: #f4f4f2; color: #1d2230;
    font: 15px/1.55 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
  .wrap {{ max-width: 900px; margin: 0 auto; padding: 48px 32px 80px; }}
  header.report {{ border-bottom: 3px solid #1d2230; padding-bottom: 20px; margin-bottom: 28px; }}
  h1 {{ margin: 6px 0 6px; font-size: 26px; letter-spacing: -.02em; }}
  .subtitle {{ margin: 0 0 12px; font-size: 16px; color: #4a5060; }}
  .stamp {{ color: #6a7080; font-size: 13px; }} .stamp code {{ color: #1d2230; }}
  .total {{ font-size: 40px; font-weight: 700; letter-spacing: -.03em; }}
  .total small {{ font-size: 14px; font-weight: 400; color: #6a7080; margin-left: 8px; }}
  .chips {{ display: flex; flex-wrap: wrap; gap: 8px; margin: 16px 0 8px; }}
  .chip {{ font-size: 12px; padding: 4px 10px; color: #fff; text-transform: uppercase; letter-spacing: .04em; }}
  h2 {{ font-size: 20px; margin: 40px 0 14px; padding-bottom: 6px; border-bottom: 1px solid #d8d8d4; }}
  h3 {{ font-size: 15px; margin: 20px 0 8px; }}
  table.src {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  table.src th, table.src td {{ text-align: left; padding: 7px 10px; border-bottom: 1px solid #e2e2de; }}
  table.src th {{ color: #6a7080; font-weight: 600; }}
  .mono {{ font-family: "SF Mono", ui-monospace, Menlo, Consolas, monospace; font-size: 12px; overflow-wrap: anywhere; }}
  .finding {{ background: #fff; border: 1px solid #e2e2de; border-left-width: 4px; padding: 18px 20px; margin: 14px 0; }}
  .finding-head {{ display: flex; align-items: center; gap: 10px; }}
  .badge {{ font-size: 11px; padding: 3px 8px; color: #fff; text-transform: uppercase; letter-spacing: .05em; }}
  .plugin {{ font-size: 12px; color: #6a7080; }}
  .finding h4 {{ margin: 10px 0 6px; font-size: 17px; }}
  .finding p {{ margin: 0 0 4px; }}
  .meta {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-top: 14px; padding-top: 14px; border-top: 1px solid #eee; }}
  .meta h5 {{ margin: 0 0 4px; font-size: 12px; text-transform: uppercase; letter-spacing: .06em; color: #6a7080; }}
  .meta ul {{ margin: 0; padding-left: 16px; }}
  .empty {{ color: #6a7080; }}
  .lead {{ color: #4a5060; margin: 0 0 10px; }}
  .counts {{ display: flex; gap: 32px; align-items: baseline; }}
  .counts .n {{ font-size: 40px; font-weight: 700; letter-spacing: -.03em; }}
  .counts .n.obs {{ font-size: 26px; color: #6a7080; }}
  .counts small {{ font-size: 13px; color: #6a7080; margin-left: 6px; }}
  table.ev {{ width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 4px; }}
  table.ev td {{ padding: 3px 8px; border-bottom: 1px solid #eee; vertical-align: top; }}
  table.ev td:first-child {{ color: #6a7080; white-space: nowrap; width: 1%; }}
  ul.checks {{ columns: 2; margin: 0; }}
  {sev_css}
  {border_css}
  @media print {{ body {{ background: #fff; }} .finding {{ break-inside: avoid; }} }}
</style></head>
<body><div class="wrap">
  <header class="report">
    <h1>{title}</h1>
    {subtitle}
    <div class="stamp">Run <code>{_esc(report.get('run_id'))}</code> &middot; generated {_esc(report.get('generated_at'))}</div>
  </header>
  <div class="counts">
    <div><span class="n">{_esc(vuln_count)}</span><small>vulnerabilit{'y' if vuln_count == 1 else 'ies'}</small></div>
    <div><span class="n obs">{_esc(obs_count)}</span><small>observation{'' if obs_count == 1 else 's'} (not vulnerabilities)</small></div>
  </div>
  <div class="chips">{chips}</div>
  <h2>Assessment scope</h2>
  {scope_html}
  {checks_html}
  <h2>Vulnerabilities ({_esc(vuln_count)})</h2>
  <p class="lead">Issues that should be remediated, most severe first.</p>
  {vulns_html}
  <h2>Observations ({_esc(obs_count)})</h2>
  <p class="lead">Informational items and hardening opportunities. These are not vulnerabilities.</p>
  {obs_html}
</div></body></html>"""

    html_path.write_text(doc, encoding="utf-8")
    return html_path
