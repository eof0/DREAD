from __future__ import annotations

import html
from pathlib import Path
from typing import Any

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
    """Render the unified suite report as one self-contained, print-friendly HTML file."""
    output_dir.mkdir(parents=True, exist_ok=True)
    html_path = output_dir / f"{base_name}.html"

    roll = report.get("rollups") or {}
    fbs = roll.get("findings_by_severity") or {}
    total = roll.get("total_findings", len(report.get("findings") or []))
    findings = sorted(
        report.get("findings") or [],
        key=lambda f: (_rank(str(f.get("severity", "info"))), str(f.get("plugin_name", ""))),
    )
    title = _esc(report.get("title") or "DREAD Unified Security Report")

    chips = "".join(
        f'<span class="chip sev-{s}">{s}: {fbs.get(s, 0)}</span>' for s in _SEVERITY_ORDER
    )

    src = report.get("sources") or {}
    src_blocks: list[str] = []
    bp = src.get("probe") or {}
    if bp.get("included"):
        rows = "".join(
            f"<tr><td>{_esc(s.get('target'))}</td><td>{_esc(s.get('finding_count'))}</td>"
            f"<td class='mono'>{_esc(s.get('artifact'))}</td></tr>"
            for s in (bp.get("scans") or [])
        )
        src_blocks.append(
            "<h3>Probe</h3><table class='src'><thead><tr><th>Target</th>"
            f"<th>Findings</th><th>Artifact</th></tr></thead><tbody>{rows}</tbody></table>"
        )
    bs = src.get("scope") or {}
    if bs.get("included"):
        summ = bs.get("summary") or {}
        buckets = ", ".join((summ.get("cloud_bucket_counts") or {}).keys()) or "none"
        src_blocks.append(
            f"<h3>Scope</h3><p>Subdomains discovered: "
            f"<strong>{_esc(summ.get('subdomain_count', 0))}</strong>. Cloud buckets: {_esc(buckets)}.</p>"
        )
    sources_html = "".join(src_blocks) or "<p class='empty'>No sources attached.</p>"

    blocks: list[str] = []
    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        endpoints = f.get("affected_endpoints") or ([f.get("url")] if f.get("url") else [])
        ep_html = "".join(f"<li class='mono'>{_esc(e)}</li>" for e in endpoints) or "<li>none recorded</li>"
        blocks.append(
            f'<article class="finding sev-border-{sev}">'
            f'<div class="finding-head"><span class="badge sev-{sev}">{_esc(sev)}</span>'
            f'<span class="plugin">{_esc(f.get("plugin_name") or "scanner")}</span></div>'
            f'<h4>{_esc(f.get("title") or "Untitled finding")}</h4>'
            f'<p>{_esc(f.get("description") or "No description provided.")}</p>'
            f'<div class="meta"><div><h5>Remediation</h5>'
            f'<p>{_esc(f.get("remediation") or "Review and remediate the affected behavior.")}</p></div>'
            f'<div><h5>Affected endpoints</h5><ul>{ep_html}</ul></div></div></article>'
        )
    findings_html = "".join(blocks) or "<p class='empty'>No findings recorded.</p>"

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
  .eyebrow {{ font-size: 12px; letter-spacing: .12em; text-transform: uppercase; color: #6a7080; }}
  h1 {{ margin: 6px 0 12px; font-size: 34px; letter-spacing: -.02em; }}
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
  {sev_css}
  {border_css}
  footer {{ margin-top: 50px; color: #9a9aa2; font-size: 12px; }}
  @media print {{ body {{ background: #fff; }} .finding {{ break-inside: avoid; }} }}
</style></head>
<body><div class="wrap">
  <header class="report">
    <span class="eyebrow">DREAD / unified security report</span>
    <h1>{title}</h1>
    <div class="stamp">Run <code>{_esc(report.get('run_id'))}</code> &middot; generated {_esc(report.get('generated_at'))}</div>
  </header>
  <div class="total">{_esc(total)}<small>total findings</small></div>
  <div class="chips">{chips}</div>
  <h2>Sources</h2>
  {sources_html}
  <h2>Findings</h2>
  {findings_html}
  <footer>DREAD unified suite report &middot; schema {_esc(report.get('reports_schema_version'))}</footer>
</div></body></html>"""

    html_path.write_text(doc, encoding="utf-8")
    return html_path
