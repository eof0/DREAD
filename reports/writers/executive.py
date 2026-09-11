"""
Executive summary writer — for a non-technical reader (a business owner, a manager).

Leads with an overall risk verdict, explains each vulnerability in plain English with a
fix urgency, and collapses low-risk observations into a single line. No payloads, no
internal tool or plugin names, no JSON. The technical report carries the detail.
"""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape as _xml_escape

from plain_language import explain, risk_statement, urgency

_SEV_ORDER = ("critical", "high", "medium", "low")
_SEV_COLOR = {"critical": "#b02a37", "high": "#c8582b", "medium": "#b8860b", "low": "#3f7d58"}
_RISK_COLOR = {"Critical": "#b02a37", "High": "#c8582b", "Moderate": "#b8860b", "Low": "#3f7d58"}


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def _sev_rank(finding: dict[str, Any]) -> int:
    sev = str(finding.get("severity", "low")).lower()
    return _SEV_ORDER.index(sev) if sev in _SEV_ORDER else len(_SEV_ORDER)


def _vulnerabilities(report: dict[str, Any]) -> list[dict[str, Any]]:
    vulns = [f for f in report.get("findings") or [] if f.get("classification") == "vulnerability"]
    return sorted(vulns, key=_sev_rank)


def _observation_sentence(report: dict[str, Any]) -> str:
    count = report.get("rollups", {}).get("observation_count", 0)
    if not count:
        return ""
    noun = "observation" if count == 1 else "observations"
    return (
        f"We also noted {count} low-risk {noun} (informational items such as software "
        f"details or standard network services). These are not vulnerabilities; the "
        f"technical report lists them for your IT team."
    )


def _subject(report: dict[str, Any]) -> str:
    return report.get("target") or "the target environment"


# -- HTML ---------------------------------------------------------------------

def write_executive_html(report: dict[str, Any], output_dir: Path, base_name: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    out = output_dir / f"{base_name}.html"

    roll = report.get("rollups") or {}
    vuln_count = roll.get("vulnerability_count", 0)
    label, sentence = risk_statement(roll.get("overall_risk", "none"), vuln_count)
    risk_color = _RISK_COLOR.get(label, "#3f7d58")

    vuln_blocks: list[str] = []
    for f in _vulnerabilities(report):
        sev = str(f.get("severity", "low")).lower()
        e = explain(f)
        vuln_blocks.append(
            f'<article class="vuln">'
            f'<div class="vhead"><span class="sev" style="background:{_SEV_COLOR.get(sev, "#3f7d58")}">'
            f'{_esc(sev)}</span><span class="urgency">{_esc(urgency(sev))}</span></div>'
            f'<h3>{_esc(e.headline)}</h3>'
            f'<p class="loc">Where: <span class="mono">{_esc(f.get("url") or _subject(report))}</span></p>'
            f'<p><strong>What it means:</strong> {_esc(e.what_it_means)}</p>'
            f'<p><strong>Why it matters:</strong> {_esc(e.why_it_matters)}</p>'
            f'<p><strong>What to do:</strong> {_esc(e.what_to_do)}</p>'
            f'</article>'
        )
    if vuln_blocks:
        vulns_html = "".join(vuln_blocks)
    else:
        vulns_html = (
            '<p class="clean">Nothing requiring action was found on the systems we tested. '
            'The observations below are informational only.</p>'
        )

    obs = _observation_sentence(report)
    obs_html = f'<div class="obs"><h2>Other observations</h2><p>{_esc(obs)}</p></div>' if obs else ""

    return _write(
        out,
        f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(report.get('title') or 'Security Assessment - Executive Summary')}</title>
<style>
  :root {{ color-scheme: light; }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; background: #f4f4f2; color: #1d2230;
    font: 16px/1.6 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
  .wrap {{ max-width: 780px; margin: 0 auto; padding: 48px 32px 80px; }}
  header {{ border-bottom: 3px solid #1d2230; padding-bottom: 18px; margin-bottom: 8px; }}
  h1 {{ margin: 0 0 6px; font-size: 26px; letter-spacing: -.02em; }}
  .subtitle {{ margin: 0; font-size: 16px; color: #4a5060; }}
  .verdict {{ margin: 26px 0; padding: 20px 24px; background: #fff; border-left: 6px solid {risk_color}; }}
  .verdict .rank {{ font-size: 13px; letter-spacing: .08em; text-transform: uppercase; color: #6a7080; }}
  .verdict .level {{ font-size: 30px; font-weight: 700; color: {risk_color}; margin: 2px 0 8px; }}
  .verdict p {{ margin: 0; font-size: 17px; }}
  h2 {{ font-size: 20px; margin: 40px 0 8px; }}
  .lead {{ color: #4a5060; margin: 0 0 12px; }}
  .vuln {{ background: #fff; border: 1px solid #e2e2de; border-radius: 4px; padding: 18px 22px; margin: 16px 0; }}
  .vhead {{ display: flex; align-items: center; gap: 12px; margin-bottom: 6px; }}
  .sev {{ font-size: 12px; padding: 3px 10px; color: #fff; text-transform: uppercase; letter-spacing: .05em; border-radius: 3px; }}
  .urgency {{ font-size: 13px; font-weight: 600; color: #1d2230; }}
  .vuln h3 {{ margin: 6px 0 10px; font-size: 19px; }}
  .vuln p {{ margin: 6px 0; }}
  .loc {{ color: #6a7080; font-size: 14px; }}
  .mono {{ font-family: "SF Mono", ui-monospace, Menlo, Consolas, monospace; font-size: 13px; overflow-wrap: anywhere; }}
  .clean {{ background: #fff; border-left: 6px solid #3f7d58; padding: 16px 20px; }}
  .obs {{ margin-top: 34px; }}
  .obs p {{ color: #4a5060; }}
  .method {{ margin-top: 40px; font-size: 14px; color: #6a7080; border-top: 1px solid #d8d8d4; padding-top: 16px; }}
  @media print {{ body {{ background: #fff; }} .vuln, .verdict {{ break-inside: avoid; }} }}
</style></head>
<body><div class="wrap">
  <header><h1>{_esc(report.get('title') or 'Security Assessment')}</h1>
  <p class="subtitle">{_esc(_subject(report))}</p></header>
  <div class="verdict"><div class="rank">Overall risk</div>
    <div class="level">{_esc(label)}</div><p>{_esc(sentence)}</p></div>
  <h2>{'What we found' if vuln_count else 'Findings'}</h2>
  <p class="lead">{_esc(_vuln_lead(vuln_count))}</p>
  {vulns_html}
  {obs_html}
  <p class="method">{_esc(_methodology(report))}</p>
</div></body></html>""",
    )


def _vuln_lead(vuln_count: int) -> str:
    if not vuln_count:
        return ""
    noun = "issue that needs" if vuln_count == 1 else "issues that need"
    return f"We found {vuln_count} {noun} attention, listed from most to least urgent."


def _methodology(report: dict[str, Any]) -> str:
    checks = report.get("checks_performed") or []
    subj = _subject(report)
    base = (
        f"This assessment tested {subj} from the outside, the way an attacker on the internet "
        f"would see it, covering common web and network weaknesses."
    )
    if checks:
        base += f" {len(checks)} categories of checks were performed."
    return base + f" Generated {report.get('generated_at', '')}."


def _write(path: Path, doc: str) -> Path:
    path.write_text(doc, encoding="utf-8")
    return path


# -- PDF ----------------------------------------------------------------------

def write_executive_pdf(report: dict[str, Any], output_dir: Path, base_name: str) -> Path:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

    output_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = output_dir / f"{base_name}.pdf"

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("Ex", parent=styles["Title"], fontSize=17, leading=21)
    subtitle_style = ParagraphStyle(
        "ExSub", parent=styles["Title"], fontName="Helvetica", fontSize=13,
        leading=16, textColor=colors.HexColor("#4a5060"),
    )
    body = styles["Normal"]
    body.fontSize = 11
    body.leading = 16

    roll = report.get("rollups") or {}
    vuln_count = roll.get("vulnerability_count", 0)
    label, sentence = risk_statement(roll.get("overall_risk", "none"), vuln_count)

    doc = SimpleDocTemplate(str(pdf_path), pagesize=LETTER, rightMargin=54,
                            leftMargin=54, topMargin=54, bottomMargin=54)
    story: list[Any] = [
        Paragraph(_xml_escape(str(report.get("title") or "Security Assessment")), title_style),
        Paragraph(_xml_escape(_subject(report)), subtitle_style),
        Spacer(1, 0.25 * inch),
        Paragraph(f"<b>Overall risk: {_xml_escape(label)}</b>", styles["Heading2"]),
        Paragraph(_xml_escape(sentence), body),
        Spacer(1, 0.2 * inch),
    ]

    story.append(Paragraph("What we found" if vuln_count else "Findings", styles["Heading2"]))
    lead = _vuln_lead(vuln_count)
    if lead:
        story.append(Paragraph(_xml_escape(lead), body))
    story.append(Spacer(1, 0.08 * inch))

    for f in _vulnerabilities(report):
        sev = str(f.get("severity", "low")).lower()
        e = explain(f)
        story.append(Paragraph(
            f'<b>[{_xml_escape(sev.upper())} &middot; {_xml_escape(urgency(sev))}]</b> '
            f'{_xml_escape(e.headline)}', styles["Heading3"]))
        story.append(Paragraph(f"<i>Where: {_xml_escape(str(f.get('url') or _subject(report)))}</i>", body))
        story.append(Paragraph(f"<b>What it means:</b> {_xml_escape(e.what_it_means)}", body))
        story.append(Paragraph(f"<b>Why it matters:</b> {_xml_escape(e.why_it_matters)}", body))
        story.append(Paragraph(f"<b>What to do:</b> {_xml_escape(e.what_to_do)}", body))
        story.append(Spacer(1, 0.14 * inch))

    if not vuln_count:
        story.append(Paragraph(
            "Nothing requiring action was found on the systems we tested.", body))
        story.append(Spacer(1, 0.14 * inch))

    obs = _observation_sentence(report)
    if obs:
        story.append(Paragraph("Other observations", styles["Heading2"]))
        story.append(Paragraph(_xml_escape(obs), body))
        story.append(Spacer(1, 0.2 * inch))

    story.append(Paragraph(_xml_escape(_methodology(report)),
                           ParagraphStyle("Method", parent=body, fontSize=9,
                                          textColor=colors.HexColor("#6a7080"))))
    doc.build(story)
    return pdf_path
