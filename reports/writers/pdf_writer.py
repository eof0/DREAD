from __future__ import annotations

from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    PageBreak,
    Table,
    TableStyle,
)

from writers import cloud_storage_checked


def write_suite_pdf(report: dict[str, Any], output_dir: Path, base_name: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = output_dir / f"{base_name}.pdf"

    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=LETTER,
        rightMargin=54,
        leftMargin=54,
        topMargin=54,
        bottomMargin=54,
    )
    story: list[Any] = []

    title = str(report.get("title") or "Recon/Vuln Analysis - Report Findings")
    target = str(report.get("target") or "")
    # 17pt keeps the default title (longest month included) on one line of a Letter page.
    title_style = ParagraphStyle("ReportTitle", parent=styles["Title"], fontSize=17, leading=21)
    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Title"],
        fontName="Helvetica",
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#4a5060"),
    )

    story.append(Paragraph(escape(title), title_style))
    if target:
        story.append(Paragraph(escape(target), subtitle_style))
    story.append(Spacer(1, 0.2 * inch))
    story.append(
        Paragraph(
            f"<b>Run ID:</b> {escape(str(report.get('run_id', '')))}<br/>"
            f"<b>Generated:</b> {escape(str(report.get('generated_at', '')))}",
            styles["Normal"],
        )
    )
    story.append(Spacer(1, 0.25 * inch))
    story.append(Paragraph("Executive overview", styles["Heading2"]))
    roll = report.get("rollups") or {}
    vuln_count = roll.get("vulnerability_count", 0)
    obs_count = roll.get("observation_count", 0)
    vbs = roll.get("vulnerabilities_by_severity") or {}
    subject = escape(target) if target else "the target environment"
    story.append(
        Paragraph(
            f"This report summarizes the results of an external reconnaissance and "
            f"vulnerability assessment of {subject}. "
            f"<b>Vulnerabilities:</b> {vuln_count}. "
            f"<b>Observations (not vulnerabilities):</b> {obs_count}.",
            styles["Normal"],
        )
    )
    story.append(Spacer(1, 0.1 * inch))
    sev_line = ", ".join(f"{k}: {vbs.get(k, 0)}" for k in ("critical", "high", "medium", "low")
                         if vbs.get(k)) or "none"
    story.append(Paragraph(f"<b>Vulnerabilities by severity:</b> {escape(sev_line)}", styles["Normal"]))

    # Customer-facing: describe what was assessed, never which internal tool did it.
    src = report.get("sources") or {}
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph("Assessment scope", styles["Heading2"]))
    scans = (src.get("probe") or {}).get("scans") or []
    if scans:
        story.append(Paragraph("<b>Hosts tested</b>", styles["Normal"]))
        for s in scans[:12]:
            story.append(
                Paragraph(
                    f"  • {escape(str(s.get('target')))}: {s.get('finding_count')} finding(s)",
                    styles["Normal"],
                )
            )
    summ = (src.get("scope") or {}).get("summary")
    if summ:
        buckets = cloud_storage_checked(summ)
        story.append(Spacer(1, 0.08 * inch))
        story.append(
            Paragraph(
                escape(
                    f"Attack surface discovery: {summ.get('subdomain_count', 0)} subdomain(s) "
                    f"discovered; cloud storage checked: {buckets}."
                ),
                styles["Normal"],
            )
        )

    checks = report.get("checks_performed") or []
    if checks:
        story.append(Spacer(1, 0.12 * inch))
        story.append(Paragraph("<b>Checks performed:</b> " + escape(", ".join(checks)), styles["Normal"]))

    all_findings = report.get("findings") or []
    vulnerabilities = [f for f in all_findings if f.get("classification") == "vulnerability"]
    observations = [f for f in all_findings if f.get("classification") != "vulnerability"]

    def _table(rows: list[dict[str, Any]]) -> Table:
        data = [["Severity", "Check", "Title", "URL"]]
        for f in rows[:200]:
            data.append([
                escape(str(f.get("severity", "")))[:12],
                escape(str(f.get("plugin_name", "")))[:22],
                escape(str(f.get("title", "")))[:55],
                escape(str(f.get("url", "")))[:40],
            ])
        t = Table(data, colWidths=[0.75 * inch, 1.15 * inch, 2.6 * inch, 1.5 * inch])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f8")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        return t

    story.append(PageBreak())
    story.append(Paragraph(f"Vulnerabilities ({len(vulnerabilities)})", styles["Heading2"]))
    story.append(Spacer(1, 0.08 * inch))
    if vulnerabilities:
        story.append(_table(vulnerabilities))
    else:
        story.append(Paragraph("No vulnerabilities were identified.", styles["Normal"]))

    story.append(Spacer(1, 0.25 * inch))
    story.append(Paragraph(f"Observations ({len(observations)})", styles["Heading2"]))
    story.append(Paragraph(
        "<i>Informational items and hardening opportunities. These are not vulnerabilities.</i>",
        styles["Normal"]))
    story.append(Spacer(1, 0.08 * inch))
    if observations:
        story.append(_table(observations))
    else:
        story.append(Paragraph("No observations recorded.", styles["Normal"]))

    doc.build(story)
    return pdf_path
