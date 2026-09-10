from __future__ import annotations

from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    PageBreak,
    Table,
    TableStyle,
)


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

    story.append(Paragraph("DREAD — Unified Suite Report", styles["Title"]))
    story.append(Spacer(1, 0.2 * inch))
    story.append(
        Paragraph(
            f"<b>Run ID:</b> {escape(str(report.get('run_id', '')))}<br/>"
            f"<b>Generated:</b> {escape(str(report.get('generated_at', '')))}<br/>"
            f"<b>Schema:</b> {escape(str(report.get('reports_schema_version', '')))}",
            styles["Normal"],
        )
    )
    story.append(Spacer(1, 0.25 * inch))
    story.append(Paragraph("Executive overview", styles["Heading2"]))
    roll = report.get("rollups") or {}
    fbs = roll.get("findings_by_severity") or {}
    story.append(
        Paragraph(
            f"This consolidated report aggregates outputs from the DREAD product suite. "
            f"<b>Total normalized findings:</b> {roll.get('total_findings', 0)} "
            f"(Probe-backed; other products attach summaries as they are integrated).",
            styles["Normal"],
        )
    )
    story.append(Spacer(1, 0.1 * inch))
    sev_line = ", ".join(f"{k}: {v}" for k, v in fbs.items() if v)
    story.append(Paragraph(f"<b>Severity distribution:</b> {escape(sev_line)}", styles["Normal"]))

    src = report.get("sources") or {}
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph("Sources", styles["Heading2"]))
    for name in ("probe", "scope"):
        block = src.get(name) or {}
        inc = block.get("included")
        story.append(Paragraph(f"<b>{escape(name)}</b> — included: {inc}", styles["Normal"]))
        if name == "probe" and block.get("scans"):
            for s in block["scans"][:12]:
                line = (
                    f"  • {escape(str(s.get('artifact')))} | "
                    f"target {escape(str(s.get('target')))} | "
                    f"findings {s.get('finding_count')}"
                )
                story.append(Paragraph(line, styles["Normal"]))
        if name == "scope" and block.get("summary"):
            summ = block["summary"]
            story.append(
                Paragraph(
                    escape(
                        f"  Subdomains: {summ.get('subdomain_count', 0)}; "
                        f"cloud keys: {list((summ.get('cloud_bucket_counts') or {}).keys())}"
                    ),
                    styles["Normal"],
                )
            )
        story.append(Spacer(1, 0.08 * inch))

    story.append(PageBreak())
    story.append(Paragraph("Findings (normalized)", styles["Heading2"]))
    story.append(Spacer(1, 0.1 * inch))

    findings = report.get("findings") or []
    max_rows = 200
    table_data = [["Severity", "Plugin", "Title", "URL"]]
    for f in findings[:max_rows]:
        table_data.append(
            [
                escape(str(f.get("severity", "")))[:12],
                escape(str(f.get("plugin_name", "")))[:22],
                escape(str(f.get("title", "")))[:55],
                escape(str(f.get("url", "")))[:40],
            ]
        )

    t = Table(table_data, colWidths=[0.75 * inch, 1.15 * inch, 2.6 * inch, 1.5 * inch])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f8")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(t)

    if len(findings) > max_rows:
        story.append(Spacer(1, 0.15 * inch))
        story.append(
            Paragraph(
                f"<i>{len(findings) - max_rows} additional findings omitted from PDF; "
                f"see JSON or HTML dashboard for full data.</i>",
                styles["Normal"],
            )
        )

    doc.build(story)
    return pdf_path
