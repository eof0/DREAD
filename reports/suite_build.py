"""Orchestrate suite aggregation and artifact generation."""

from __future__ import annotations

from pathlib import Path

from aggregate import aggregate_from_cli_inputs
from dashboard_writer import write_dashboard_bundle
from suite_schema import REPORTS_SCHEMA_VERSION
from writers.json_writer import write_suite_json, write_technical_json

# Customer deliverable base names (kept distinct from the internal dread_suite_report).
EXECUTIVE_NAME = "executive_summary"
TECHNICAL_NAME = "technical_report"


def slim_report_for_dashboard(report: dict) -> dict:
    """Drop heavy raw embeds for the SPA payload (normalized findings remain)."""
    out = {k: v for k, v in report.items() if k != "raw_embed"}
    return out


def run_build(
    *,
    output_dir: Path,
    base_name: str,
    title: str,
    probe_paths: list[Path],
    scope_path: Path | None,
    include: frozenset[str],
    formats: frozenset[str],
    dashboard_src: Path,
    try_npm_build: bool,
) -> tuple[list[str], list[str]]:
    """
    Returns (artifact_messages, errors). Errors non-empty means partial failure.
    """
    messages: list[str] = []
    errors: list[str] = []

    report = aggregate_from_cli_inputs(
        probe_paths=probe_paths,
        scope_path=scope_path,
        include=include,
        report_title=title,
        schema_version=REPORTS_SCHEMA_VERSION,
    )

    # Internal artifact: the full report (with raw_embed) that the dashboard, run
    # history and DreadAI read. Always written when JSON is requested, under its
    # established name so those readers keep working.
    if "json" in formats:
        p = write_suite_json(report, output_dir, base_name)
        messages.append(f"[+] Internal report: {p}")
        tp = write_technical_json(report, output_dir, TECHNICAL_NAME)
        messages.append(f"[+] Technical JSON: {tp}")

    if "pdf" in formats:
        try:
            from writers.executive import write_executive_pdf
            from writers.pdf_writer import write_suite_pdf

            messages.append(f"[+] Executive PDF: {write_executive_pdf(report, output_dir, EXECUTIVE_NAME)}")
            messages.append(f"[+] Technical PDF: {write_suite_pdf(report, output_dir, TECHNICAL_NAME)}")
        except ModuleNotFoundError as e:
            errors.append(
                "PDF requires reportlab. Install: pip install reportlab "
                f"({e.name})"
            )
        except Exception as e:
            errors.append(f"PDF failed: {e}")

    if "html" in formats:
        try:
            from writers.executive import write_executive_html
            from writers.html_writer import write_suite_html

            messages.append(f"[+] Executive summary: {write_executive_html(report, output_dir, EXECUTIVE_NAME)}")
            messages.append(f"[+] Technical report: {write_suite_html(report, output_dir, TECHNICAL_NAME)}")
        except Exception as e:
            errors.append(f"HTML failed: {e}")

    if "dashboard" in formats:
        dash_payload = slim_report_for_dashboard(report)
        idx, err = write_dashboard_bundle(
            dash_payload,
            output_dir,
            dashboard_src,
            try_build=try_npm_build,
        )
        if err:
            errors.append(f"Dashboard: {err}")
        elif idx:
            messages.append(f"[+] Dashboard: {idx} (serve folder: {idx.parent})")

    if "dashboard" in formats:
        db = output_dir / "dashboard"
        if db.is_dir():
            messages.append(
                f"    Tip: cd {db} && python -m http.server 8765 "
                "then open http://127.0.0.1:8765/"
            )

    return messages, errors
