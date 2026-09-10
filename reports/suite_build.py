"""Orchestrate suite aggregation and artifact generation."""

from __future__ import annotations

from pathlib import Path

from aggregate import aggregate_from_cli_inputs
from dashboard_writer import write_dashboard_bundle
from suite_schema import REPORTS_SCHEMA_VERSION
from writers.json_writer import write_suite_json


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

    if "json" in formats:
        p = write_suite_json(report, output_dir, base_name)
        messages.append(f"[+] JSON: {p}")

    if "pdf" in formats:
        try:
            from writers.pdf_writer import write_suite_pdf

            p = write_suite_pdf(report, output_dir, base_name)
            messages.append(f"[+] PDF: {p}")
        except ModuleNotFoundError as e:
            errors.append(
                "PDF requires reportlab. Install: pip install reportlab "
                f"({e.name})"
            )
        except Exception as e:
            errors.append(f"PDF failed: {e}")

    if "html" in formats:
        try:
            from writers.html_writer import write_suite_html

            p = write_suite_html(report, output_dir, base_name)
            messages.append(f"[+] HTML: {p}")
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
