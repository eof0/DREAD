from __future__ import annotations

from typing import Dict


def write_pdf(report: Dict, output_dir: str, output_name: str) -> str:
    """
    Write a PDF artifact for the given scan report.

    Note: `reportlab` is an optional dependency. If it's missing, we raise a
    clear RuntimeError so the caller can decide whether to fail or skip.
    """
    if not output_name:
        raise ValueError("output_name is required for PDF output")

    try:
        # Lazy import so JSON/MD scans don't hard-fail when PDF deps are absent.
        from scanner.reporting.pdf_report import PDFReportGenerator
    except ModuleNotFoundError as e:
        # Typical failure: `reportlab` missing.
        if e.name == "reportlab":
            raise RuntimeError(
                "PDF output requires the optional dependency 'reportlab'. "
                "Install it (e.g. `pip install reportlab`) or run with "
                "`--format json`."
            ) from e
        raise

    generator = PDFReportGenerator(
        report_data=report,
        output_directory=output_dir,
        client_name=output_name,
        output_name=output_name,
    )
    return generator.generate()
