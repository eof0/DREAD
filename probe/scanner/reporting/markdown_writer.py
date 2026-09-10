from typing import Dict

from scanner.reporting.markdown_report import MarkdownReportGenerator


def write_markdown(report: Dict, output_dir: str, output_name: str) -> str:
    if not output_name:
        raise ValueError("output_name is required for Markdown output")

    generator = MarkdownReportGenerator(
        report_data=report,
        output_directory=output_dir,
        client_name=output_name,
        output_name=output_name,
    )
    return generator.generate()
