from __future__ import annotations

from typing import Dict, Iterable, List
import sys
from pathlib import Path

from scanner.reporting.json_writer import write_json
from scanner.reporting.markdown_writer import write_markdown
from scanner.reporting.pdf_writer import write_pdf
from scanner.reporting.html_generator import write_html


class Reporter:
    ALLOWED_FORMATS = ("json", "md", "pdf", "html")
    WRITERS = {
        "json": write_json,
        "md": write_markdown,
        "pdf": write_pdf,
        "html": write_html,
    }

    @classmethod
    def write(
        cls,
        report: Dict,
        output_name: str,
        formats: Iterable[str],
        output_dir: str = "REPORTS",
    ) -> List[str]:
        if not output_name:
            raise ValueError("output_name is required for report generation")

        if formats is None:
            raise ValueError("At least one output format is required")

        normalized = []
        for fmt in formats:
            if fmt is None:
                continue
            item = fmt.strip().lower()
            if not item:
                continue
            if item == "markdown":
                item = "md"
            normalized.append(item)

        if not normalized:
            raise ValueError("At least one output format is required")

        invalid = [fmt for fmt in normalized if fmt not in cls.ALLOWED_FORMATS]
        if invalid:
            raise ValueError(f"Unsupported report format(s): {', '.join(invalid)}")

        repo_root = Path(__file__).resolve().parents[3]
        default_output_dir = repo_root / "REPORTS"
        requested_output_dir = Path(output_dir) if output_dir else default_output_dir
        if not output_dir or str(requested_output_dir).strip().lower() == "scan_results":
            requested_output_dir = default_output_dir
        resolved_output_dir = (
            requested_output_dir
            if requested_output_dir.is_absolute()
            else (repo_root / requested_output_dir)
        ).resolve()
        resolved_output_dir.mkdir(parents=True, exist_ok=True)

        artifacts: List[str] = []
        failures: List[str] = []
        for fmt in cls.ALLOWED_FORMATS:
            if fmt not in normalized:
                continue
            writer = cls.WRITERS[fmt]
            try:
                artifact = Path(
                    writer(report, str(resolved_output_dir), output_name)
                ).resolve()
                if not artifact.exists():
                    raise RuntimeError(f"Failed to write {artifact}")
                print(f"[+] Report written -> {artifact}")
                artifacts.append(str(artifact))
            except Exception as e:
                message = f"{fmt.upper()} report generation failed: {e}"
                failures.append(message)
                print(f"[!] {message}", file=sys.stderr)

        if artifacts:
            return artifacts
        raise RuntimeError(
            "; ".join(failures) or "No report artifacts were generated"
        )
