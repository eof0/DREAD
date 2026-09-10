#!/usr/bin/env python3
"""
HTML report artifact for Probe.

Public builds ship a placeholder HTML file only. Full interactive HTML / Web UI
is provided in the private product line.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict

PUBLIC_HTML_PLACEHOLDER = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DREAD — HTML report</title>
    <style>
        :root { color-scheme: light dark; }
        body {
            font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
            line-height: 1.6;
            max-width: 42rem;
            margin: 2rem auto;
            padding: 1.5rem;
        }
        h1 { font-size: 1.25rem; font-weight: 600; }
        p { margin: 1rem 0; }
        .meta { font-size: 0.875rem; opacity: 0.85; margin-top: 2rem; }
        code { font-size: 0.9em; }
    </style>
</head>
<body>
    <h1>HTML report</h1>
    <p>This has been removed and replaced with a Web UI version not built into the public version. Please use one of the other options.</p>
    <p>For this build, use <strong>JSON</strong>, <strong>Markdown</strong>, or <strong>PDF</strong> output instead (for example <code>--format json,md,pdf</code>).</p>
    <p class="meta">Scan target (reference only): <code>__TARGET__</code><br>
    Generated: __TIMESTAMP__</p>
</body>
</html>
"""


def generate_html_report(report_data: Dict[str, Any], output_path: str) -> str:
    """
    Write the public-placeholder HTML file (no Chart.js / full report UI).
    """
    target = str(report_data.get("target", "unknown"))
    ts_raw = str(report_data.get("timestamp", ""))
    try:
        cleaned = ts_raw.replace("Z", "")
        dt = datetime.fromisoformat(cleaned)
        formatted = dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        formatted = ts_raw or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = (
        PUBLIC_HTML_PLACEHOLDER
        .replace("__TARGET__", target)
        .replace("__TIMESTAMP__", formatted)
    )
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return str(path.resolve())


def write_html(report: Dict[str, Any], output_dir: str, output_name: str) -> str:
    """Write HTML report placeholder to file."""
    output_root = Path(output_dir).resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    output_path = output_root / f"{output_name}.html"
    generated = Path(generate_html_report(report, str(output_path))).resolve()
    if not generated.exists():
        raise OSError(f"Failed to write {generated}")
    return str(generated)
