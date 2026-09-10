from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


def _try_npm_build(dashboard_dir: Path) -> tuple[bool, str]:
    if not (dashboard_dir / "package.json").is_file():
        return False, "package.json missing"
    lock = dashboard_dir / "package-lock.json"
    npm_install = ["npm", "ci"] if lock.is_file() else ["npm", "install"]
    try:
        subprocess.run(
            npm_install,
            cwd=str(dashboard_dir),
            check=True,
            capture_output=True,
            text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        return False, f"{' '.join(npm_install)} failed: {e}"
    try:
        subprocess.run(
            ["npm", "run", "build"],
            cwd=str(dashboard_dir),
            check=True,
            capture_output=True,
            text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        return False, f"npm run build failed: {e}"
    return True, ""


def write_dashboard_bundle(
    report: dict[str, Any],
    output_dir: Path,
    dashboard_src: Path,
    try_build: bool = True,
) -> tuple[Path | None, str | None]:
    """
    Copies Vite `dist/` into output_dir/dashboard/ and writes report.json for the SPA to fetch.
    Returns (dashboard_index_path, error_message).
    """
    dist = dashboard_src / "dist"
    if not dist.is_dir() and try_build:
        ok, msg = _try_npm_build(dashboard_src)
        if not ok:
            return None, msg or "dashboard dist not built"
    if not dist.is_dir():
        return (
            None,
            "Dashboard UI not built. Run: cd reports/dashboard && npm ci && npm run build",
        )

    dash_out = output_dir / "dashboard"
    if dash_out.exists():
        shutil.rmtree(dash_out)
    shutil.copytree(dist, dash_out)

    report_path = dash_out / "report.json"
    report_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")

    index_html = dash_out / "index.html"
    if not index_html.is_file():
        return None, "dist/index.html missing after build"
    return index_html, None
