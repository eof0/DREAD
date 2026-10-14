"""Local DREAD web application API."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[2]
RUNS_DIR = Path(
    os.environ.get("DREAD_RUNS_DIR", Path.home() / ".dread" / "runs")
).resolve()
DASHBOARD_DIR = ROOT / "reports" / "dashboard" / "dist"


sys.path.insert(0, str(ROOT))
from env_loader import load_env_file  # noqa: E402

load_env_file(ROOT / ".env")

from reports.api.jobs import JobManager, QueueFull


@asynccontextmanager
async def lifespan(app):
    with JobManager(
        RUNS_DIR, cwd=ROOT,
        workers=max(1, int(os.environ.get("DREAD_JOB_WORKERS", "2"))),
        queue_size=max(1, int(os.environ.get("DREAD_JOB_QUEUE_SIZE", "8"))),
        timeout=max(1, float(os.environ.get("DREAD_JOB_TIMEOUT", "3600"))),
    ) as manager:
        app.state.jobs = manager
        yield


app = FastAPI(title="DREAD", version="1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    max_subdomains: int = Field(default=10, ge=0, le=100)


class DiscoverRequest(BaseModel):
    target: str = Field(min_length=1, max_length=2048)


class CannonRun(BaseModel):
    tool: str = Field(min_length=1, max_length=64)
    target: str = Field(min_length=1, max_length=2048)
    authorized: bool = False


class CannonKaboom(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    mode: Literal["all", "load", "staged"]
    authorized: bool = False


class ChatRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=8000)


def _validate_target(target: str) -> str:
    value = target.strip()
    raw_scheme = urlparse(value).scheme.lower()
    if raw_scheme in {"data", "file", "ftp", "javascript", "ws", "wss"}:
        raise HTTPException(status_code=422, detail="Target must be an HTTP or HTTPS URL")
    parsed = urlparse(value if "://" in value else f"https://{value}")
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or any(char.isspace() for char in value)
    ):
        raise HTTPException(status_code=422, detail="Target must be an HTTP or HTTPS URL")
    return value


def _safe_target(target: str) -> str:
    value = target.strip()
    if not value or value.startswith("-") or any(char.isspace() for char in value):
        raise HTTPException(status_code=422, detail="Invalid target")
    return value


def _latest_report(job_dir: Path) -> Path | None:
    reports = sorted(job_dir.glob("run_*/suite_report/dread_suite_report.json"))
    return reports[-1] if reports else None


def _start_job(kind, command, meta=None, finalize=None):
    try:
        return app.state.jobs.submit(kind, command, meta, finalize)
    except QueueFull as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc


def _scan_command(job_dir: Path, target: str, max_subdomains: int) -> list[str]:
    return [
        sys.executable,
        str(ROOT / "dread.py"),
        "scan",
        target,
        "--max-subdomains",
        str(max_subdomains),
        "--suite-out",
        str(job_dir),
        "--suite-report",
        "--suite-report-formats",
        "json,html,pdf",
    ]


def _scan_finalize(job_dir: Path, return_code: int) -> dict:
    report_path = _latest_report(job_dir)
    status = "completed" if return_code == 0 and report_path else "failed"
    if report_path:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        if report.get("rollups", {}).get("partial"):
            status = "partial"
    return {"status": status, "report_path": str(report_path) if report_path else None,
            "report_id": job_dir.name if report_path else None}


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "service": "dread"}


@app.get("/api/scans")
def scans() -> list[dict]:
    return [job for job in app.state.jobs.list() if job["kind"] == "scan"]


@app.post("/api/scans", status_code=202)
def start_scan(request: ScanRequest) -> dict:
    target = _validate_target(request.target)
    return _start_job("scan", lambda folder: _scan_command(folder, target, request.max_subdomains),
                      {"target": target}, _scan_finalize)


@app.get("/api/scans/{job_id}")
def scan_status(job_id: str) -> dict:
    return job_status(job_id)


@app.get("/api/scans/{job_id}/events")
def scan_events(job_id: str, cursor: int = Query(default=0, ge=0)) -> dict:
    return job_events(job_id, cursor)


def _reports() -> list[tuple[str, Path]]:
    return [(path.parent.parent.parent.name, path) for path in RUNS_DIR.glob("*/run_*/suite_report/dread_suite_report.json")]


@app.get("/api/runs")
def runs() -> list[dict]:
    result = []
    for report_id, path in _reports():
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        result.append({
            "id": report_id,
            "run_id": report.get("run_id"),
            "target": report.get("target") or report.get("title"),
            "generated_at": report.get("generated_at"),
            "total_findings": (report.get("rollups") or {}).get("total_findings", 0),
            "risk_level": (report.get("rollups") or {}).get("overall_risk"),
        })
    return sorted(result, key=lambda item: item.get("generated_at") or "", reverse=True)


@app.get("/api/runs/latest")
def latest_report() -> dict:
    available = runs()
    if not available:
        raise HTTPException(status_code=404, detail="No reports available")
    return run_report(available[0]["id"])


@app.get("/api/runs/{report_id}")
def run_report(report_id: str) -> dict:
    matches = [path for found_id, path in _reports() if found_id == report_id]
    if not matches:
        raise HTTPException(status_code=404, detail="Report not found")
    try:
        return json.loads(matches[-1].read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail="Report could not be read") from exc


@app.get("/api/jobs")
def jobs() -> list[dict]:
    return app.state.jobs.list()


@app.get("/api/jobs/{job_id}")
def job_status(job_id: str) -> dict:
    try:
        return app.state.jobs.get(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Job not found") from exc


@app.get("/api/jobs/{job_id}/events")
def job_events(job_id: str, cursor: int = Query(default=0, ge=0)) -> dict:
    try:
        return app.state.jobs.events(job_id, cursor)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Job not found") from exc


@app.post("/api/jobs/{job_id}/cancel")
def cancel_job(job_id: str) -> dict:
    try:
        return app.state.jobs.cancel(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Job not found") from exc


@app.get("/api/products")
def products_list() -> list[dict]:
    sys.path.insert(0, str(ROOT))
    from products import SUITE_PRODUCTS

    return [
        {"cli": p.cli_name, "name": p.display_name, "summary": p.summary, "status": p.status}
        for p in SUITE_PRODUCTS
    ]


@app.get("/api/cannon/tools")
def cannon_tools() -> list[dict]:
    result = subprocess.run(
        [sys.executable, str(ROOT / "cannon" / "cannon.py"), "tools", "--json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise HTTPException(status_code=500, detail=result.stderr.strip() or "cannon tools failed")
    return json.loads(result.stdout)


@app.post("/api/cannon/run", status_code=202)
def cannon_run(request: CannonRun) -> dict:
    if not request.authorized:
        raise HTTPException(status_code=422, detail="Authorization required to run active tools")
    target = _safe_target(request.target)
    tool = request.tool.strip()
    command = [
        sys.executable, str(ROOT / "cannon" / "cannon.py"),
        "run", tool, target, "--authorized",
    ]
    return _start_job("cannon.run", command, {"tool": tool, "target": target})


@app.post("/api/cannon/kaboom", status_code=202)
def cannon_kaboom(request: CannonKaboom) -> dict:
    if not request.authorized:
        raise HTTPException(status_code=422, detail="Authorization required to run active tools")
    target = _safe_target(request.target)
    command = [
        sys.executable, str(ROOT / "cannon" / "cannon.py"),
        "kaboom", target, "--mode", request.mode, "--authorized",
    ]
    return _start_job("cannon.kaboom", command, {"target": target, "mode": request.mode})


@app.post("/api/scope/discover", status_code=202)
def scope_discover(request: DiscoverRequest) -> dict:
    target = _validate_target(request.target)
    command = [sys.executable, str(ROOT / "dread.py"), "discover", target]
    return _start_job("scope.discover", command, {"target": target})


@app.post("/api/db/update", status_code=202)
def db_update() -> dict:
    return _start_job("db.update", [sys.executable, str(ROOT / "dread.py"), "update-db"])


@app.post("/api/db/update-cve", status_code=202)
def db_update_cve() -> dict:
    return _start_job("db.update-cve", [sys.executable, str(ROOT / "dread.py"), "update-cve-db"])


@app.post("/api/dreadai/chat")
def dreadai_chat(request: ChatRequest) -> dict:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise HTTPException(status_code=503, detail="ANTHROPIC_API_KEY is not set")
    sys.path.insert(0, str(ROOT / "dreadai"))
    import agent

    return {"result": agent.ask(request.prompt)}


if DASHBOARD_DIR.is_dir():
    app.mount("/assets", StaticFiles(directory=DASHBOARD_DIR / "assets"), name="assets")


@app.get("/{path:path}")
def frontend(path: str = ""):
    if not DASHBOARD_DIR.is_dir():
        return {"message": "Build the dashboard with npm run build", "api": "/api/health"}
    requested = (DASHBOARD_DIR / path).resolve()
    if requested.parent == DASHBOARD_DIR.resolve() and requested.is_file():
        return FileResponse(requested)
    return FileResponse(DASHBOARD_DIR / "index.html")
