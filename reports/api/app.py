"""Local DREAD web application API."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[2]
RUNS_DIR = Path(
    os.environ.get("DREAD_RUNS_DIR", Path.home() / ".dread" / "runs")
).resolve()
DASHBOARD_DIR = ROOT / "reports" / "dashboard" / "dist"
RUNS_DIR.mkdir(parents=True, exist_ok=True)


sys.path.insert(0, str(ROOT))
from env_loader import load_env_file  # noqa: E402

load_env_file(ROOT / ".env")

app = FastAPI(title="DREAD", version="1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()


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


def _write_event(job_dir: Path, event: dict) -> None:
    with (job_dir / "events.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event) + "\n")


def _latest_report(job_dir: Path) -> Path | None:
    reports = sorted(job_dir.glob("run_*/suite_report/dread_suite_report.json"))
    return reports[-1] if reports else None


def _stream_job(job_id: str, job_dir: Path, command: list[str], finalize=None) -> None:
    _write_event(job_dir, {"type": "started", "command": command[1:]})
    with _jobs_lock:
        _jobs[job_id]["status"] = "running"
    try:
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )
        assert process.stdout is not None
        buffer = ""
        while True:
            chunk = process.stdout.read(256)
            if not chunk:
                break
            buffer += chunk
            # Split on both newline and carriage return so in-place progress
            # counters (e.g. "still running... 10s elapsed\r") stream too.
            parts = re.split(r"[\r\n]", buffer)
            buffer = parts.pop()
            for part in parts:
                message = part.strip()
                if message:
                    _write_event(job_dir, {"type": "log", "message": message})
        if buffer.strip():
            _write_event(job_dir, {"type": "log", "message": buffer.strip()})
        return_code = process.wait()
        extra = finalize(return_code) if finalize else {}
        status = extra.pop("status", None) or ("completed" if return_code == 0 else "failed")
        _write_event(job_dir, {"type": "finished", "status": status, "return_code": return_code, **extra})
        with _jobs_lock:
            _jobs[job_id].update({"status": status, "return_code": return_code, **extra})
    except OSError as exc:
        _write_event(job_dir, {"type": "finished", "status": "failed", "error": str(exc)})
        with _jobs_lock:
            _jobs[job_id].update({"status": "failed", "error": str(exc)})


def _start_job(kind: str, command: list[str], meta: dict | None = None, finalize=None) -> dict:
    job_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + os.urandom(4).hex()
    job = {"kind": kind, "status": "queued", "created_at": datetime.now(timezone.utc).isoformat(), **(meta or {})}
    with _jobs_lock:
        _jobs[job_id] = job
    job_dir = RUNS_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    threading.Thread(target=_stream_job, args=(job_id, job_dir, command, finalize), daemon=True).start()
    return _job_summary(job_id, job)


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


def _scan_finalize(job_dir: Path):
    def finalize(return_code: int) -> dict:
        report_path = _latest_report(job_dir)
        status = "completed" if return_code == 0 and report_path else "failed"
        extra = {"status": status, "report_path": str(report_path) if report_path else None}
        if report_path:
            extra["report_id"] = report_path.parent.parent.name
        return extra

    return finalize


def _job_summary(job_id: str, job: dict) -> dict:
    return {"id": job_id, **{key: value for key, value in job.items() if key != "report_path"}, "has_report": bool(job.get("report_path"))}


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "service": "dread"}


@app.get("/api/scans")
def scans() -> list[dict]:
    with _jobs_lock:
        return [_job_summary(job_id, job) for job_id, job in _jobs.items()]


@app.post("/api/scans", status_code=202)
def start_scan(request: ScanRequest) -> dict:
    target = _validate_target(request.target)
    job_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + os.urandom(4).hex()
    job = {"kind": "scan", "target": target, "status": "queued", "created_at": datetime.now(timezone.utc).isoformat()}
    with _jobs_lock:
        _jobs[job_id] = job
    job_dir = RUNS_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    command = _scan_command(job_dir, target, request.max_subdomains)
    threading.Thread(
        target=_stream_job, args=(job_id, job_dir, command, _scan_finalize(job_dir)), daemon=True
    ).start()
    return _job_summary(job_id, job)


@app.get("/api/scans/{job_id}")
def scan_status(job_id: str) -> dict:
    with _jobs_lock:
        job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _job_summary(job_id, job)


@app.get("/api/scans/{job_id}/events")
def scan_events(job_id: str) -> list[dict]:
    path = RUNS_DIR / job_id / "events.jsonl"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Scan not found")
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


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
            "risk_level": ((report.get("rollups") or {}).get("risk") or {}).get("level"),
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
    with _jobs_lock:
        return [_job_summary(job_id, job) for job_id, job in _jobs.items()]


@app.get("/api/jobs/{job_id}")
def job_status(job_id: str) -> dict:
    with _jobs_lock:
        job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return _job_summary(job_id, job)


@app.get("/api/jobs/{job_id}/events")
def job_events(job_id: str) -> list[dict]:
    path = RUNS_DIR / job_id / "events.jsonl"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Job not found")
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


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
