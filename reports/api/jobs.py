"""Persistent, bounded execution for local application jobs."""

from __future__ import annotations

import codecs
import json
import os
import queue
import re
import selectors
import signal
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

TERMINAL = {"completed", "partial", "failed", "cancelled", "timed_out", "interrupted"}


class QueueFull(RuntimeError):
    pass


def process_start(pid: int) -> str | None:
    """Linux start-time token so a recycled pid is not treated as this job."""
    try:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except OSError:
        return None
    tail = text.rsplit(")", 1)[-1].split()
    return tail[19] if len(tail) > 19 else None


def reap_process_group(pid, started) -> None:
    if not isinstance(pid, int) or not started or process_start(pid) != started:
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pid, sig)
        except OSError:
            return
        if sig == signal.SIGTERM:
            time.sleep(0.1)


class JobManager:
    def __init__(self, directory: Path, *, workers=2, queue_size=8, timeout=3600, cwd=None):
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.cwd = cwd
        self.lock = threading.RLock()
        self.pending = queue.Queue(maxsize=max(1, queue_size))
        self.stopping = threading.Event()
        self.jobs = {}
        self.cancellations = {}
        for path in directory.glob("*/job.json"):
            try:
                job = json.loads(path.read_text())
                job_id = path.parent.name
                job["id"] = job_id
                self.jobs[job_id] = job
                if job["status"] not in TERMINAL:
                    reap_process_group(job.get("pid"), job.get("process_start"))
                    self._update(job_id, status="interrupted", error="Application stopped before the job finished")
            except (OSError, ValueError, KeyError, TypeError):
                continue
        self.workers = [threading.Thread(target=self._work, daemon=True) for _ in range(max(1, workers))]
        for worker in self.workers:
            worker.start()

    def _update(self, job_id, **changes):
        with self.lock:
            self.jobs[job_id].update(changes)
            path = self.directory / job_id / "job.json"
            temporary = path.with_suffix(".tmp")
            temporary.write_text(json.dumps(self.jobs[job_id]), encoding="utf-8")
            temporary.replace(path)

    def _event(self, job_id, event):
        with self.lock:
            with (self.directory / job_id / "events.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(event) + "\n")

    def get(self, job_id):
        with self.lock:
            job = self.jobs[job_id]
            return {key: value for key, value in job.items() if key != "report_path"} | {
                "has_report": bool(job.get("report_path")),
            }

    def list(self):
        with self.lock:
            return sorted((self.get(key) for key in self.jobs), key=lambda job: job.get("created_at", ""), reverse=True)

    def submit(self, kind, command, meta=None, finalize=None):
        with self.lock:
            if self.stopping.is_set() or self.pending.full():
                raise QueueFull("Job queue is full; wait for a running job to finish")
            job_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
            folder = self.directory / job_id
            folder.mkdir()
            job = {**(meta or {}), "id": job_id, "kind": kind, "status": "queued",
                   "created_at": datetime.now(timezone.utc).isoformat()}
            self.jobs[job_id] = job
            self.cancellations[job_id] = threading.Event()
            self._update(job_id)
            # Scan commands need their allocated output directory.
            argv = command(folder) if callable(command) else command
            self.pending.put_nowait((job_id, argv, finalize))
            return self.get(job_id)

    def cancel(self, job_id):
        with self.lock:
            job = self.jobs[job_id]
            if job["status"] not in TERMINAL:
                self.cancellations[job_id].set()
                status = "cancelled" if job["status"] == "queued" else "cancelling"
                self._update(job_id, status=status)
            return self.get(job_id)

    def events(self, job_id, cursor=0, limit=200):
        with self.lock:
            self.get(job_id)
            events = []
            path = self.directory / job_id / "events.jsonl"
            if not path.exists():
                return {"events": [], "cursor": 0}
            with path.open("rb") as stream:
                stream.seek(min(max(0, cursor), path.stat().st_size))
                for _ in range(min(max(1, limit), 200)):
                    start = stream.tell()
                    line = stream.readline()
                    if not line.endswith(b"\n"):
                        stream.seek(start)
                        break
                    try:
                        events.append(json.loads(line))
                    except ValueError:
                        continue
                return {"events": events, "cursor": stream.tell()}

    @staticmethod
    def _stop(process):
        # Each job owns a session, including subprocesses started by its CLI.
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(process.pid, sig)
            except OSError:
                break
            if sig == signal.SIGTERM:
                time.sleep(0.1)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.kill(process.pid, signal.SIGKILL)
            except OSError:
                pass
            process.wait(timeout=5)

    def _work(self):
        while not self.stopping.is_set() or not self.pending.empty():
            try:
                job_id, command, finalize = self.pending.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                self._execute(job_id, command, finalize)
            except Exception as exc:
                with self.lock:
                    job = self.jobs.get(job_id)
                    if job and job.get("status") not in TERMINAL:
                        job["error"] = str(exc)
                        try:
                            self._update(job_id, status="failed", error=str(exc))
                        except OSError:
                            job["status"] = "failed"
            finally:
                with self.lock:
                    self.cancellations.pop(job_id, None)
                self.pending.task_done()

    def _execute(self, job_id, command, finalize):
        process = None
        extra = {}
        status = "failed"
        cancel = None
        try:
            with self.lock:
                cancel = self.cancellations[job_id]
                if cancel.is_set():
                    return
                self._update(job_id, status="running")
            self._event(job_id, {"type": "started", "command": command[1:]})
            process = subprocess.Popen(command, cwd=self.cwd, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, start_new_session=True,
                                       env={**os.environ, "PYTHONUNBUFFERED": "1"})
            self._update(job_id, pid=process.pid, process_start=process_start(process.pid))
            deadline = time.monotonic() + self.timeout
            decoder = codecs.getincrementaldecoder("utf-8")("replace")
            buffer = ""

            def emit(text):
                nonlocal buffer
                buffer += text
                lines = re.split(r"[\r\n]", buffer)
                buffer = lines.pop()
                for line in lines:
                    if line.strip():
                        self._event(job_id, {"type": "log", "message": line[:8192]})
                if len(buffer) >= 8192:
                    self._event(job_id, {"type": "log", "message": buffer[:8192]})
                    buffer = buffer[8192:]

            with process.stdout, selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map() or process.poll() is None:
                    if cancel.is_set() or time.monotonic() >= deadline:
                        status = "cancelled" if cancel.is_set() else "timed_out"
                        self._stop(process)
                        break
                    for key, _ in selector.select(timeout=0.05):
                        chunk = os.read(key.fd, 8192)
                        if chunk:
                            emit(decoder.decode(chunk))
                        else:
                            selector.unregister(key.fileobj)
                emit(decoder.decode(b"", final=True) + "\n")
            return_code = process.wait()
            extra["return_code"] = return_code
            if status not in {"cancelled", "timed_out"}:
                extra.update(finalize(self.directory / job_id, return_code) if finalize else {})
                status = extra.pop("status", "completed" if return_code == 0 else "failed")
        except Exception as exc:
            extra["error"] = str(exc)
        finally:
            if process is not None and process.poll() is None:
                try:
                    self._stop(process)
                except OSError as exc:
                    extra.setdefault("error", str(exc))
            with self.lock:
                # Cancel can arrive after the process exits and before this write.
                if self.jobs[job_id]["status"] == "cancelled" or (
                    cancel is not None and cancel.is_set() and status != "timed_out"
                ):
                    status = "cancelled"
                try:
                    self._update(job_id, status=status, **extra)
                except OSError as exc:
                    self.jobs[job_id].update(status=status, error=str(exc))
                finished = self.jobs[job_id]["status"]
            self._event(job_id, {"type": "finished", "status": finished, **extra})

    def close(self):
        self.stopping.set()
        with self.lock:
            for job_id in list(self.cancellations):
                self.cancel(job_id)
        for worker in self.workers:
            worker.join()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
