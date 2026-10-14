import json
import os
import signal
import subprocess
import sys
import time

import pytest

from reports.api.jobs import JobManager, QueueFull, process_start


def wait_for(predicate):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.01)
    pytest.fail("Job did not reach the expected state")


@pytest.fixture
def manager(tmp_path):
    runner = JobManager(tmp_path, workers=1, queue_size=1, timeout=5)
    yield runner
    runner.close()


def command(code):
    return [sys.executable, "-u", "-c", code]


def test_output_streams_before_exit_and_cursor_does_not_repeat(manager):
    job = manager.submit("test", command("import time; print('ready'); time.sleep(1); print('done')"))
    def ready():
        page = manager.events(job["id"])
        return page if any(e.get("message") == "ready" for e in page["events"]) else None

    first = wait_for(ready)
    assert manager.get(job["id"])["status"] == "running"
    wait_for(lambda: manager.get(job["id"])["status"] == "completed")
    next_page = manager.events(job["id"], first["cursor"])
    assert [event["message"] for event in next_page["events"] if event["type"] == "log"] == ["done"]
    assert manager.events(job["id"], next_page["cursor"])["events"] == []


def test_queue_is_bounded_and_queued_cancel_prevents_execution(manager, tmp_path):
    active = manager.submit("test", command("import time; time.sleep(60)"))
    wait_for(lambda: manager.get(active["id"])["status"] == "running")
    marker = tmp_path / "unexpected"
    queued = manager.submit("test", command(f"from pathlib import Path; Path({str(marker)!r}).touch()"))
    with pytest.raises(QueueFull):
        manager.submit("test", command("pass"))
    assert manager.cancel(queued["id"])["status"] == "cancelled"
    manager.cancel(active["id"])
    wait_for(lambda: manager.get(active["id"])["status"] == "cancelled")
    assert not marker.exists()


def test_timeout_stops_child_process_group(tmp_path):
    marker = tmp_path / "descendant"
    child = f"import time; from pathlib import Path; time.sleep(1); Path({str(marker)!r}).touch()"
    with JobManager(tmp_path / "runs", workers=1, timeout=0.2) as manager:
        job = manager.submit("test", command(f"import subprocess, sys, time; subprocess.Popen([sys.executable, '-c', {child!r}]); time.sleep(60)"))
        wait_for(lambda: manager.get(job["id"])["status"] == "timed_out")
    time.sleep(1)
    assert not marker.exists()


def test_restart_restores_history_and_marks_unfinished_jobs(tmp_path):
    for job_id, status in [("old", "running"), ("done", "completed")]:
        folder = tmp_path / job_id
        folder.mkdir()
        (folder / "job.json").write_text(json.dumps({"id": job_id, "kind": "scan", "status": status}))
    with JobManager(tmp_path) as manager:
        assert manager.get("old")["status"] == "interrupted"
        assert manager.get("done")["status"] == "completed"
        assert len(manager.list()) == 2
    assert json.loads((tmp_path / "old/job.json").read_text())["status"] == "interrupted"


def test_finalize_exception_does_not_leave_job_running(manager):
    def broken(*_):
        raise ValueError("report invalid")

    job = manager.submit("test", command("pass"), finalize=broken)
    wait_for(lambda: manager.get(job["id"])["status"] == "failed")
    assert manager.get(job["id"])["error"] == "report invalid"


def test_cancel_during_finalize_is_not_overwritten(manager):
    def finalize(folder, _code):
        manager.cancel(folder.name)
        return {"status": "completed"}

    job = manager.submit("test", command("pass"), finalize=finalize)
    wait_for(lambda: manager.get(job["id"])["status"] in {"cancelled", "completed", "failed"})
    assert manager.get(job["id"])["status"] == "cancelled"


def test_launch_failure_is_recorded(manager):
    job = manager.submit("test", ["/no/such/dread-binary"])
    wait_for(lambda: manager.get(job["id"])["status"] == "failed")
    assert manager.get(job["id"])["error"]


def test_restart_reaps_orphaned_process_group(tmp_path):
    marker = tmp_path / "orphan-lived"
    child = (
        "import time; from pathlib import Path; "
        f"time.sleep(30); Path({str(marker)!r}).write_text('x')"
    )
    parent = subprocess.Popen(
        [sys.executable, "-c",
         "import subprocess, sys, time; "
         f"subprocess.Popen([sys.executable, '-c', {child!r}]); "
         "time.sleep(60)"],
        start_new_session=True,
    )
    try:
        started = process_start(parent.pid)
        assert started
        folder = tmp_path / "stuck"
        folder.mkdir()
        (folder / "job.json").write_text(json.dumps({
            "id": "stuck", "kind": "scan", "status": "running",
            "pid": parent.pid, "process_start": started,
        }))
        with JobManager(tmp_path) as manager:
            assert manager.get("stuck")["status"] == "interrupted"
        parent.wait(timeout=2)
        assert not marker.exists()
    finally:
        if parent.poll() is None:
            os.killpg(parent.pid, signal.SIGKILL)
            parent.wait(timeout=2)


def test_restart_does_not_kill_a_reused_pid(tmp_path):
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True,
    )
    try:
        folder = tmp_path / "stuck"
        folder.mkdir()
        (folder / "job.json").write_text(json.dumps({
            "id": "stuck", "kind": "scan", "status": "running",
            "pid": proc.pid, "process_start": "not-this-process",
        }))
        with JobManager(tmp_path) as manager:
            assert manager.get("stuck")["status"] == "interrupted"
        assert proc.poll() is None
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=2)


def test_shutdown_cancels_running_jobs(tmp_path):
    manager = JobManager(tmp_path)
    job = manager.submit("test", command("import time; time.sleep(60)"))
    wait_for(lambda: manager.get(job["id"])["status"] == "running")
    manager.close()
    assert manager.get(job["id"])["status"] == "cancelled"
