"""Browser regressions against the built dashboard and local API."""

import functools
import http.server
import json
import os
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("DREAD_TEST_BROWSER") != "1", reason="Set DREAD_TEST_BROWSER=1 after building the dashboard")
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def report():
    from reports.aggregate import build_unified_report

    return build_unified_report(
        reports_schema_version="1.0", run_id="browser", title="Browser assessment",
        probe_reports=[("probe", {"target": "http://localhost", "scan_id": "browser",
            "statistics": {"risk": {"level": "critical", "normalized_score": 95}, "urls_scanned": 3, "partial": True},
            "findings": [{"title": "Example finding", "severity": "critical", "plugin_name": "test", "url": "http://localhost"}],
        })], scope_report=None, include_probe=True, include_scope=False,
    )


@pytest.fixture
def page():
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1365, "height": 900})
        yield page
        browser.close()


@pytest.fixture
def application(tmp_path, monkeypatch, report):
    import uvicorn
    import reports.api.app as api

    runs = tmp_path / "runs"
    output = runs / "finished/run_browser/suite_report/dread_suite_report.json"
    output.parent.mkdir(parents=True)
    output.write_text(json.dumps(report))
    old = runs / "interrupted"
    old.mkdir()
    (old / "job.json").write_text(json.dumps({"id": "interrupted", "kind": "scope.discover", "status": "running", "created_at": "2000"}))
    monkeypatch.setattr(api, "RUNS_DIR", runs)
    monkeypatch.setenv("DREAD_JOB_WORKERS", "1")
    monkeypatch.setenv("DREAD_JOB_QUEUE_SIZE", "1")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        server = uvicorn.Server(uvicorn.Config(api.app, log_level="error"))
        thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
        thread.start()
        deadline = time.monotonic() + 5
        while not server.started:
            assert thread.is_alive() and time.monotonic() < deadline
            time.sleep(0.01)
        yield f"http://127.0.0.1:{listener.getsockname()[1]}", api.app.state.jobs
        server.should_exit = True
        thread.join(timeout=10)
        assert not thread.is_alive()


def test_live_report_uses_suite_risk_contract(page, application):
    from playwright.sync_api import expect

    url, _ = application
    page.goto(url)
    expect(page.locator(".risk-score strong")).to_have_text("95")
    expect(page.locator(".risk-level")).to_have_text("critical")
    expect(page.get_by_role("status")).to_contain_text("Incomplete assessment")
    assert page.request.get(url + "/api/runs").json()[0]["risk_level"] == "critical"
    page.screenshot(path="/tmp/dread-dashboard-report.png", full_page=True)


def test_job_survives_navigation_reload_and_can_be_cancelled(page, application):
    from playwright.sync_api import expect

    url, manager = application
    job = manager.submit("scan", [sys.executable, "-u", "-c", "import time; print('scan running'); time.sleep(60)"], {"target": "localhost"})
    page.goto(url)
    page.get_by_role("button", name="Full scan", exact=True).click()
    expect(page.get_by_role("log")).to_contain_text("scan running")
    page.get_by_role("button", name="Discovery", exact=True).click()
    expect(page.get_by_role("log")).to_contain_text("interrupted")
    page.get_by_role("button", name="Full scan", exact=True).click()
    expect(page.get_by_role("log")).to_contain_text("scan running")
    page.reload()
    page.get_by_role("button", name="Full scan", exact=True).click()
    expect(page.get_by_role("log")).to_contain_text("scan running")
    page.get_by_role("button", name="Cancel", exact=True).click()
    expect(page.locator(".status-pill")).to_have_text("cancelled")
    assert manager.get(job["id"])["status"] == "cancelled"


def test_missing_job_stops_polling_and_shows_error(page, application):
    from playwright.sync_api import expect

    url, manager = application
    job = manager.submit("scan", [sys.executable, "-c", "import time; time.sleep(60)"])
    page.route(f"**/api/jobs/{job['id']}", lambda route: route.fulfill(status=404, json={"detail": "Job not found"}))
    page.goto(url)
    page.get_by_role("button", name="Full scan", exact=True).click()
    expect(page.locator(".form-error")).to_have_text("Job not found")
    expect(page.locator(".status-pill")).to_have_text("interrupted")
    expect(page.get_by_role("button", name="Cancel", exact=True)).to_have_count(0)


def test_queue_full_returns_429(page, application):
    url, manager = application
    first = manager.submit("test", [sys.executable, "-c", "import time; time.sleep(60)"])
    deadline = time.monotonic() + 5
    while manager.get(first["id"])["status"] != "running":
        assert time.monotonic() < deadline
        time.sleep(0.01)
    manager.submit("test", [sys.executable, "-c", "pass"])
    response = page.request.post(url + "/api/db/update")
    assert response.status == 429


def test_exported_dashboard_runs_without_api(page, tmp_path, report):
    from playwright.sync_api import expect
    from reports.dashboard_writer import write_dashboard_bundle

    index, error = write_dashboard_bundle(report, tmp_path, ROOT / "reports/dashboard", try_build=False)
    assert not error
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(index.parent))
    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        requests = []
        page.on("request", lambda request: requests.append(request.url))
        page.goto(f"http://127.0.0.1:{server.server_port}")
        expect(page.locator(".risk-score strong")).to_have_text("95")
        expect(page.get_by_text("Example finding", exact=True)).to_be_visible()
        expect(page.get_by_role("button", name="Full scan", exact=True)).to_have_count(0)
        assert not any("/api/" in request for request in requests)
        page.set_viewport_size({"width": 390, "height": 844})
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        page.screenshot(path="/tmp/dread-dashboard-mobile.png", full_page=True)
        server.shutdown()
        thread.join()
