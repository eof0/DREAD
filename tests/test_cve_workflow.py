from __future__ import annotations

from pathlib import Path

import yaml


def test_cve_workflow_has_safe_producer_contract() -> None:
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load(
        (root / ".github/workflows/update-cve-db.yml").read_text(encoding="utf-8")
    )
    triggers = workflow.get("on", workflow.get(True))
    job = workflow["jobs"]["sync-and-publish"]
    steps = job["steps"]
    names = [step.get("name") for step in steps]

    assert triggers["schedule"][0]["cron"] == "17 6 * * *"
    assert "full_rebuild" in triggers["workflow_dispatch"]["inputs"]
    assert workflow["permissions"]["contents"] == "write"
    assert workflow["concurrency"]["group"] == "cve-db-producer"
    assert job["timeout-minutes"] == 360
    assert steps[0]["with"]["persist-credentials"] is False
    assert next(step for step in steps if step.get("uses") == "actions/setup-python@v5")["with"]["python-version"] == "3.13"
    assert job["env"]["NVD_API_KEY"] == "${{ secrets.NVD_API_KEY }}"
    assert names.index("Restore previous snapshot") < names.index("Update canonical database")
    assert "build_cve_snapshot.py" in next(step["run"] for step in steps if step.get("name") == "Build snapshot")
    assert "update_cve_snapshot_release.sh" in next(step["run"] for step in steps if step.get("name") == "Publish releases")


def test_release_script_keeps_database_releases_out_of_latest() -> None:
    root = Path(__file__).resolve().parents[1]
    script = (root / "scripts/update_cve_snapshot_release.sh").read_text(encoding="utf-8")
    assert "cve-db-latest" in script
    assert "--latest=false" in script
    assert "--clobber" in script
