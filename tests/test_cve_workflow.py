from __future__ import annotations

import os
import subprocess
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
    publish = next(step for step in steps if step.get("name") == "Publish snapshot")
    assert "update_cve_snapshot_release.sh" in publish["run"]
    assert publish["env"]["PREVIOUS_MANIFEST"]


def test_daily_snapshot_updates_one_release(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "cve_db.sqlite.gz").write_bytes(b"snapshot")
    (dist / "manifest.json").write_text("{}")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    gh = bin_dir / "gh"
    gh.write_text(
        "#!/usr/bin/env python3\n"
        "import os, sys\n"
        "from pathlib import Path\n"
        "state = Path(os.environ['FAKE_RELEASE_STATE'])\n"
        "log = Path(os.environ['FAKE_GH_LOG'])\n"
        "command, tag = sys.argv[2:4]\n"
        "with log.open('a') as output: output.write(f'{command} {tag}\\n')\n"
        "if command == 'view': sys.exit(0 if tag in state.read_text().splitlines() else 1)\n"
        "if command == 'create': state.write_text(state.read_text() + tag + '\\n')\n"
    )
    gh.chmod(0o755)
    state = tmp_path / "releases"
    state.write_text("")
    log = tmp_path / "gh.log"
    env = os.environ | {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "FAKE_RELEASE_STATE": str(state),
        "FAKE_GH_LOG": str(log),
    }

    for _ in range(2):
        subprocess.run(
            ["bash", str(root / "scripts/update_cve_snapshot_release.sh"), str(dist)],
            check=True,
            env=env,
        )

    assert state.read_text().splitlines() == ["cve-db-latest"]
    assert log.read_text().splitlines()[-1] == "upload cve-db-latest"


def test_daily_snapshot_skips_unchanged_upload(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "cve_db.sqlite.gz").write_bytes(b"snapshot")
    manifest = {"sha256_gz": "abc123"}
    (dist / "manifest.json").write_text(__import__("json").dumps(manifest))
    previous = tmp_path / "previous"
    previous.mkdir()
    (previous / "manifest.json").write_text(__import__("json").dumps(manifest))
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    gh = bin_dir / "gh"
    gh.write_text("#!/usr/bin/env python3\nimport sys\nsys.exit(1)\n")
    gh.chmod(0o755)
    env = os.environ | {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "PREVIOUS_MANIFEST": str(previous / "manifest.json"),
    }

    subprocess.run(
        ["bash", str(root / "scripts/update_cve_snapshot_release.sh"), str(dist)],
        check=True,
        env=env,
    )
