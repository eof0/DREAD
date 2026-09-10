from __future__ import annotations

import json
from unittest import mock

import pytest

import products
from dread import main as dread_main


def test_suite_version_defined() -> None:
    assert products.SUITE_VERSION
    assert isinstance(products.SUITE_VERSION, str)


def test_dread_version_stdout(capsys) -> None:
    with mock.patch("sys.argv", ["dread", "version"]):
        code = dread_main()
    assert code == 0
    assert products.SUITE_VERSION in capsys.readouterr().out


def test_products_json_stdout(capsys) -> None:
    with mock.patch("sys.argv", ["dread", "products", "--json"]):
        code = dread_main()
    assert code == 0
    data = json.loads(capsys.readouterr().out)
    assert isinstance(data, list)
    assert {p["cli_name"] for p in data} >= {"probe", "scope", "reports"}


def test_scan_command_runs_full_scan() -> None:
    with (
        mock.patch("dread.full_scan", return_value=0) as full_scan_mock,
        mock.patch("sys.argv", ["dread", "scan", "example.com"]),
    ):
        code = dread_main()
    assert code == 0
    full_scan_mock.assert_called_once()


def test_full_scan_alias_still_runs_full_scan() -> None:
    with (
        mock.patch("dread.full_scan", return_value=0) as full_scan_mock,
        mock.patch("sys.argv", ["dread", "full-scan", "example.com"]),
    ):
        code = dread_main()
    assert code == 0
    full_scan_mock.assert_called_once()


def test_update_cve_db_passthrough() -> None:
    completed = mock.Mock(returncode=0)
    with (
        mock.patch("subprocess.run", return_value=completed) as run_mock,
        mock.patch("sys.argv", ["dread", "update-cve-db", "--days", "7"]),
    ):
        code = dread_main()
    assert code == 0
    run_mock.assert_called_once()
    cmd = run_mock.call_args.args[0]
    assert cmd[2] == "update-cve-db"
    assert "--days" in cmd
    assert "7" in cmd


def test_update_cve_db_default_preserves_snapshot_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    completed = mock.Mock(returncode=0)
    run_mock = mock.Mock(return_value=completed)
    monkeypatch.setattr("subprocess.run", run_mock)
    monkeypatch.setattr("sys.argv", ["dread", "update-cve-db"])
    code = dread_main()
    assert code == 0
    assert run_mock.call_args.args[0][2:] == ["update-cve-db"]


def test_update_cve_db_snapshot_flags_are_forwarded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    completed = mock.Mock(returncode=0)
    for flag in ("--snapshot-only", "--no-snapshot", "--raw-full"):
        run_mock = mock.Mock(return_value=completed)
        monkeypatch.setattr("subprocess.run", run_mock)
        monkeypatch.setattr("sys.argv", ["dread", "update-cve-db", flag])
        code = dread_main()
        assert code == 0
        assert flag in run_mock.call_args.args[0]


def test_update_db_passthrough_to_asn_updater() -> None:
    completed = mock.Mock(returncode=0)
    with (
        mock.patch("subprocess.run", return_value=completed) as run_mock,
        mock.patch("sys.argv", ["dread", "update-db", "--force"]),
    ):
        code = dread_main()
    assert code == 0
    run_mock.assert_called_once()
    cmd = run_mock.call_args.args[0]
    assert cmd[2] == "update-asn-db"
    assert "--force" in cmd


def test_cve_stats_passthrough() -> None:
    completed = mock.Mock(returncode=0)
    with (
        mock.patch("subprocess.run", return_value=completed) as run_mock,
        mock.patch("sys.argv", ["dread", "cve-stats"]),
    ):
        code = dread_main()
    assert code == 0
    run_mock.assert_called_once()
    assert run_mock.call_args.args[0][2] == "cve-stats"


def test_profiles_passthrough() -> None:
    completed = mock.Mock(returncode=0)
    with (
        mock.patch("subprocess.run", return_value=completed) as run_mock,
        mock.patch("sys.argv", ["dread", "profiles"]),
    ):
        code = dread_main()
    assert code == 0
    run_mock.assert_called_once()
    assert run_mock.call_args.args[0][2] == "profiles"


def test_light_scan_passthrough_to_probe_scan() -> None:
    completed = mock.Mock(returncode=0)
    with (
        mock.patch("subprocess.run", return_value=completed) as run_mock,
        mock.patch("sys.argv", ["dread", "light-scan", "example.com"]),
    ):
        code = dread_main()
    assert code == 0
    run_mock.assert_called_once()
    cmd = run_mock.call_args.args[0]
    assert cmd[2] == "scan"
    assert "example.com" in cmd
