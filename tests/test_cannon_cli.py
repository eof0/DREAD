from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest import mock

_CANNON = Path(__file__).resolve().parents[1] / "cannon"
if str(_CANNON) not in sys.path:
    sys.path.insert(0, str(_CANNON))

import packages  # noqa: E402
import runner  # noqa: E402


def _load_cli():
    spec = importlib.util.spec_from_file_location("cannon_cli", _CANNON / "cannon.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cli = _load_cli()


def _run(argv):
    with mock.patch.object(sys, "argv", ["cannon"] + argv):
        return cli.main()


def test_info_and_version_ok(capsys):
    assert _run(["info"]) == 0
    assert _run(["version"]) == 0
    assert "Cannon" in capsys.readouterr().out


def test_tools_reports_availability(capsys, monkeypatch):
    monkeypatch.setattr(runner, "which", lambda b: "/usr/bin/nmap" if b == "nmap" else None)
    monkeypatch.setattr(packages, "detect_manager", lambda: None)
    assert _run(["tools"]) == 0
    out = capsys.readouterr().out
    assert "nmap" in out
    assert "available" in out
    assert "missing" in out


def test_run_refuses_without_authorization(capsys, monkeypatch):
    called = mock.Mock()
    monkeypatch.setattr(runner, "run", called)
    code = _run(["run", "nmap", "example.test"])
    assert code == 2
    assert "authorized" in capsys.readouterr().err.lower()
    called.assert_not_called()


def test_run_rejects_unknown_tool():
    assert _run(["run", "bogus", "example.test", "--authorized"]) == 2


def test_run_reports_missing_binary(monkeypatch):
    monkeypatch.setattr(runner, "which", lambda b: None)
    monkeypatch.setattr(packages, "detect_manager", lambda: None)
    assert _run(["run", "nmap", "example.test", "--authorized"]) == 3


def test_tools_json_includes_install_for_missing(capsys, monkeypatch):
    import json

    monkeypatch.setattr(runner, "which", lambda b: None)  # everything missing
    monkeypatch.setattr(
        packages,
        "install_guidance",
        lambda binary, pkgs=None: {"manager": "pacman", "available": True, "command": f"sudo pacman -S --needed {binary}"},
    )
    assert _run(["tools", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data and all(entry["available"] is False for entry in data)
    assert all("install" in entry and entry["install"]["command"] for entry in data)


def test_run_executes_authorized_tool(monkeypatch, capsys):
    monkeypatch.setattr(runner, "which", lambda b: "/usr/bin/nmap")
    seen = {}

    def fake_run(tool, argv, timeout=120.0):
        seen["tool"] = tool
        seen["argv"] = argv
        return runner.ToolResult(tool, argv, 0, "scan output", "", 1.2, False)

    monkeypatch.setattr(runner, "run", fake_run)
    code = _run(["run", "nmap", "example.test", "--authorized"])
    assert code == 0
    assert seen["tool"] == "nmap"
    assert "example.test" in seen["argv"]
    assert "scan output" in capsys.readouterr().out


def test_tools_json_output(capsys, monkeypatch):
    import json

    monkeypatch.setattr(runner, "which", lambda b: "/usr/bin/nmap" if b == "nmap" else None)
    monkeypatch.setattr(packages, "detect_manager", lambda: None)
    assert _run(["tools", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    by = {t["name"]: t for t in data}
    assert by["nmap"]["available"] is True
    assert by["nmap"]["path"] == "/usr/bin/nmap"
    assert by["wrk"]["available"] is False


def test_run_json_output(monkeypatch, capsys):
    import json

    monkeypatch.setattr(runner, "which", lambda b: "/usr/bin/nmap")
    monkeypatch.setattr(
        runner,
        "run",
        lambda tool, argv, timeout=120.0: runner.ToolResult(tool, argv, 0, "out", "", 1.2, False),
    )
    assert _run(["run", "nmap", "example.test", "--authorized", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["tool"] == "nmap"
    assert data["returncode"] == 0
    assert data["timed_out"] is False
    assert "example.test" in data["argv"]


def _fake_result(tool, argv, rc=0, timed_out=False):
    return runner.ToolResult(tool, argv, rc, "", "", 0.1, timed_out)


def test_kaboom_refuses_without_authorization(monkeypatch):
    monkeypatch.setattr(runner, "run", mock.Mock())
    assert _run(["kaboom", "example.test", "--mode", "all"]) == 2


def test_kaboom_all_runs_every_available_tool(monkeypatch, capsys):
    present = {"nmap", "wrk"}
    monkeypatch.setattr(runner, "which", lambda b: f"/usr/bin/{b}" if b in present else None)
    ran = []

    def fake_run(tool, argv, timeout=120.0):
        ran.append((tool, argv))
        return _fake_result(tool, argv)

    monkeypatch.setattr(runner, "run", fake_run)
    code = _run(["kaboom", "example.test", "--mode", "all", "--authorized"])
    assert code == 0
    names = [t for t, _ in ran]
    assert names == ["nmap", "wrk"]  # recon before load, only available ones


def test_kaboom_load_uses_heavy_argv(monkeypatch):
    monkeypatch.setattr(runner, "which", lambda b: "/usr/bin/wrk" if b == "wrk" else None)
    ran = []
    monkeypatch.setattr(
        runner, "run", lambda tool, argv, timeout=120.0: ran.append((tool, argv)) or _fake_result(tool, argv)
    )
    code = _run(["kaboom", "example.test", "--mode", "load", "--authorized"])
    assert code == 0
    assert ran and ran[0][0] == "wrk"
    assert "-c100" in ran[0][1]  # heavy template


def test_kaboom_reports_when_nothing_installed(monkeypatch):
    monkeypatch.setattr(runner, "which", lambda b: None)
    monkeypatch.setattr(runner, "run", mock.Mock())
    assert _run(["kaboom", "example.test", "--mode", "all", "--authorized"]) == 3


def test_kaboom_menu_prompts_when_mode_omitted(monkeypatch):
    monkeypatch.setattr(runner, "which", lambda b: "/usr/bin/nmap" if b == "nmap" else None)
    ran = []
    monkeypatch.setattr(
        runner, "run", lambda tool, argv, timeout=120.0: ran.append(tool) or _fake_result(tool, argv)
    )
    monkeypatch.setattr(cli, "input", lambda _prompt="": "1", raising=False)
    assert _run(["kaboom", "example.test", "--authorized"]) == 0
    assert ran == ["nmap"]


def test_bad_config_reports_cleanly(capsys):
    code = _run(["tools", "--config", "/no/such/catalog.json"])
    assert code == 2
    assert "Invalid tools catalog" in capsys.readouterr().err


def test_malformed_config_reports_cleanly(tmp_path, capsys):
    # A JSON string / object / list-of-scalars must produce the clean catalog
    # error + exit 2, not a raw TypeError traceback or a silently-empty catalog.
    for payload in ('"nope"', "{}", "[1, 2]"):
        cfg = tmp_path / "bad.json"
        cfg.write_text(payload)
        code = _run(["tools", "--config", str(cfg)])
        assert code == 2, payload
        assert "Invalid tools catalog" in capsys.readouterr().err


def test_run_nonzero_tool_exit_reported_as_failure(monkeypatch):
    monkeypatch.setattr(runner, "which", lambda b: "/usr/bin/nmap")
    monkeypatch.setattr(
        runner,
        "run",
        lambda tool, argv, timeout=120.0: runner.ToolResult(tool, argv, 1, "", "boom", 0.1, False),
    )
    assert _run(["run", "nmap", "example.test", "--authorized"]) == 1


def test_run_json_nonzero_tool_exit_reported_as_failure(monkeypatch, capsys):
    monkeypatch.setattr(runner, "which", lambda b: "/usr/bin/nmap")
    monkeypatch.setattr(
        runner,
        "run",
        lambda tool, argv, timeout=120.0: runner.ToolResult(tool, argv, 2, "", "", 0.1, False),
    )
    assert _run(["run", "nmap", "example.test", "--authorized", "--json"]) == 1


def test_kaboom_nonzero_tool_exit_reported_as_failure(monkeypatch):
    monkeypatch.setattr(runner, "which", lambda b: "/usr/bin/nmap" if b == "nmap" else None)
    monkeypatch.setattr(
        runner,
        "run",
        lambda tool, argv, timeout=120.0: runner.ToolResult(tool, argv, 3, "", "", 0.1, False),
    )
    assert _run(["kaboom", "example.test", "--mode", "all", "--authorized"]) == 1


def test_run_rejects_dash_prefixed_target(monkeypatch, capsys):
    # A target like "-oN/tmp/x" must not reach the tool as a flag (argument
    # injection). It is only forceable past argparse with "--", so test that path.
    monkeypatch.setattr(runner, "which", lambda b: "/usr/bin/nmap")
    called = mock.Mock()
    monkeypatch.setattr(runner, "run", called)
    code = _run(["run", "nmap", "--authorized", "--", "-oN/tmp/x"])
    assert code == 2
    called.assert_not_called()
    assert "target" in capsys.readouterr().err.lower()


def test_kaboom_rejects_dash_prefixed_target(monkeypatch):
    monkeypatch.setattr(runner, "which", lambda b: "/usr/bin/nmap")
    called = mock.Mock()
    monkeypatch.setattr(runner, "run", called)
    code = _run(["kaboom", "--mode", "all", "--authorized", "--", "--data=x"])
    assert code == 2
    called.assert_not_called()


def test_kaboom_json_no_mode_noninteractive_exits_clean(monkeypatch, capsys):
    monkeypatch.setattr(runner, "which", lambda b: "/usr/bin/nmap" if b == "nmap" else None)
    monkeypatch.setattr(runner, "run", mock.Mock())

    def raise_eof(*_a, **_k):
        raise EOFError

    monkeypatch.setattr(cli, "input", raise_eof, raising=False)
    code = _run(["kaboom", "example.test", "--authorized", "--json"])
    assert code == 2
    captured = capsys.readouterr()
    assert "modes:" not in captured.out  # menu must not corrupt stdout/json


def test_kaboom_menu_goes_to_stderr(monkeypatch, capsys):
    monkeypatch.setattr(runner, "which", lambda b: "/usr/bin/nmap" if b == "nmap" else None)
    monkeypatch.setattr(
        runner, "run", lambda tool, argv, timeout=120.0: _fake_result(tool, argv)
    )
    monkeypatch.setattr(cli, "input", lambda *_a, **_k: "1", raising=False)
    assert _run(["kaboom", "example.test", "--authorized"]) == 0
    captured = capsys.readouterr()
    assert "modes:" in captured.err
    assert "modes:" not in captured.out
