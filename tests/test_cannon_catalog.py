from __future__ import annotations

import sys
from pathlib import Path

import pytest

_CANNON = Path(__file__).resolve().parents[1] / "cannon"
if str(_CANNON) not in sys.path:
    sys.path.insert(0, str(_CANNON))

from catalog import CATALOG, build_argv, by_name


def test_catalog_entries_are_well_formed():
    assert CATALOG
    for tool in CATALOG:
        assert tool.name and tool.binary
        assert tool.category in {"load", "recon"}
        assert "{target}" in " ".join(tool.argv)


def test_by_name_lookup():
    assert by_name("nmap") is not None
    assert by_name("nope") is None


def test_build_argv_substitutes_target():
    tool = by_name("nmap")
    argv = build_argv(tool, "example.test")
    assert argv[0] == tool.binary
    assert "example.test" in argv
    assert "{target}" not in " ".join(argv)


def test_build_argv_heavy_uses_high_intensity_template():
    wrk = by_name("wrk")
    assert wrk.heavy is not None
    heavy = build_argv(wrk, "https://example.test", heavy=True)
    light = build_argv(wrk, "https://example.test", heavy=False)
    assert heavy != light
    assert "-c100" in heavy


def test_recon_tool_without_heavy_falls_back_to_default():
    nmap = by_name("nmap")
    assert nmap.heavy is None
    assert build_argv(nmap, "t", heavy=True) == build_argv(nmap, "t", heavy=False)


def test_load_catalog_reads_a_custom_config(tmp_path):
    from catalog import load_catalog

    cfg = tmp_path / "tools.json"
    cfg.write_text(
        '[{"name": "curl", "binary": "curl", "category": "load", '
        '"description": "probe", "argv": ["{target}"]}]'
    )
    tools = load_catalog(cfg)
    assert len(tools) == 1
    assert tools[0].name == "curl"
    assert by_name("curl", tools) is not None


def test_build_argv_tolerates_braces_in_custom_args(tmp_path):
    from catalog import Tool, build_argv

    tool = Tool("x", "x", "recon", "d", ("-p{1-100}", "{target}"))
    argv = build_argv(tool, "host")
    assert argv == ["x", "-p{1-100}", "host"]


@pytest.mark.parametrize("payload", ['"just a string"', "42", "{}", '{"name": "x"}'])
def test_load_catalog_rejects_non_array_top_level(tmp_path, payload):
    from catalog import load_catalog

    cfg = tmp_path / "tools.json"
    cfg.write_text(payload)
    # A structurally wrong catalog must raise ValueError (which the CLI catches),
    # never a raw TypeError or a silently-empty catalog.
    with pytest.raises(ValueError):
        load_catalog(cfg)


@pytest.mark.parametrize("payload", ["[1, 2, 3]", '["a", "b"]', "[[], []]"])
def test_load_catalog_rejects_non_object_entries(tmp_path, payload):
    from catalog import load_catalog

    cfg = tmp_path / "tools.json"
    cfg.write_text(payload)
    with pytest.raises(ValueError):
        load_catalog(cfg)


def test_catalog_global_is_not_parsed_at_import():
    import catalog as c

    # The bundled catalog is served lazily via module __getattr__, not parsed at
    # import time, so a corrupt tools.json cannot crash `import catalog`.
    assert "CATALOG" not in vars(c)
    assert c.CATALOG  # still resolvable on demand
