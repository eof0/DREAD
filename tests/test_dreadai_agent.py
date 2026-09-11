"""DreadAI agent: LangSmith tracing config and the expanded tool surface (no LLM calls)."""

from __future__ import annotations

import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_DREADAI = _REPO / "dreadai"
for p in (str(_REPO), str(_DREADAI)):
    if p not in sys.path:
        sys.path.insert(0, p)

import os

import pytest

import agent


@pytest.fixture(autouse=True)
def _isolate_tracing_env():
    """Keep LangSmith tracing off and prevent env leaks (and 403 trace spam) between tests."""
    keys = ["LANGCHAIN_TRACING_V2", "LANGSMITH_TRACING", "LANGCHAIN_PROJECT",
            "LANGCHAIN_API_KEY", "LANGSMITH_API_KEY", "DREADAI_LANGSMITH_PROJECT"]
    saved = {k: os.environ.get(k) for k in keys}
    for k in keys:
        os.environ.pop(k, None)
    yield
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


# --- LangSmith tracing -------------------------------------------------------

def test_tracing_is_noop_without_key(monkeypatch):
    for var in ("LANGSMITH_API_KEY", "LANGCHAIN_API_KEY", "LANGCHAIN_TRACING_V2",
                "LANGSMITH_TRACING"):
        monkeypatch.delenv(var, raising=False)

    result = agent.configure_tracing()

    assert result["enabled"] is False
    # Must not have turned tracing on with no key.
    import os
    assert os.environ.get("LANGCHAIN_TRACING_V2") != "true"


def test_tracing_enables_with_key(monkeypatch):
    monkeypatch.delenv("LANGCHAIN_TRACING_V2", raising=False)
    monkeypatch.setenv("LANGSMITH_API_KEY", "ls-test-key")
    monkeypatch.setenv("DREADAI_LANGSMITH_PROJECT", "dreadai-test")

    result = agent.configure_tracing()

    assert result["enabled"] is True
    assert result["project"] == "dreadai-test"
    import os
    assert os.environ["LANGCHAIN_TRACING_V2"] == "true"
    assert os.environ["LANGCHAIN_PROJECT"] == "dreadai-test"


# --- expanded tools ----------------------------------------------------------

def test_discover_attack_surface_tool(monkeypatch):
    # Scope runs in a subprocess; monkeypatch the CLI helper to return a scope result.
    monkeypatch.setattr(agent, "_run_scope_cli", lambda domain: {
        "domain": domain,
        "discovery": {
            "subdomains": {"all_unique": ["a.x.test", "b.x.test"]},
            "subdomain_takeover": [{"subdomain": "b.x.test", "service": "GitHub Pages"}],
            "cloud_assets": {"s3_buckets": ["bkt"]},
        },
    })

    out = agent.discover_attack_surface.invoke({"domain": "x.test"})

    assert out["subdomain_count"] == 2
    assert out["takeover_count"] == 1
    assert out["cloud_asset_count"] == 1


def test_triage_cves_tool(monkeypatch):
    sys.path.insert(0, str(_REPO / "intel"))
    import store

    class Rec:
        def __init__(self, cid, kev, cvss):
            self.cve_id, self.kev, self.cvss_score = cid, kev, cvss
            self.epss_score = 0.5
            self.epss_percentile = 0.9
            self.found = True
            self.severity = "high"
            self.cvss_vector = None
            self.kev_date_added = None
            self.published_date = None
            self.description = ""
            self.references = []

    monkeypatch.setattr(store, "fetch_records",
                        lambda ids, db_path=None: [Rec("CVE-2021-44228", True, 10.0),
                                                   Rec("CVE-2020-0001", False, 5.0)])

    out = agent.triage_cves.invoke({"text": "we saw CVE-2021-44228 and CVE-2020-0001"})

    assert out["cve_count"] == 2
    # KEV entry must rank first (act_now).
    assert out["triage"][0]["cve_id"] == "CVE-2021-44228"
    assert out["triage"][0]["priority"] == "act_now"


def test_assess_internal_network_tool(monkeypatch):
    sys.path.insert(0, str(_REPO / "spear"))
    import spear

    monkeypatch.setattr(spear, "assess", lambda cidr, **kw: {
        "target": cidr, "hosts_up": 1,
        "findings": [{"host": "10.0.0.5", "severity": "high", "title": "Redis exposed"}],
        "rollups": {"total_findings": 1, "findings_by_severity": {"high": 1}},
    })

    out = agent.assess_internal_network.invoke({"cidr": "10.0.0.0/29"})

    assert out["hosts_up"] == 1
    assert out["rollups"]["total_findings"] == 1
    assert any("Redis" in f["title"] for f in out["findings"])


def test_generate_report_classifies_vulns_and_observations(tmp_path, monkeypatch):
    monkeypatch.setenv("DREAD_DATA_DIR", str(tmp_path))
    findings = [
        {"severity": "high", "title": "SQLi", "url": "u", "plugin_name": "web_vulnerabilities"},
        {"severity": "info", "title": "Fingerprint", "url": "u2", "plugin_name": "fingerprinting"},
    ]
    out = agent.generate_report.invoke({"target": "x.test", "findings": findings})

    assert out["vulnerability_count"] == 1
    assert out["observation_count"] == 1
    assert Path(out["report_path"]).is_file()


def test_build_suite_reports_tool(monkeypatch, tmp_path):
    sys.path.insert(0, str(_REPO / "reports"))
    import suite_build

    captured = {}

    def fake_run_build(**kwargs):
        captured.update(kwargs)
        return (["[+] Executive summary: exec.html", "[+] Technical report: tech.html"], [])

    monkeypatch.setattr(suite_build, "run_build", fake_run_build)

    out = agent.build_suite_reports.invoke({
        "output_dir": str(tmp_path),
        "probe_report_paths": ["/tmp/probe_01.json"],
        "scope_report_path": None,
    })

    assert out["errors"] == []
    assert any("Executive" in m for m in out["messages"])


def test_tools_registered_and_agent_builds(monkeypatch):
    names = {t.name for t in agent.TOOLS}
    assert {"scan_target", "fetch_cve", "verify_vulnerability", "rule_out_false_positive",
            "generate_report", "run_pentest", "discover_attack_surface", "triage_cves",
            "assess_internal_network", "build_suite_reports"} <= names

    # build_agent wires TOOLS into a graph without calling the model.
    monkeypatch.setattr(agent, "ChatAnthropic", lambda **kw: object())
    sentinel = object()
    monkeypatch.setattr(agent, "create_react_agent", lambda model, tools, prompt: (tools, prompt, sentinel))
    tools, prompt, s = agent.build_agent()
    assert s is sentinel and len(tools) == len(agent.TOOLS)


# --- external tools (install-on-consent) ------------------------------------

def _fake_tool():
    import catalog
    return catalog.Tool(name="nmap", binary="nmap", category="recon",
                        description="Port scan.", argv=("-F", "{target}"))


def test_run_external_tool_runs_when_installed(monkeypatch):
    import catalog
    import runner

    monkeypatch.setattr(catalog, "load_catalog", lambda: (_fake_tool(),))
    monkeypatch.setattr(runner, "which", lambda b: "/usr/bin/nmap")
    monkeypatch.setattr(runner, "run", lambda name, argv, timeout=120.0:
                        runner.ToolResult(tool=name, argv=argv, returncode=0, stdout="80/tcp open",
                                          stderr="", duration=0.1, timed_out=False))

    out = agent.run_external_tool.invoke({"tool_name": "nmap", "target": "10.0.0.5"})
    assert out["ran"] is True
    assert "80/tcp" in out["stdout"]


def test_run_external_tool_reports_needs_install_when_missing(monkeypatch):
    import catalog
    import packages
    import runner

    monkeypatch.setattr(catalog, "load_catalog", lambda: (_fake_tool(),))
    monkeypatch.setattr(runner, "which", lambda b: None)
    monkeypatch.setattr(packages, "install_guidance", lambda b, pkgs=None: {
        "manager": "pacman", "package": "nmap", "available": True, "command": "sudo pacman -S nmap"})

    out = agent.run_external_tool.invoke({"tool_name": "nmap", "target": "10.0.0.5"})
    assert out["ran"] is False
    assert out["needs_install"] is True
    assert out["install_command"] == "sudo pacman -S nmap"


def test_run_external_tool_unknown_tool(monkeypatch):
    import catalog
    monkeypatch.setattr(catalog, "load_catalog", lambda: (_fake_tool(),))
    out = agent.run_external_tool.invoke({"tool_name": "definitely-not-a-tool", "target": "x"})
    assert "error" in out


def test_install_external_tool_is_consent_gated(monkeypatch):
    import catalog
    import packages

    monkeypatch.setattr(catalog, "load_catalog", lambda: (_fake_tool(),))
    monkeypatch.setattr(packages, "install_guidance", lambda b, pkgs=None: {
        "manager": "pacman", "package": "nmap", "available": True, "command": "sudo pacman -S nmap"})

    ran = {"called": False}
    monkeypatch.setattr(agent, "_run_install", lambda cmd: ran.__setitem__("called", True) or 0)

    # Without consent: returns the command, does NOT run it.
    monkeypatch.delenv("DREADAI_ALLOW_INSTALL", raising=False)
    out = agent.install_external_tool.invoke({"tool_name": "nmap"})
    assert out["installed"] is False
    assert out["install_command"] == "sudo pacman -S nmap"
    assert ran["called"] is False

    # With explicit session consent: runs the install.
    monkeypatch.setenv("DREADAI_ALLOW_INSTALL", "1")
    out = agent.install_external_tool.invoke({"tool_name": "nmap"})
    assert ran["called"] is True
    assert out["installed"] is True
