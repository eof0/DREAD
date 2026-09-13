"""DreadAI agent: a LangGraph agent that drives the DREAD suite."""

from __future__ import annotations

import os
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
_PROBE = _REPO / "probe"
_REPORTS = _REPO / "reports"
_CANNON = _REPO / "cannon"
_SCOPE = _REPO / "scope"
_INTEL = _REPO / "intel"
_SPEAR = _REPO / "spear"
# Only probe/ and cannon/ go on the path at import time. scope/, reports/, intel/ and
# spear/ are added lazily inside the tools that use them: putting those directories
# on sys.path at import time would shadow the same-named namespace packages
# (scope.discovery, reports.api, ...) that other modules import.
for _p in (_REPO, _PROBE, _CANNON):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))


def _on_path(directory: Path) -> None:
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

from langchain_anthropic import ChatAnthropic
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent

MODEL = os.environ.get("DREADAI_MODEL", "claude-sonnet-5")  # back-compat alias

# Per-provider default model. DreadAI runs on Claude out of the box; set DREADAI_PROVIDER
# to run on anything else — a local Qwen via Ollama (zero cost, offline), or any cloud
# model (OpenAI/GPT, Google Gemini, Groq, OpenRouter, DeepSeek, Together, xAI, ...).
_DEFAULT_MODELS = {
    "anthropic": "claude-sonnet-5",
    "ollama": "qwen2.5-coder:7b",
    "local": "qwen2.5-coder:7b",
    "openai": "gpt-4o-mini",
    "openrouter": "openai/gpt-4o-mini",
    "groq": "llama-3.3-70b-versatile",
    "deepseek": "deepseek-chat",
    "together": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
    "xai": "grok-2-latest",
    "google": "gemini-1.5-flash",
}

# Provider aliases people actually type.
_ALIASES = {
    "gpt": "openai", "chatgpt": "openai", "oai": "openai",
    "claude": "anthropic", "anthropic-api": "anthropic",
    "qwen": "ollama",
    "gemini": "google", "google-genai": "google",
    "grok": "xai",
}

# Cloud providers reachable through an OpenAI-compatible endpoint (langchain-openai's
# ChatOpenAI + a base_url). This is the "anything" path — any OpenAI-compatible service
# works by pointing DREADAI_BASE_URL/DREADAI_API_KEY at it, even one not listed here.
_OPENAI_COMPATIBLE_BASES = {
    "openai": None,  # api.openai.com (SDK default)
    "openrouter": "https://openrouter.ai/api/v1",
    "groq": "https://api.groq.com/openai/v1",
    "deepseek": "https://api.deepseek.com/v1",
    "together": "https://api.together.xyz/v1",
    "xai": "https://api.x.ai/v1",
}

# Anthropic's OAuth beta header — sent alongside a login/bearer token (not an api key).
_ANTHROPIC_OAUTH_HEADER = {"anthropic-beta": "oauth-2025-04-20"}


def _load_chat_class(dotted: str):
    """Import a chat-model class by 'module:Class' (a seam so providers stay optional)."""
    import importlib

    module_name, class_name = dotted.split(":", 1)
    return getattr(importlib.import_module(module_name), class_name)


def _local_base_url() -> str:
    return (os.environ.get("DREADAI_BASE_URL") or os.environ.get("OLLAMA_HOST")
            or "http://localhost:11434")


def build_model():
    """
    Construct the chat model for the configured provider.

    DREADAI_PROVIDER selects the backend (default "anthropic" = Claude):
      - "anthropic"/"claude" — Claude, via ANTHROPIC_API_KEY *or* a login/OAuth bearer
        token (ANTHROPIC_AUTH_TOKEN). Either works; no key needed if you're logged in.
      - "ollama"/"qwen" — a local Qwen (or any Ollama model), zero cost and offline.
      - "openai"/"gpt", "google"/"gemini", "groq", "openrouter", "deepseek", "together",
        "xai" — cloud models. Any other value is treated as an OpenAI-compatible endpoint,
        so *any* such service works via DREADAI_BASE_URL + DREADAI_API_KEY.

    DREADAI_MODEL overrides the per-provider default; DREADAI_BASE_URL / OLLAMA_HOST point
    at a local/remote endpoint; DREADAI_API_KEY carries the key for non-Anthropic providers.
    """
    provider = os.environ.get("DREADAI_PROVIDER", "anthropic").strip().lower()
    provider = _ALIASES.get(provider, provider)
    model = os.environ.get("DREADAI_MODEL") or _DEFAULT_MODELS.get(provider)

    if provider == "anthropic":
        return _build_anthropic(model or "claude-sonnet-5")
    if provider == "google":
        return _build_google(model or "gemini-1.5-flash")
    if provider == "ollama":
        return _build_ollama(model or "qwen2.5-coder:7b")
    if provider == "local":
        return _build_openai_compatible(
            "local", model, default_base=_local_base_url().rstrip("/") + "/v1",
            local_style=True)

    # Everything else is an OpenAI-compatible endpoint: openai/gpt, groq, openrouter,
    # deepseek, together, xai, a local vLLM/LM Studio, or any custom/unknown service.
    return _build_openai_compatible(provider, model)


def _build_anthropic(model: str):
    """Claude via API key *or* login. An ANTHROPIC_API_KEY sends x-api-key; otherwise a
    login/OAuth bearer token (ANTHROPIC_AUTH_TOKEN) is sent as Authorization: Bearer."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    token = (os.environ.get("ANTHROPIC_AUTH_TOKEN")
             or os.environ.get("DREADAI_ANTHROPIC_AUTH_TOKEN"))
    if api_key:
        return ChatAnthropic(model=model, api_key=api_key)
    if token:
        return _anthropic_via_login(model, token)
    # No explicit credential: hand back a client and let ChatAnthropic's own env
    # resolution (or a clear auth error at call time) take over.
    return ChatAnthropic(model=model)


def _anthropic_via_login(model: str, token: str):
    """Use a login/OAuth bearer token instead of an x-api-key.

    ChatAnthropic always injects an (empty) x-api-key header, so we swap in anthropic
    clients built with auth_token= — those send `Authorization: Bearer <token>` and the
    OAuth beta header, and no x-api-key. This lets a logged-in user (e.g. Claude login /
    `ANTHROPIC_AUTH_TOKEN`) drive DreadAI without a raw API key.
    """
    import anthropic

    chat = ChatAnthropic(model=model, api_key="oauth-login")  # placeholder, overridden below
    # This relies on ChatAnthropic's private _client/_async_client. If a future
    # langchain-anthropic drops them, fail loudly with guidance rather than silently
    # sending the bogus placeholder key as x-api-key.
    if not (hasattr(chat, "_client") and hasattr(chat, "_async_client")):
        raise RuntimeError(
            "Claude login (ANTHROPIC_AUTH_TOKEN) relies on ChatAnthropic internals that "
            "this langchain-anthropic version no longer exposes. Use an API key "
            "(ANTHROPIC_API_KEY) instead, or pin langchain-anthropic."
        )
    chat._client = anthropic.Anthropic(
        auth_token=token, default_headers=_ANTHROPIC_OAUTH_HEADER)
    chat._async_client = anthropic.AsyncAnthropic(
        auth_token=token, default_headers=_ANTHROPIC_OAUTH_HEADER)
    return chat


def _build_google(model: str):
    try:
        ChatGoogle = _load_chat_class("langchain_google_genai:ChatGoogleGenerativeAI")
    except ImportError as exc:
        raise RuntimeError(
            "DreadAI's Google/Gemini provider needs 'langchain-google-genai' "
            "(pip install langchain-google-genai) and a GOOGLE_API_KEY."
        ) from exc
    api_key = os.environ.get("DREADAI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    kwargs = {"model": model, "temperature": 0}
    if api_key:
        kwargs["google_api_key"] = api_key
    return ChatGoogle(**kwargs)


def _build_ollama(model: str):
    """Prefer the native Ollama client (best tool-calling for Qwen); fall back to any
    OpenAI-compatible client against Ollama's /v1 endpoint."""
    base_url = _local_base_url().rstrip("/")
    try:
        ChatOllama = _load_chat_class("langchain_ollama:ChatOllama")
        return ChatOllama(model=model, base_url=base_url, temperature=0)
    except ImportError:
        pass
    return _build_openai_compatible(
        "ollama", model, default_base=base_url + "/v1", local_style=True)


def _build_openai_compatible(provider: str, model, default_base: str = None,
                             local_style: bool = False):
    model = model or _DEFAULT_MODELS.get(provider) or "gpt-4o-mini"
    base_url = (os.environ.get("DREADAI_BASE_URL")
                or default_base
                or _OPENAI_COMPATIBLE_BASES.get(provider))
    if local_style and base_url and not base_url.rstrip("/").endswith("/v1"):
        base_url = base_url.rstrip("/") + "/v1"
    try:
        ChatOpenAI = _load_chat_class("langchain_openai:ChatOpenAI")
    except ImportError as exc:
        raise RuntimeError(
            "DreadAI's OpenAI-compatible provider needs 'langchain-openai' "
            "(pip install langchain-openai). For a local model, also install "
            "'langchain-ollama' and run Ollama (ollama pull qwen2.5-coder:7b)."
        ) from exc
    # Local endpoints ignore the key; cloud ones read DREADAI_API_KEY / OPENAI_API_KEY.
    api_key = (os.environ.get("DREADAI_API_KEY")
               or os.environ.get("OPENAI_API_KEY")
               or "not-needed")
    kwargs = {"model": model, "temperature": 0, "api_key": api_key}
    if base_url:
        kwargs["base_url"] = base_url
    return ChatOpenAI(**kwargs)


def configure_tracing() -> dict:
    """
    Enable LangSmith tracing when a key is present, otherwise no-op.

    Safe to call unconditionally: without LANGSMITH_API_KEY / LANGCHAIN_API_KEY it
    leaves tracing off so DreadAI runs the same with or without observability.
    """
    api_key = os.environ.get("LANGSMITH_API_KEY") or os.environ.get("LANGCHAIN_API_KEY")
    if not api_key:
        return {"enabled": False}
    project = os.environ.get("DREADAI_LANGSMITH_PROJECT", "dreadai")
    os.environ["LANGCHAIN_TRACING_V2"] = "true"
    os.environ["LANGSMITH_TRACING"] = "true"
    os.environ["LANGCHAIN_PROJECT"] = project
    os.environ.setdefault("LANGCHAIN_API_KEY", api_key)
    return {"enabled": True, "project": project}

SYSTEM = (
    "You are DreadAI, the security orchestration agent for DREAD, a professional-grade "
    "security assessment suite. Your capabilities span the whole suite: external attack-surface "
    "discovery (Scope), web vulnerability scanning (Probe), internal-network assessment (Spear), "
    "CVE intelligence and KEV/EPSS triage (Intel), and unified two-audience reporting (Reports). "
    "Chain the tools as a security professional would: discover the surface, scan it, confirm "
    "what is real and rule out false positives, triage by real-world exploitability, and report "
    "for both executives and engineers. Operate ONLY against targets the operator states they are "
    "authorized to test; internal-network assessment targets private ranges. You have no ability "
    "to poison name resolution or capture credentials — those live behind a separate human "
    "authorization gate, by design.\n\n"
    "For depth beyond the built-in checks you have expert methodology on tap: call "
    "list_security_skills to browse the installed Trail of Bits and secskills libraries "
    "(attacking JWTs/OAuth/GraphQL, exploiting SSRF/deserialization, reviewing cryptography, "
    "differential review, static analysis, and more), load_security_skill to pull one in, then "
    "FOLLOW its methodology using your own tools. Drive real external tools with "
    "run_external_tool — including 42crunch for a static API Security Audit of an OpenAPI "
    "definition (OWASP API Top 10, 0-100 score). Reach for a skill or external tool when a task "
    "needs a technique the built-in scanners don't cover."
)


@tool
def scan_target(target: str, profile: str = "quick") -> dict:
    """Run a Probe scan against an authorized target and return a summary.

    profile is one of the Probe scan profiles. "quick" is the lightest.
    """
    from scanner.config import SCAN_PROFILES, ScanConfig
    from scanner.engine import ScanEngine

    if profile not in SCAN_PROFILES:
        return {"error": f"unknown profile {profile!r}", "profiles": sorted(SCAN_PROFILES)}
    try:
        report = ScanEngine(ScanConfig(target_url=target, profile=profile)).run_scan()
    except Exception as exc:
        return {"error": str(exc), "target": target}
    stats = report.get("statistics", {})
    return {
        "scan_id": report.get("scan_id"),
        "target": report.get("target", target),
        "total_findings": stats.get("total_findings"),
        "findings_by_severity": stats.get("findings_by_severity", {}),
    }


@tool
def fetch_cve(cve_id: str) -> dict:
    """Look up one CVE by id in the local DREAD CVE store."""
    from scanner.cve_db_manager import get_cve_by_id

    try:
        entry = get_cve_by_id(cve_id)
    except FileNotFoundError as exc:
        return {"cve_id": cve_id, "error": str(exc)}
    if entry is None:
        return {"cve_id": cve_id, "found": False}
    return {"found": True, **entry}


def _probe(url: str) -> dict:
    import requests

    resp = requests.get(url, timeout=15)
    return {"status": resp.status_code, "body": resp.text}


@tool
def verify_vulnerability(url: str, evidence: str) -> dict:
    """Confirm a finding by re-fetching its URL and checking the evidence still appears."""
    try:
        probe = _probe(url)
    except Exception as exc:
        return {"url": url, "error": str(exc)}
    present = evidence in probe["body"]
    return {"url": url, "status": probe["status"], "evidence_present": present, "confirmed": present}


@tool
def rule_out_false_positive(url: str, evidence: str) -> dict:
    """Judge a candidate finding as a false positive when its evidence no longer holds."""
    try:
        probe = _probe(url)
    except Exception as exc:
        return {"url": url, "error": str(exc)}
    present = evidence in probe["body"]
    return {"url": url, "status": probe["status"], "false_positive": not present}


@tool
def generate_report(target: str, findings: list[dict]) -> dict:
    """Write a unified suite JSON report for the given findings and return its path.

    Findings are classified vulnerability-vs-observation with DREAD's standard rule,
    so counts match the rest of the suite.
    """
    from datetime import datetime, timezone

    _on_path(_REPORTS)
    from aggregate import _classify
    from writers.json_writer import write_suite_json

    by_severity: dict[str, int] = {}
    vuln_count = 0
    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        by_severity[sev] = by_severity.get(sev, 0) + 1
        f.setdefault("classification", _classify(f))
        if f["classification"] == "vulnerability":
            vuln_count += 1
    run_id = f"dreadai_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    report = {
        "report_type": "unified_suite",
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sources": ["dreadai"],
        "target": target,
        "findings": findings,
        "rollups": {
            "total_findings": len(findings),
            "findings_by_severity": by_severity,
            "vulnerability_count": vuln_count,
            "observation_count": len(findings) - vuln_count,
        },
    }
    path = write_suite_json(report, _REPO / "reports", run_id)
    return {
        "report_path": str(path),
        "total_findings": len(findings),
        "vulnerability_count": vuln_count,
        "observation_count": len(findings) - vuln_count,
    }


def _run_scope_cli(domain: str) -> dict:
    """Run the Scope discovery CLI in a subprocess and return its parsed JSON.

    Scope is invoked out-of-process (as `dread` does) to avoid a sys.path collision:
    scope/ is both a namespace package (scope.discovery) and a CLI module (scope.py).
    """
    import json
    import subprocess

    cmd = [sys.executable, str(_SCOPE / "scope.py"), "discover", domain,
           "--output", "json", "--quiet"]
    proc = subprocess.run(cmd, cwd=str(_REPO), capture_output=True, text=True, timeout=900)
    if proc.returncode != 0:
        return {"error": (proc.stderr or proc.stdout or "scope failed").strip()[:500]}
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        start, end = proc.stdout.find("{"), proc.stdout.rfind("}")
        if start != -1 and end > start:
            return json.loads(proc.stdout[start:end + 1])
        return {"error": "could not parse Scope output"}


@tool
def discover_attack_surface(domain: str) -> dict:
    """Run Scope external discovery on an authorized domain: subdomains, takeovers, cloud assets."""
    result = _run_scope_cli(domain)
    if "error" in result:
        return {"domain": domain, "error": result["error"]}
    disc = result.get("discovery", {}) or {}
    subs = (disc.get("subdomains") or {}).get("all_unique", []) or []
    takeovers = disc.get("subdomain_takeover") or []
    cloud = disc.get("cloud_assets") or {}
    cloud_count = sum(len(v) for v in cloud.values() if isinstance(v, list))
    return {
        "domain": domain,
        "subdomain_count": len(subs),
        "subdomains": subs[:50],
        "takeover_count": len(takeovers),
        "takeovers": takeovers,
        "cloud_asset_count": cloud_count,
    }


@tool
def triage_cves(text: str) -> dict:
    """Extract every CVE id from text and rank them by real-world priority (KEV/EPSS/CVSS)."""
    _on_path(_INTEL)
    import prioritize
    import store
    from intel import _priority_for, _record_json, extract_cve_ids  # intel/intel.py

    cve_ids = extract_cve_ids(text)
    if not cve_ids:
        return {"cve_count": 0, "triage": []}
    try:
        records = store.fetch_records(cve_ids)
    except store.CVEStoreMissing as exc:
        return {"cve_count": len(cve_ids), "error": str(exc)}
    graded = [(r, _priority_for(r)) for r in records]
    ordered = prioritize.rank((r.cve_id, p) for r, p in graded)
    by_id = {r.cve_id: (r, p) for r, p in graded}
    return {
        "cve_count": len(cve_ids),
        "triage": [_record_json(*by_id[cid]) for cid, _ in ordered],
    }


@tool
def assess_internal_network(cidr: str) -> dict:
    """Assess an authorized internal range (private): discover hosts, enumerate services, risk-rank.

    Read-only reconnaissance. This tool CANNOT poison name resolution or capture
    credentials; those active capabilities require a separate human authorization gate.
    """
    _on_path(_SPEAR)
    import spear
    from recon import tcp_connect_banner, tcp_ping

    try:
        return spear.assess(cidr, prober=tcp_ping, connector=tcp_connect_banner)
    except ValueError as exc:  # e.g. a public range without explicit allowance
        return {"target": cidr, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return {"target": cidr, "error": str(exc)}


@tool
def build_suite_reports(
    output_dir: str,
    probe_report_paths: list[str],
    scope_report_path: str | None = None,
) -> dict:
    """Build the two-audience deliverables (executive_summary + technical_report) from artifacts."""
    from pathlib import Path as _Path

    _on_path(_REPORTS)
    from suite_build import run_build
    from suite_schema import REPORTS_SCHEMA_VERSION

    include = ["probe"]
    if scope_report_path:
        include.append("scope")
    messages, errors = run_build(
        output_dir=_Path(output_dir),
        base_name="dread_suite_report",
        title="",
        probe_paths=[_Path(p) for p in probe_report_paths],
        scope_path=_Path(scope_report_path) if scope_report_path else None,
        include=frozenset(include),
        formats=frozenset({"json", "html", "pdf"}),
        dashboard_src=_REPORTS / "dashboard",
        try_npm_build=False,
    )
    return {"output_dir": output_dir, "messages": messages, "errors": errors}


@tool
def run_pentest(target: str, tools: list[str] | None = None, heavy: bool = False) -> dict:
    """Wield Cannon against an authorized target: DREAD's active pentest engine.

    DreadAI drives Cannon directly, past the fixed menu a human operator is limited to.
    Pass `tools` to run specific cataloged tools by name, or leave empty to run every
    installed tool. Set heavy to escalate the load tools. Call again to adapt on results.
    """
    import catalog as bc_catalog
    import runner as bc_runner

    if target.startswith("-"):
        return {"error": f"refusing target {target!r}: cannot begin with '-'"}
    cat = bc_catalog.load_catalog()
    chosen = (
        [t for t in (bc_catalog.by_name(name, cat) for name in tools) if t is not None]
        if tools
        else list(cat)
    )
    results = []
    for tool_entry in chosen:
        if bc_runner.which(tool_entry.binary) is None:
            results.append({"tool": tool_entry.name, "skipped": "not installed"})
            continue
        argv = bc_catalog.build_argv(tool_entry, target, heavy=heavy and tool_entry.category == "load")
        outcome = bc_runner.run(tool_entry.name, argv)
        results.append({
            "tool": tool_entry.name,
            "returncode": outcome.returncode,
            "timed_out": outcome.timed_out,
            "duration": outcome.duration,
            "stdout": outcome.stdout[-2000:],
        })
    return {"target": target, "heavy": heavy, "results": results}


def _run_install(command: str) -> int:
    """Run a package-manager install command, streaming to the operator's terminal (for sudo).

    The command comes from Cannon's package-manager detection over the trusted tool
    catalog; we split it into argv rather than using a shell to avoid injection.
    """
    import shlex
    import subprocess

    return subprocess.run(shlex.split(command)).returncode


@tool
def list_external_tools() -> dict:
    """List the external security tools DreadAI can drive, and whether each is installed."""
    import catalog
    import runner

    tools = []
    for t in catalog.load_catalog():
        tools.append({
            "name": t.name, "binary": t.binary, "category": t.category,
            "description": t.description, "installed": runner.which(t.binary) is not None,
        })
    return {"tools": tools}


@tool
def run_external_tool(tool_name: str, target: str, heavy: bool = False) -> dict:
    """Run a cataloged external tool (nmap, nikto, ...) against an authorized target.

    We can't build everything, so DreadAI drives real tools. If the tool isn't
    installed this returns needs_install with the exact install command — ask the
    operator for permission, then call install_external_tool.
    """
    import catalog
    import packages
    import runner

    if target.startswith("-"):
        return {"error": f"refusing target {target!r}: cannot begin with '-'"}
    tool_entry = catalog.by_name(tool_name)
    if tool_entry is None:
        available = [t.name for t in catalog.load_catalog()]
        return {"error": f"unknown tool {tool_name!r}", "available_tools": available}

    if runner.which(tool_entry.binary) is None:
        guidance = packages.install_guidance(tool_entry.binary, tool_entry.packages)
        return {
            "ran": False,
            "needs_install": True,
            "tool": tool_name,
            "install_command": guidance.get("command"),
            "package_manager": guidance.get("manager"),
            "message": (
                f"{tool_name} is not installed. Ask the operator for permission to install "
                f"it ({guidance.get('command') or 'no package-manager command available'}), "
                "then call install_external_tool."
            ),
        }

    argv = catalog.build_argv(tool_entry, target, heavy=heavy and tool_entry.category == "load")
    outcome = runner.run(tool_entry.name, argv)
    return {
        "ran": True,
        "tool": tool_name,
        "returncode": outcome.returncode,
        "timed_out": outcome.timed_out,
        "duration": outcome.duration,
        "stdout": outcome.stdout[-4000:],
    }


@tool
def install_external_tool(tool_name: str) -> dict:
    """Install a missing cataloged tool — ONLY with operator consent.

    Consent is session-scoped: it installs only when DREADAI_ALLOW_INSTALL=1 (set by
    the operator, e.g. via the chat harness after they approve). Otherwise it returns
    the exact command for the operator to run themselves.
    """
    import catalog
    import packages

    tool_entry = catalog.by_name(tool_name)
    if tool_entry is None:
        return {"installed": False, "error": f"unknown tool {tool_name!r}"}
    guidance = packages.install_guidance(tool_entry.binary, tool_entry.packages)
    command = guidance.get("command")
    if not command:
        return {"installed": False, "tool": tool_name,
                "error": "no package-manager install command available; install manually",
                "package_manager": guidance.get("manager")}

    if os.environ.get("DREADAI_ALLOW_INSTALL") != "1":
        return {
            "installed": False,
            "tool": tool_name,
            "install_command": command,
            "message": "Operator consent required. Approve installs for this session "
                       "(the chat harness will ask), then retry.",
        }

    rc = _run_install(command)
    return {"installed": rc == 0, "tool": tool_name, "install_command": command, "returncode": rc}


@tool
def list_security_skills(query: str = "") -> dict:
    """List security methodology skills (Trail of Bits + secskills) DreadAI can follow.

    Optional `query` filters by substring over the skill id or description. Returns skill
    ids ("plugin:name") with one-line descriptions; load one with load_security_skill to
    get its full methodology, then carry it out with DreadAI's own tools. Works on any
    backing model (Claude, a local Qwen, or a cloud model) — it is plain catalog data.
    """
    _on_path(Path(__file__).resolve().parent)
    import skills as _skills

    catalog = _skills.discover_skills()
    q = query.strip().lower()
    items = [
        {"id": k, "description": v["description"]}
        for k, v in sorted(catalog.items())
        if not q or q in k.lower() or q in v["description"].lower()
    ]
    return {"count": len(items), "skills": items}


@tool
def load_security_skill(name: str) -> dict:
    """Load a security skill's full methodology by id ("plugin:name") or bare name.

    Returns the skill's instructions to FOLLOW (with DreadAI's own tools) plus its
    supporting files. Call list_security_skills first to find the right one. On a miss it
    returns an error with suggestions rather than failing.
    """
    _on_path(Path(__file__).resolve().parent)
    import skills as _skills

    return _skills.load_skill(name)


TOOLS = [
    # Discovery -> scan -> confirm -> triage -> report, the professional workflow.
    discover_attack_surface,
    scan_target,
    assess_internal_network,
    verify_vulnerability,
    rule_out_false_positive,
    fetch_cve,
    triage_cves,
    generate_report,
    build_suite_reports,
    run_pentest,
    # We can't build everything: drive real external tools, installing on operator consent.
    list_external_tools,
    run_external_tool,
    install_external_tool,
    # Deep methodology: the Trail of Bits + secskills skill libraries, followed with our tools.
    list_security_skills,
    load_security_skill,
]


def build_agent():
    configure_tracing()
    return create_react_agent(build_model(), TOOLS, prompt=SYSTEM)


def ask(prompt: str) -> str:
    result = build_agent().invoke({"messages": [("user", prompt)]})
    return result["messages"][-1].content
