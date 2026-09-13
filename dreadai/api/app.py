#!/usr/bin/env python3
"""
DreadAI HTTP API.

Python/Flask equivalent of Next.js route files. Install Flask before running:
    pip install flask

Every route calls the same in-process agent tools the CLI uses, so the HTTP
surface and the `dreadai chat` agent stay in step.

Endpoints:
    POST /api/dreadai/scan
    GET  /api/dreadai/cve
    POST /api/dreadai/verify
    POST /api/dreadai/rule-out
    POST /api/dreadai/report
    POST /api/dreadai/discover
    POST /api/dreadai/triage
    POST /api/dreadai/assess
    POST /api/dreadai/reports
    GET  /api/dreadai/external-tools
    POST /api/dreadai/run-tool
    POST /api/dreadai/chat
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from flask import Flask, jsonify, request

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import agent

app = Flask(__name__)


def _json_body() -> dict:
    """Parse the request JSON body, treating any non-dict payload as empty."""
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else {}


@app.route("/api/dreadai/scan", methods=["POST"])
def scan_target():
    body = _json_body()
    return jsonify(agent.scan_target.invoke(
        {"target": body.get("target", ""), "profile": body.get("profile", "quick")}
    ))


@app.route("/api/dreadai/cve", methods=["GET"])
def fetch_cve():
    return jsonify(agent.fetch_cve.invoke({"cve_id": request.args.get("cve_id", "")}))


@app.route("/api/dreadai/verify", methods=["POST"])
def verify_vulnerability():
    body = _json_body()
    return jsonify(agent.verify_vulnerability.invoke(
        {"url": body.get("url", ""), "evidence": body.get("evidence", "")}
    ))


@app.route("/api/dreadai/rule-out", methods=["POST"])
def rule_out_false_positive():
    body = _json_body()
    return jsonify(agent.rule_out_false_positive.invoke(
        {"url": body.get("url", ""), "evidence": body.get("evidence", "")}
    ))


@app.route("/api/dreadai/report", methods=["POST"])
def generate_report():
    body = _json_body()
    return jsonify(agent.generate_report.invoke(
        {"target": body.get("target", ""), "findings": body.get("findings", [])}
    ))


@app.route("/api/dreadai/discover", methods=["POST"])
def discover_attack_surface():
    return jsonify(agent.discover_attack_surface.invoke({"domain": _json_body().get("domain", "")}))


@app.route("/api/dreadai/triage", methods=["POST"])
def triage_cves():
    return jsonify(agent.triage_cves.invoke({"text": _json_body().get("text", "")}))


@app.route("/api/dreadai/assess", methods=["POST"])
def assess_internal_network():
    return jsonify(agent.assess_internal_network.invoke({"cidr": _json_body().get("cidr", "")}))


@app.route("/api/dreadai/reports", methods=["POST"])
def build_suite_reports():
    body = _json_body()
    return jsonify(agent.build_suite_reports.invoke({
        "output_dir": body.get("output_dir", ""),
        "probe_report_paths": body.get("probe_report_paths", []),
        "scope_report_path": body.get("scope_report_path"),
    }))


@app.route("/api/dreadai/external-tools", methods=["GET"])
def list_external_tools():
    return jsonify(agent.list_external_tools.invoke({}))


@app.route("/api/dreadai/run-tool", methods=["POST"])
def run_external_tool():
    body = _json_body()
    return jsonify(agent.run_external_tool.invoke({
        "tool_name": body.get("tool_name", ""), "target": body.get("target", ""),
        "heavy": bool(body.get("heavy", False)),
    }))


@app.route("/api/dreadai/chat", methods=["POST"])
def chat():
    data = _json_body()
    prompt = data.get("prompt", "")
    if not prompt:
        return jsonify({"error": "Missing 'prompt' in request body."}), 400
    if agent.needs_anthropic_credential():
        return jsonify({"error": "No Claude credential found (ANTHROPIC_API_KEY or a login/"
                                  "ANTHROPIC_AUTH_TOKEN). Set DREADAI_PROVIDER=qwen for a "
                                  "fully local model instead."}), 503
    return jsonify({"result": agent.ask(prompt)})


if __name__ == "__main__":
    # debug=True enables the Werkzeug interactive debugger, which allows
    # arbitrary code execution from anyone who can trigger an unhandled
    # exception and reach it over the network. Opt in explicitly for local
    # dev only, and never allow it while bound to every interface -- use
    # FLASK_HOST=127.0.0.1 for a debug session.
    host = os.environ.get("FLASK_HOST", "0.0.0.0")
    debug_requested = os.environ.get("FLASK_DEBUG", "").strip().lower() in {"1", "true", "yes"}
    debug = debug_requested and host not in {"0.0.0.0", "::"}
    if debug_requested and not debug:
        print(f"[!] FLASK_DEBUG requested but host is {host!r}; refusing to enable the debugger on a non-loopback bind.")
    app.run(host=host, port=int(os.environ.get("PORT", "5000")), debug=debug)
