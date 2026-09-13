"""DreadAI chat harness: session, slash-commands, tool-call surfacing (no LLM)."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace

_REPO = Path(__file__).resolve().parents[1]
_DREADAI = _REPO / "dreadai"
for p in (str(_REPO), str(_DREADAI)):
    if p not in sys.path:
        sys.path.insert(0, p)

import chat


class FakeAgent:
    """Mimics a LangGraph agent: returns a message list, optionally with tool calls."""

    def __init__(self, script):
        self._script = script  # list of turns; each is (final_text, [tool_names])

    def invoke(self, state):
        final_text, tool_names = self._script.pop(0)
        messages = list(state["messages"])
        for name in tool_names:
            messages.append(SimpleNamespace(content="", tool_calls=[{"name": name, "args": {}}]))
            messages.append(SimpleNamespace(content=f"{name} result", tool_calls=None))
        messages.append(SimpleNamespace(content=final_text, tool_calls=None))
        return {"messages": messages}


def test_session_returns_final_and_surfaces_tool_calls():
    session = chat.ChatSession(agent_factory=lambda: FakeAgent([("Found 2 subdomains.",
                                                                 ["discover_attack_surface"])]))
    result = session.ask("map x.test")

    assert result["content"] == "Found 2 subdomains."
    assert result["tool_calls"] == ["discover_attack_surface"]


def test_session_keeps_history_across_turns():
    session = chat.ChatSession(agent_factory=lambda: FakeAgent([
        ("first answer", []),
        ("second answer", ["scan_target"]),
    ]))
    session.ask("hi")
    before = len(session.history)
    session.ask("now scan")
    assert len(session.history) > before
    assert session.turns == 2


def test_parse_command_recognizes_slash_commands():
    assert chat.parse_command("/help") == ("help", "")
    assert chat.parse_command("/tools") == ("tools", "")
    assert chat.parse_command("/allow-install on") == ("allow-install", "on")
    assert chat.parse_command("just a question") is None


def test_handle_allow_install_sets_session_consent(monkeypatch):
    monkeypatch.delenv("DREADAI_ALLOW_INSTALL", raising=False)
    session = chat.ChatSession(agent_factory=lambda: FakeAgent([]))

    out = chat.handle_command(session, "allow-install", "on")
    assert os.environ.get("DREADAI_ALLOW_INSTALL") == "1"
    assert "install" in out.lower()

    chat.handle_command(session, "allow-install", "off")
    assert os.environ.get("DREADAI_ALLOW_INSTALL") != "1"


def test_handle_clear_resets_history():
    session = chat.ChatSession(agent_factory=lambda: FakeAgent([("x", [])]))
    session.ask("hi")
    chat.handle_command(session, "clear", "")
    assert session.history == []
    assert session.turns == 0


def test_handle_help_and_tools_return_text():
    session = chat.ChatSession(agent_factory=lambda: FakeAgent([]))
    assert "exit" in chat.handle_command(session, "help", "").lower()
    tools_text = chat.handle_command(session, "tools", "")
    assert "scan_target" in tools_text or "discover_attack_surface" in tools_text


def test_exit_command_signals_quit():
    session = chat.ChatSession(agent_factory=lambda: FakeAgent([]))
    assert chat.handle_command(session, "exit", "") is chat.QUIT


def test_models_with_no_arg_lists_providers(monkeypatch):
    monkeypatch.delenv("DREADAI_PROVIDER", raising=False)
    session = chat.ChatSession(agent_factory=lambda: FakeAgent([]))
    out = chat.handle_command(session, "models", "")
    assert "ollama" in out
    assert "anthropic" in out


def test_models_qwen_alias_switches_to_ollama_with_no_credential_note(monkeypatch):
    monkeypatch.delenv("DREADAI_PROVIDER", raising=False)
    monkeypatch.delenv("DREADAI_MODEL", raising=False)
    session = chat.ChatSession(agent_factory=lambda: FakeAgent([]))

    out = chat.handle_command(session, "models", "qwen")

    assert os.environ["DREADAI_PROVIDER"] == "ollama"
    assert "no api key" in out.lower() or "fully local" in out.lower()


def test_models_switch_drops_cached_agent_so_it_rebuilds(monkeypatch):
    monkeypatch.delenv("DREADAI_PROVIDER", raising=False)
    session = chat.ChatSession(agent_factory=lambda: FakeAgent([("hi", [])]))
    session.ask("hello")            # caches an agent instance
    assert session._agent is not None

    chat.handle_command(session, "models", "qwen")

    assert session._agent is None   # next .ask() rebuilds via agent_factory


def test_models_unknown_name_lists_valid_choices():
    session = chat.ChatSession(agent_factory=lambda: FakeAgent([]))
    out = chat.handle_command(session, "models", "not-a-real-provider")
    assert "unknown" in out.lower()
    assert "ollama" in out


def test_startup_warning_none_when_provider_is_ollama(monkeypatch):
    monkeypatch.setenv("DREADAI_PROVIDER", "ollama")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    assert chat._startup_warning() is None


def test_startup_warning_fires_for_anthropic_without_credential(monkeypatch):
    monkeypatch.delenv("DREADAI_PROVIDER", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("DREADAI_ANTHROPIC_AUTH_TOKEN", raising=False)
    warning = chat._startup_warning()
    assert warning is not None
    assert "/models qwen" in warning


def test_startup_warning_none_when_anthropic_credential_present(monkeypatch):
    monkeypatch.delenv("DREADAI_PROVIDER", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    assert chat._startup_warning() is None
