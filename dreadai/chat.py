"""
DreadAI chat harness — an interactive terminal window for the agent.

A small purpose-built REPL (in the spirit of Claude Code / opencode / pi): you talk
to DreadAI, it reasons, calls suite tools and external tools, and answers. It shows
which tools it runs as it works, keeps conversation history across turns, and
handles the install-consent flow for external tools.

The session and command handling are pure/testable; `run_repl` is the I/O loop.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Callable, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

# Sentinel returned by handle_command to signal the REPL should exit.
QUIT = object()

_BANNER = r"""
  ██████╗ ██████╗ ███████╗ █████╗ ██████╗  █████╗ ██╗
  ██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗██║
  ██║  ██║██████╔╝█████╗  ███████║██║  ██║███████║██║
  ██║  ██║██╔══██╗██╔══╝  ██╔══██║██║  ██║██╔══██║██║
  ██████╔╝██║  ██║███████╗██║  ██║██████╔╝██║  ██║██║
  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝
  DreadAI — security orchestration agent.  /help for commands.
"""

_HELP = """Commands:
  /help              show this help
  /models            list available models/providers
  /models <name>     switch model (e.g. "qwen" for local/offline, "claude", "gpt", "gemini")
  /tools             list the tools DreadAI can use
  /allow-install on  allow DreadAI to install missing external tools this session
  /allow-install off revoke install permission
  /clear             clear the conversation history
  /exit  /quit       leave the chat

Type anything else to talk to DreadAI. It will discover, scan, confirm, triage,
and report — asking before it installs anything. Authorized targets only."""

# key -> (label, needs a credential?). Keys match agent._DEFAULT_MODELS providers,
# plus the aliases people actually type (agent._ALIASES resolves those to a key here).
_MODEL_LABELS = {
    "ollama": "local, via Ollama — no API key, no login",
    "anthropic": "Claude — API key or a login/ANTHROPIC_AUTH_TOKEN",
    "openai": "OpenAI/GPT — API key",
    "google": "Google Gemini — API key",
    "groq": "Groq — API key",
    "openrouter": "OpenRouter — API key",
    "deepseek": "DeepSeek — API key",
    "together": "Together AI — API key",
    "xai": "xAI/Grok — API key",
}


def parse_command(line: str) -> Optional[tuple[str, str]]:
    """Parse a '/command [arg]' line into (command, arg), or None for normal input."""
    stripped = line.strip()
    if not stripped.startswith("/"):
        return None
    body = stripped[1:].strip()
    if not body:
        return ("", "")
    parts = body.split(None, 1)
    return (parts[0].lower(), parts[1] if len(parts) > 1 else "")


class ChatSession:
    """Holds conversation state and drives the agent turn by turn."""

    def __init__(self, agent_factory: Optional[Callable[[], Any]] = None):
        self._agent_factory = agent_factory
        self._agent = None
        self.history: list = []
        self.turns = 0

    def _agent_instance(self):
        if self._agent is None:
            if self._agent_factory is None:
                from agent import build_agent
                self._agent_factory = build_agent
            self._agent = self._agent_factory()
        return self._agent

    def ask(self, prompt: str) -> dict:
        """Run one turn; return {'content', 'tool_calls'} and extend history."""
        state = {"messages": self.history + [("user", prompt)]}
        result = self._agent_instance().invoke(state)
        messages = result["messages"]
        tool_calls = [
            tc.get("name") if isinstance(tc, dict) else getattr(tc, "name", str(tc))
            for m in messages
            for tc in (getattr(m, "tool_calls", None) or [])
        ]
        self.history = messages
        self.turns += 1
        final = messages[-1]
        content = getattr(final, "content", final)
        return {"content": content, "tool_calls": tool_calls}

    def clear(self) -> None:
        self.history = []
        self.turns = 0

    def switch_model(self) -> None:
        """Drop the cached agent so the next turn rebuilds it against the new
        DREADAI_PROVIDER/DREADAI_MODEL — conversation history is kept."""
        self._agent = None


def _models_list_text() -> str:
    from agent import _DEFAULT_MODELS, active_provider

    current = active_provider()
    lines = ["Models (/models <name> to switch — history carries over):"]
    for key, default_model in _DEFAULT_MODELS.items():
        marker = "*" if key == current else " "
        label = _MODEL_LABELS.get(key, "")
        lines.append(f"  {marker} {key:<11} {default_model:<28} {label}")
    lines.append("\nAliases: qwen->ollama, claude->anthropic, gpt->openai, gemini->google, grok->xai")
    return "\n".join(lines)


def _switch_model_text(session: "ChatSession", arg: str) -> str:
    from agent import _ALIASES, _DEFAULT_MODELS

    choice = arg.strip().lower()
    if not choice:
        return _models_list_text()
    provider = _ALIASES.get(choice, choice)
    if provider not in _DEFAULT_MODELS:
        return (f"Unknown model '{arg}'. Try one of: {', '.join(sorted(_DEFAULT_MODELS))} "
                "(or an alias like qwen/claude/gpt/gemini/grok).")
    os.environ["DREADAI_PROVIDER"] = provider
    os.environ.pop("DREADAI_MODEL", None)  # fall back to that provider's default model
    session.switch_model()
    if provider in ("ollama", "local"):
        return (f"Switched to {provider} ({_DEFAULT_MODELS[provider]}) — fully local, "
                "no API key or login needed for either provider.")
    return f"Switched to {provider} ({_DEFAULT_MODELS[provider]})."


def _tool_list_text() -> str:
    try:
        from agent import TOOLS
        return "Tools:\n" + "\n".join(f"  - {t.name}: {t.description.splitlines()[0]}"
                                      for t in TOOLS)
    except Exception:  # noqa: BLE001
        return "Tools: (agent unavailable)"


def handle_command(session: ChatSession, command: str, arg: str):
    """Handle a slash command. Returns text to print, or the QUIT sentinel."""
    if command in ("exit", "quit"):
        return QUIT
    if command == "help" or command == "":
        return _HELP
    if command == "tools":
        return _tool_list_text()
    if command == "models":
        return _switch_model_text(session, arg)
    if command == "clear":
        session.clear()
        return "Conversation cleared."
    if command == "allow-install":
        if arg.strip().lower() in ("on", "yes", "true", "1"):
            os.environ["DREADAI_ALLOW_INSTALL"] = "1"
            return "Install permission GRANTED for this session. DreadAI may install missing tools."
        os.environ.pop("DREADAI_ALLOW_INSTALL", None)
        return "Install permission revoked."
    return f"Unknown command: /{command}  (try /help)"


def _startup_warning() -> Optional[str]:
    """Warn (don't block) when the *default* provider is Claude and no credential is
    set — /models is still reachable to switch to a local/offline model like Qwen."""
    from agent import needs_anthropic_credential

    if not needs_anthropic_credential():
        return None
    return ("No Claude credential found (ANTHROPIC_API_KEY, or a login/ANTHROPIC_AUTH_TOKEN).\n"
            "    Run /models qwen to use the local model instead, or set a credential.")


def run_repl() -> int:
    """Interactive chat loop. Defaults to Claude; run /models to switch — a local Qwen
    (via Ollama) needs no API key and no login at all."""
    from agent import configure_tracing
    traced = configure_tracing()

    print(_BANNER)
    warning = _startup_warning()
    if warning:
        print(f"\x1b[33m[!] {warning}\x1b[0m\n")
    if traced.get("enabled"):
        print(f"  LangSmith tracing on (project: {traced['project']}).\n")

    session = ChatSession()
    while True:
        try:
            line = input("\x1b[1;36mdreadai>\x1b[0m ")
        except (EOFError, KeyboardInterrupt):
            print("\nbye.")
            return 0

        command = parse_command(line)
        if command is not None:
            result = handle_command(session, command[0], command[1])
            if result is QUIT:
                print("bye.")
                return 0
            print(result)
            continue

        if not line.strip():
            continue

        try:
            print("\x1b[2m  …thinking\x1b[0m", flush=True)
            answer = session.ask(line)
        except Exception as exc:  # noqa: BLE001
            print(f"\x1b[31m[!] {exc}\x1b[0m", file=sys.stderr)
            continue

        if answer["tool_calls"]:
            unique = []
            for name in answer["tool_calls"]:
                if name not in unique:
                    unique.append(name)
            print("\x1b[2m  ran: " + ", ".join(unique) + "\x1b[0m")
        print("\x1b[1;32mDreadAI:\x1b[0m " + str(answer["content"]) + "\n")


if __name__ == "__main__":
    raise SystemExit(run_repl())
