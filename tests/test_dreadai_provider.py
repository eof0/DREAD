"""DreadAI model provider: Claude by default, local Qwen via Ollama when configured."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_DREADAI = _REPO / "dreadai"
for p in (str(_REPO), str(_DREADAI)):
    if p not in sys.path:
        sys.path.insert(0, p)

import agent


@pytest.fixture(autouse=True)
def _isolate_provider_env():
    keys = ["DREADAI_PROVIDER", "DREADAI_MODEL", "DREADAI_BASE_URL", "OLLAMA_HOST",
            "DREADAI_API_KEY", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
            "DREADAI_ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY", "GOOGLE_API_KEY"]
    saved = {k: os.environ.get(k) for k in keys}
    for k in keys:
        os.environ.pop(k, None)
    yield
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


class _Fake:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


def test_default_provider_is_claude(monkeypatch):
    captured = {}
    monkeypatch.setattr(agent, "ChatAnthropic", lambda **kw: captured.update(kw) or _Fake(**kw))

    agent.build_model()
    assert captured["model"] == "claude-sonnet-5"


def test_ollama_provider_uses_qwen_and_local_endpoint(monkeypatch):
    monkeypatch.setenv("DREADAI_PROVIDER", "ollama")
    made = {}
    monkeypatch.setattr(agent, "_load_chat_class",
                        lambda dotted: (lambda **kw: made.update(dotted=dotted, **kw) or _Fake(**kw)))

    agent.build_model()
    assert "ChatOllama" in made["dotted"]
    assert made["model"] == "qwen2.5-coder:7b"          # sensible local default
    assert made["base_url"] == "http://localhost:11434"  # Ollama default


def test_explicit_model_and_base_url_override(monkeypatch):
    monkeypatch.setenv("DREADAI_PROVIDER", "ollama")
    monkeypatch.setenv("DREADAI_MODEL", "qwen2.5-coder:14b")
    monkeypatch.setenv("DREADAI_BASE_URL", "http://192.168.1.5:11434")
    made = {}
    monkeypatch.setattr(agent, "_load_chat_class",
                        lambda dotted: (lambda **kw: made.update(**kw) or _Fake(**kw)))

    agent.build_model()
    assert made["model"] == "qwen2.5-coder:14b"
    assert made["base_url"] == "http://192.168.1.5:11434"


def test_ollama_falls_back_to_openai_compatible(monkeypatch):
    monkeypatch.setenv("DREADAI_PROVIDER", "ollama")
    made = {}

    def loader(dotted):
        if "ChatOllama" in dotted:
            raise ImportError("langchain-ollama not installed")
        return lambda **kw: made.update(dotted=dotted, **kw) or _Fake(**kw)

    monkeypatch.setattr(agent, "_load_chat_class", loader)

    agent.build_model()
    # Falls back to the OpenAI-compatible client against Ollama's /v1.
    assert "ChatOpenAI" in made["dotted"]
    assert made["base_url"].endswith("/v1")


def test_helpful_error_when_no_local_provider(monkeypatch):
    monkeypatch.setenv("DREADAI_PROVIDER", "ollama")
    monkeypatch.setattr(agent, "_load_chat_class",
                        lambda dotted: (_ for _ in ()).throw(ImportError("nope")))

    with pytest.raises(RuntimeError) as err:
        agent.build_model()
    msg = str(err.value).lower()
    assert "langchain-ollama" in msg or "langchain-openai" in msg


# --- Any cloud model (OpenAI/GPT, Gemini, OpenRouter, ... anything) --------------------

def test_gpt_alias_uses_openai_compatible(monkeypatch):
    monkeypatch.setenv("DREADAI_PROVIDER", "gpt")           # alias -> openai
    made = {}
    monkeypatch.setattr(agent, "_load_chat_class",
                        lambda dotted: (lambda **kw: made.update(dotted=dotted, **kw) or _Fake(**kw)))

    agent.build_model()
    assert "ChatOpenAI" in made["dotted"]
    assert made["model"] == "gpt-4o-mini"


def test_openrouter_uses_its_base_url(monkeypatch):
    monkeypatch.setenv("DREADAI_PROVIDER", "openrouter")
    made = {}
    monkeypatch.setattr(agent, "_load_chat_class",
                        lambda dotted: (lambda **kw: made.update(dotted=dotted, **kw) or _Fake(**kw)))

    agent.build_model()
    assert "ChatOpenAI" in made["dotted"]
    assert made["base_url"] == "https://openrouter.ai/api/v1"


def test_gemini_alias_uses_google_provider(monkeypatch):
    monkeypatch.setenv("DREADAI_PROVIDER", "gemini")        # alias -> google
    made = {}
    monkeypatch.setattr(agent, "_load_chat_class",
                        lambda dotted: (lambda **kw: made.update(dotted=dotted, **kw) or _Fake(**kw)))

    agent.build_model()
    assert "ChatGoogleGenerativeAI" in made["dotted"]
    assert made["model"] == "gemini-1.5-flash"


def test_unknown_provider_is_openai_compatible_via_base_url(monkeypatch):
    # "anything": an unlisted provider works as an OpenAI-compatible endpoint.
    monkeypatch.setenv("DREADAI_PROVIDER", "bigpickle")
    monkeypatch.setenv("DREADAI_BASE_URL", "https://pickle.example/v1")
    monkeypatch.setenv("DREADAI_MODEL", "pickle-xl")
    made = {}
    monkeypatch.setattr(agent, "_load_chat_class",
                        lambda dotted: (lambda **kw: made.update(dotted=dotted, **kw) or _Fake(**kw)))

    agent.build_model()
    assert "ChatOpenAI" in made["dotted"]
    assert made["base_url"] == "https://pickle.example/v1"
    assert made["model"] == "pickle-xl"


# --- Claude via login OR api key ------------------------------------------------------

def test_anthropic_api_key_sends_x_api_key(monkeypatch):
    # Real ChatAnthropic (no network at construction) — verify the key becomes x-api-key.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")

    model = agent.build_model()
    headers = model._client.auth_headers
    assert headers.get("X-Api-Key") == "sk-ant-test-key"
    assert "Authorization" not in headers


def test_anthropic_login_token_sends_bearer_not_api_key(monkeypatch):
    # A login/OAuth bearer token must go out as Authorization: Bearer, with no x-api-key.
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "oauth-abc123")

    model = agent.build_model()
    headers = model._client.auth_headers
    assert headers.get("Authorization") == "Bearer oauth-abc123"
    assert "X-Api-Key" not in headers
    # The OAuth beta header must ride along.
    assert model._client.default_headers.get("anthropic-beta") == "oauth-2025-04-20"
