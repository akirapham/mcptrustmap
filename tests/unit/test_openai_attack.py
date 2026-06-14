"""OpenAI attacker backend: renders + parses a plan without a key; provider routing."""

from __future__ import annotations

import sys
import types

import pytest

from mcptrustmap.agent.llm_client import LLMClient
from mcptrustmap.errors import MtmError
from mcptrustmap.runtime.attacker import build_attack_request
from mcptrustmap.runtime.honey import mint_honey


def test_unknown_provider_rejected():
    with pytest.raises(MtmError):
        LLMClient("live", provider="gemini")


def test_openai_backend_renders_and_parses(monkeypatch):
    captured: dict = {}

    class _Completions:
        def create(self, **kw):
            captured.update(kw)
            plan = '{"probes": [{"tool": "ping_host", "arguments": {"host": "127.0.0.1; id"}}]}'
            msg = types.SimpleNamespace(content=plan)
            return types.SimpleNamespace(choices=[types.SimpleNamespace(message=msg)])

    class _Chat:
        def __init__(self):
            self.completions = _Completions()

    class _OpenAI:
        def __init__(self, *a, **k):
            self.chat = _Chat()

    monkeypatch.setitem(sys.modules, "openai", types.SimpleNamespace(OpenAI=_OpenAI))

    from mcptrustmap.agent.openai_live import openai_complete

    honey = mint_honey("s", declared_root="/honey")
    request = build_attack_request([], honey, sink_url="http://x/{port}", model="gpt-4o")
    plan = openai_complete(None, request, {})

    assert plan["probes"][0]["tool"] == "ping_host"
    assert captured["model"] == "gpt-4o"
    assert captured["response_format"] == {"type": "json_object"}
    # the attacker system prompt + arsenal both reach the model
    msgs = {m["role"]: m["content"] for m in captured["messages"]}
    assert "penetration tester" in msgs["system"]
    assert "ARSENAL" in msgs["user"]


def test_openai_backend_rejects_non_attack_purpose(monkeypatch):
    monkeypatch.setitem(sys.modules, "openai", types.SimpleNamespace(OpenAI=object))
    from mcptrustmap.agent.openai_live import openai_complete

    with pytest.raises(ValueError, match="runtime-attack"):
        openai_complete(None, {"purpose": "reason", "model": "gpt-4o"}, {})
