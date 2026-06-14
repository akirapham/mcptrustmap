"""Agent live path: the runtime-attack request renders + parses correctly.

Mocks the Anthropic client so the *rendering* (system prompt, user message, output
schema) and response parsing are verified without an API key — the live planner is
trustworthy before we ever spend a token on it.
"""

from __future__ import annotations

import sys
import types

from mcptrustmap.runtime.attacker import build_attack_request
from mcptrustmap.runtime.honey import mint_honey


def test_live_attack_renders_request_and_parses_plan(monkeypatch):
    captured: dict = {}

    class _Messages:
        def create(self, **kw):
            captured.update(kw)
            block = types.SimpleNamespace(
                type="text",
                text='{"probes": [{"tool": "ping_host", "arguments": {"host": "x"}}]}',
            )
            return types.SimpleNamespace(content=[block])

    class _Anthropic:
        def __init__(self, *a, **k):
            self.messages = _Messages()

    monkeypatch.setitem(sys.modules, "anthropic", types.SimpleNamespace(Anthropic=_Anthropic))

    from mcptrustmap.agent.live import live_complete

    honey = mint_honey("s", declared_root="/honey")
    request = build_attack_request(
        [], honey, sink_url="http://127.0.0.1:{port}/exfil", model="claude-opus-4-8"
    )
    plan = live_complete(None, request, {})

    # parsed the structured response
    assert plan == {"probes": [{"tool": "ping_host", "arguments": {"host": "x"}}]}
    # rendered the right call: model, attacker system prompt, arsenal in the user msg, schema
    assert captured["model"] == "claude-opus-4-8"
    user_msg = captured["messages"][0]["content"]
    assert "ARSENAL" in user_msg and "TOOLS" in user_msg
    assert captured["output_config"]["format"]["type"] == "json_schema"
    assert "probes" in captured["output_config"]["format"]["schema"]["properties"]
