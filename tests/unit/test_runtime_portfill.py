"""Runtime: probe args plan against a `{port}` template, resolved at call time.

Keeps the LLM attack-plan request hash independent of the sink's random port, so a
recorded cassette replays across runs.
"""

from __future__ import annotations

from mcptrustmap.runtime.attacker import build_attack_request
from mcptrustmap.runtime.honey import mint_honey
from mcptrustmap.runtime.sandbox import _resolve_port


def test_resolve_port_fills_only_string_values():
    out = _resolve_port({"url": "http://127.0.0.1:{port}/x", "count": 3}, "55021")
    assert out == {"url": "http://127.0.0.1:55021/x", "count": 3}


def test_attack_request_hash_is_port_independent():
    honey = mint_honey("s", declared_root="/honey")
    template = "http://127.0.0.1:{port}/exfil"
    # planning uses the template, so the request is identical run-to-run
    r1 = build_attack_request([], honey, sink_url=template, model="claude-opus-4-8")
    r2 = build_attack_request([], honey, sink_url=template, model="claude-opus-4-8")
    assert r1 == r2
    assert "{port}" in r1["arsenal"]["sink_url"]  # no volatile port baked into the hash
