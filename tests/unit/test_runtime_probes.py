"""Runtime: deterministic role-based probe generation (the non-LLM option)."""

from __future__ import annotations

from mcptrustmap.evidence.roles import assign_roles
from mcptrustmap.models import ArgRecord, ToolRecord
from mcptrustmap.runtime.honey import mint_honey
from mcptrustmap.runtime.probes import probe_arguments, probe_plan


def _tool(name: str, argnames: list[str]) -> ToolRecord:
    tool = ToolRecord(name=name, arguments=[ArgRecord(name=a) for a in argnames])
    assign_roles(tool)
    return tool


def test_probe_by_role():
    honey = mint_honey("s", declared_root="/workspace")
    tool = _tool("act", ["path", "command", "api_key", "url", "content"])
    args = probe_arguments(tool, honey, sink_url="http://sink/")
    assert "/etc/passwd" in args["path"]
    assert honey.canary_marker in args["command"]
    assert args["api_key"] == next(iter(honey.tokens.values()))
    assert args["url"] == "http://sink/"
    assert args["content"] == honey.canary_marker


def test_probe_plan_covers_every_tool():
    honey = mint_honey("s")
    plan = probe_plan([_tool("a", ["path"]), _tool("b", ["content"])], honey)
    assert [name for name, _ in plan] == ["a", "b"]
    assert all(isinstance(probe_args, dict) for _, probe_args in plan)
