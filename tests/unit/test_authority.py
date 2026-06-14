"""Phase 2: schema-declared authority classification."""

from __future__ import annotations

from mcptrustmap.evidence.authority import classify_declared_authority
from mcptrustmap.evidence.roles import assign_roles
from mcptrustmap.models import ArgRecord, ToolRecord


def _tool(name, desc="", annotations=None, args=None) -> ToolRecord:
    t = ToolRecord(
        name=name,
        description=desc,
        annotations=annotations or {},
        arguments=args or [],
    )
    assign_roles(t)
    return t


def test_run_shell_is_command_exec():
    t = _tool("run_shell", "Run a shell command", args=[ArgRecord(name="command")])
    classes = classify_declared_authority(t)
    assert "command_exec" in classes


def test_credential_tool():
    t = _tool("store_credential", "Store an API key", args=[ArgRecord(name="api_key")])
    assert "credential_access" in classify_declared_authority(t)


def test_readonly_tool_minimal():
    t = _tool(
        "echo",
        "Echo content back",
        annotations={"readOnlyHint": True},
        args=[ArgRecord(name="content")],
    )
    assert classify_declared_authority(t) == ["read"]


def test_constrained_command_arg_not_command_exec():
    # set_mode's enum-constrained "command" arg is a selector, not execution
    t = _tool("set_mode", "Set the mode", args=[ArgRecord(name="command", constrained=True)])
    classes = classify_declared_authority(t)
    assert "command_exec" not in classes  # critical: keeps the benign control clean
