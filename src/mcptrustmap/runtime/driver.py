"""MCP driver — list the sandboxed server's tools, fire one probe each, observe.

The driver fuses three observation channels into a per-tool ToolEffect: the tool's
own MCP response text, the filesystem delta captured by snapshotting the honey dir
*around* that single call, and the slice of egress events the sink recorded during
it. Because exactly one tool runs per probe, every observed effect is attributable
to that tool.

The fusion (`build_effect`) and the response flattening (`result_text`) are pure
and unit-tested. The async stdio session that actually talks to the container is
no-cover — it needs the optional `mcp` extra and a live server.
"""

from __future__ import annotations

from typing import Any

from .fsdiff import FsDelta, under_root
from .observe import EgressEvent, Observation, ToolEffect


def result_text(content: Any) -> str:
    """Flatten an MCP call result's content blocks (object- or dict-shaped) to text."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    parts: list[str] = []
    for block in content:
        text = getattr(block, "text", None)
        if text is None and isinstance(block, dict):
            text = block.get("text")
        if text:
            parts.append(str(text))
    return "\n".join(parts)


def build_effect(
    tool: str,
    arguments: dict[str, Any],
    response: str,
    fs_delta: FsDelta,
    egress: list[EgressEvent],
    *,
    declared_root: str,
) -> ToolEffect:
    """Assemble one tool's observed effect from the three channels.

    fs writes/deletes are re-anchored from honey-relative to in-container absolute
    paths so the path-escape oracle compares against the declared root. `execs` and
    `fs_reads` stay empty in the base backend — capturing them needs syscall
    tracing (a later increment), so the command-exec / read-escape oracles are
    simply not exercised here rather than guessed at.
    """
    return ToolEffect(
        tool=tool,
        arguments=dict(arguments),
        response=response,
        fs_writes=under_root(fs_delta.writes, declared_root),
        fs_deletes=under_root(fs_delta.deletes, declared_root),
        egress=list(egress),
    )


def names_of(tools: Any) -> list[str]:
    """Tool names from an MCP list_tools result (object- or dict-shaped)."""
    items = getattr(tools, "tools", tools)
    out: list[str] = []
    for tool in items:
        name = getattr(tool, "name", None)
        if name is None and isinstance(tool, dict):
            name = tool.get("name")
        if name:
            out.append(str(name))
    return out


async def drive_session(
    session: Any,
    probes: list[tuple[str, dict[str, Any]]],
    *,
    snapshot,
    egress_since,
    declared_root: str,
) -> Observation:  # pragma: no cover - needs the `mcp` extra + a live containerized server
    """Initialize, list tools, fire each probe with before/after observation, relist.

    `snapshot()` returns an FsSnapshot of the honey dir; `egress_since(n)` returns
    the sink events recorded after index `n`. Both are injected so this stays
    transport-agnostic and the fusion logic above remains the only thing under test.
    """
    from .fsdiff import diff_snapshots

    await session.initialize()
    before_tools = names_of(await session.list_tools())

    effects: list[ToolEffect] = []
    for name, arguments in probes:
        pre_fs = snapshot()
        pre_egress = egress_since(0)
        try:
            result = await session.call_tool(name, arguments)
            response = result_text(getattr(result, "content", None))
        except Exception as exc:  # noqa: BLE001 - a crash is itself an observation
            response = f"<call_tool error: {exc}>"
        post_fs = snapshot()
        new_egress = egress_since(len(pre_egress))
        effects.append(
            build_effect(
                name,
                arguments,
                response,
                diff_snapshots(pre_fs, post_fs),
                new_egress,
                declared_root=declared_root,
            )
        )

    after_tools = names_of(await session.list_tools())
    return Observation(
        effects=effects, tool_list_before=before_tools, tool_list_after=after_tools
    )
