"""Live MCP ingestion via the official MCP SDK (optional `[mcp]` extra).

Produces the same ToolRecord[] as the offline manifest path, so the deterministic
core analyzes a live server identically. Opt-in and never part of the release
gate. Imports `mcp` lazily so the core never depends on it.
"""

from __future__ import annotations

from typing import Any

from .errors import InputError
from .ingest.manifest import tool_from_entry
from .models import ServerRecord


def connect_server(
    command: str, *, transport: str = "stdio", server_id: str = "connect:live"
) -> ServerRecord:  # pragma: no cover - needs the optional `mcp` extra + a live server
    import asyncio
    import importlib

    try:
        mcp_mod = importlib.import_module("mcp")
        stdio_client = importlib.import_module("mcp.client.stdio").stdio_client
    except ModuleNotFoundError as exc:
        raise InputError(
            "live --connect needs the optional extra: pip install 'mcptrustmap[mcp]'"
        ) from exc
    client_session = mcp_mod.ClientSession
    stdio_params = mcp_mod.StdioServerParameters

    if transport != "stdio":
        raise InputError(f"v0.1 live connect supports stdio only, got {transport!r}")
    if not command:
        raise InputError("--connect requires --command")

    async def _list_tools() -> list[dict[str, Any]]:
        parts = command.split()
        params = stdio_params(command=parts[0], args=parts[1:])
        async with (
            stdio_client(params) as (read, write),
            client_session(read, write) as session,
        ):
            await session.initialize()
            result = await session.list_tools()
            entries: list[dict[str, Any]] = []
            for tool in result.tools:
                annotations = getattr(tool, "annotations", None)
                entries.append(
                    {
                        "name": tool.name,
                        "description": tool.description,
                        "inputSchema": tool.inputSchema or {},
                        "annotations": dict(annotations) if annotations else {},
                    }
                )
            return entries

    entries = asyncio.run(_list_tools())
    server = ServerRecord(server_id=server_id, client="generic", transport="stdio", command=command)
    server.tools = [tool_from_entry(e) for e in entries]
    return server
