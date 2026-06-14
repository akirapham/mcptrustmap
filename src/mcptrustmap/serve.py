"""MCP-server entrypoint: expose `audit` as an MCP tool a host agent can call.

A real distribution pattern (Semgrep ships its scanner as an MCP server the same
way), and a thin wrapper over the same core — no new analysis. `--self-test`
exercises the wrapper without the `mcp` package; the live stdio server needs the
optional `[mcp]` extra.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .audit import audit_to_report
from .errors import InputError
from .evidence.inventory import load_allowlist
from .ingest.manifest import parse_manifest
from .models import ArgRecord, ServerRecord, ToolRecord
from .report import validate_report

AUDIT_TOOL_NAME = "audit"
AUDIT_TOOL_DESCRIPTION = (
    "Audit the authority/authorization trust boundary of an MCP server. "
    "Provide a tools/list manifest path (and optional source dir) or a server-record path; "
    "returns a schema-valid MCPTrustMap report (findings mapped to the OWASP MCP Top 10, beta)."
)

AUDIT_TOOL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "manifest": {"type": "string", "description": "path to a tools/list JSON manifest"},
        "source": {"type": "string", "description": "path to the server source directory"},
        "server_record": {"type": "string", "description": "path to a ServerRecord JSON"},
        "allowlist": {"type": "string", "description": "path to an operator allow-list YAML"},
        "reason": {"type": "boolean", "description": "run the Claude reasoning layer"},
        "llm_mode": {"enum": ["live", "replay"], "description": "reasoning-layer mode"},
    },
}


def handle_audit(arguments: dict[str, Any]) -> dict[str, Any]:
    """The audit tool handler — builds a server from the args and returns a report."""
    allowlist = load_allowlist(arguments["allowlist"]) if arguments.get("allowlist") else None
    if arguments.get("server_record"):
        from .jsonio import load_json

        server = ServerRecord.from_dict(load_json(arguments["server_record"]))
    elif arguments.get("manifest"):
        stem = Path(arguments["manifest"]).stem
        server = ServerRecord(
            server_id=f"manifest:{stem}",
            client="generic",
            transport="stdio",
            source_path=arguments.get("source"),
        )
        server.tools = parse_manifest(arguments["manifest"])
    else:
        raise InputError("audit tool needs a manifest or server_record")
    return audit_to_report(
        server,
        allowlist=allowlist,
        reason=bool(arguments.get("reason", False)),
        llm_mode=arguments.get("llm_mode", "replay"),
    )


def run_self_test() -> int:
    """Verify the wrapper produces a valid report — no `mcp` package required."""
    server = ServerRecord(server_id="serve:selftest", client="generic", transport="stdio")
    server.tools = [
        ToolRecord(
            name="run_cmd",
            description="Run a shell command.",
            arguments=[ArgRecord(name="command", schema_path="properties/command")],
        )
    ]
    report = audit_to_report(server, reason=False)
    validate_report(report)
    assert any(f["finding_id"] == "MTM-UNCONSTRAINED-COMMAND-ARG" for f in report["findings"])
    total = report["summary"]["total_findings"]
    print(f"ok: serve self-test produced a valid report ({total} findings)")
    return 0


def serve_stdio() -> int:  # pragma: no cover - needs the optional `mcp` extra
    """Run the MCP server over stdio, exposing the `audit` tool."""
    import asyncio
    import importlib
    import json

    try:
        mcp_stdio = importlib.import_module("mcp.server.stdio")
        server_cls = importlib.import_module("mcp.server").Server
        types = importlib.import_module("mcp.types")
    except ModuleNotFoundError as exc:
        raise InputError(
            "live serve needs the optional extra: pip install 'mcptrustmap[mcp]'"
        ) from exc
    text_content, tool_cls = types.TextContent, types.Tool

    server: Any = server_cls("mcptrustmap")

    @server.list_tools()
    async def _list_tools() -> list[Any]:
        return [
            tool_cls(
                name=AUDIT_TOOL_NAME,
                description=AUDIT_TOOL_DESCRIPTION,
                inputSchema=AUDIT_TOOL_SCHEMA,
            )
        ]

    @server.call_tool()
    async def _call_tool(name: str, arguments: dict[str, Any]) -> list[Any]:
        if name != AUDIT_TOOL_NAME:
            raise InputError(f"unknown tool: {name!r}")
        report = handle_audit(arguments)
        return [text_content(type="text", text=json.dumps(report, indent=2, sort_keys=True))]

    async def _run() -> None:
        async with mcp_stdio.stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())

    asyncio.run(_run())
    return 0
