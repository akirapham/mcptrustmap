#!/usr/bin/env python
"""Re-record agent-layer cassettes for the fixtures (maintainer tool).

A scripted responder encodes what the Claude reasoning + judge layers should
return for each fixture, and the recorder bakes those into request-hash-keyed
cassettes so CI replays them deterministically (no API key, no network). Run
after changing prompts, models, or fixtures:

    uv run python scripts/record_cassettes.py
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mcptrustmap.agent.llm_client import LLMClient  # noqa: E402
from mcptrustmap.audit import audit_server  # noqa: E402
from mcptrustmap.ingest.manifest import parse_manifest  # noqa: E402
from mcptrustmap.models import ServerRecord  # noqa: E402
from mcptrustmap.reasoning import run_reasoning_layer  # noqa: E402

FIXTURES = [
    (
        "manifest:vulnerable",
        "examples/manifests/vulnerable.json",
        "examples/servers/vulnerable-mcp",
    ),
    (
        "manifest:js-vulnerable",
        "examples/manifests/js-vulnerable.json",
        "examples/servers/js-vulnerable",
    ),
]


def _find_line(files: dict[str, str], needle: str) -> str | None:
    for rel, content in files.items():
        for i, line in enumerate(content.splitlines(), 1):
            if needle in line:
                return f"{rel}:{i}"
    return None


def scripted_responder(request: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    if request["purpose"] == "reason":
        return _reason(request["server_id"], context)
    if request["purpose"] == "judge":
        return _judge(request["candidate"])
    raise ValueError(request["purpose"])


def _reason(server_id: str, context: dict[str, Any]) -> dict[str, Any]:
    if server_id != "manifest:js-vulnerable":
        # Python fixtures are fully covered by the deterministic ast path.
        return {"candidates": []}
    line = _find_line(context["source_files"], "unlinkSync")
    return {
        "candidates": [
            {
                "finding_id": "MTM-AUTHORITY-MISMATCH",
                "tool": "read_file",
                "claimed_anchor": {"kind": "file_line", "ref": line},
                "expect_authority": "filesystem",
                "rationale": "read_file is declared read-only but deletes via fs.unlinkSync.",
            },
            {
                "finding_id": "MTM-AUTHORITY-MISMATCH",
                "tool": "echo",
                "claimed_anchor": {"kind": "file_line", "ref": line},
                "expect_authority": "filesystem",
                "rationale": "WRONG: echo only returns content; this claim is incorrect.",
            },
            {
                "finding_id": "MTM-AUTHORITY-MISMATCH",
                "tool": "read_file",
                "claimed_anchor": {"kind": "file_line", "ref": "server.js:999"},
                "expect_authority": "filesystem",
                "rationale": "hallucinated anchor that does not exist in the source.",
            },
        ]
    }


def _judge(candidate: dict[str, Any]) -> dict[str, Any]:
    refute = candidate.get("tool") == "echo" or candidate.get("rationale", "").startswith("WRONG")
    if refute:
        return {
            "verdicts": [
                {
                    "lens": "source",
                    "refuted": True,
                    "reason": "cited line is not this tool",
                    "anchor_confirmed": False,
                },
                {"lens": "declaration", "refuted": True, "reason": "no genuine contradiction"},
                {"lens": "mapping", "refuted": False, "reason": "mapping is plausible"},
            ]
        }
    return {
        "verdicts": [
            {
                "lens": "source",
                "refuted": False,
                "reason": "fs.unlinkSync deletes the file",
                "anchor_confirmed": True,
            },
            {
                "lens": "declaration",
                "refuted": False,
                "reason": "readOnlyHint:true is contradicted",
            },
            {"lens": "mapping", "refuted": False, "reason": "MCP07 mismatch is correct"},
        ]
    }


def main() -> int:
    client = LLMClient.record(scripted_responder)
    for server_id, manifest, source in FIXTURES:
        server = ServerRecord(
            server_id=server_id, client="generic", transport="stdio", source_path=str(ROOT / source)
        )
        server.tools = parse_manifest(ROOT / manifest)
        _, graph = audit_server(server)
        run_reasoning_layer(server, graph, client=client)
    out = ROOT / "tests" / "cassettes" / "fixtures.json"
    client.save(out)
    print(f"wrote {len(client.recorded())} cassette entries -> {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
