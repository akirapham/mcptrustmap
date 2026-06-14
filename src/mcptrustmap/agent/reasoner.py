"""The generator: drive Claude to emit anchored CandidateFinding[] for a server.

v0.1 assembles the server source on our side (via the repo-scoped tools) and asks
for structured candidates in one call; in `live` mode this becomes an Anthropic
structured-output request, in `replay`/`record` it is keyed by a hash of the
salient inputs. Either way the candidates validate against the schema before the
gate sees them.
"""

from __future__ import annotations

import hashlib
from typing import Any

from ..errors import InputError
from ..evidence.graph import EvidenceGraph
from ..models import ServerRecord
from .llm_client import LLMClient
from .prompts import PROMPT_VERSION
from .schemas import CandidateFinding, parse_candidates
from .tools import RepoTools


def gather_source(server: ServerRecord) -> dict[str, str]:
    if not server.source_path:
        return {}
    try:
        return RepoTools(server.source_path).read_repo()
    except InputError:
        return {}


def _source_digest(source_files: dict[str, str]) -> str:
    h = hashlib.sha256()
    for rel in sorted(source_files):
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        h.update(source_files[rel].encode("utf-8", "replace"))
        h.update(b"\0")
    return h.hexdigest()[:16]


def _tool_summaries(server: ServerRecord) -> list[dict[str, Any]]:
    return [
        {
            "name": t.name,
            "description": t.description,
            "annotations": t.annotations,
            "declared_authority": t.declared_authority,
            "arguments": [
                {"name": a.name, "role": a.role, "constrained": a.constrained} for a in t.arguments
            ],
        }
        for t in server.tools
    ]


def build_reason_request(
    server: ServerRecord, source_files: dict[str, str], model: str
) -> dict[str, Any]:
    return {
        "purpose": "reason",
        "prompt_version": PROMPT_VERSION,
        "model": model,
        "server_id": server.server_id,
        "tools": _tool_summaries(server),
        "source_digest": _source_digest(source_files),
    }


def run_reasoner(
    server: ServerRecord, graph: EvidenceGraph, client: LLMClient
) -> list[CandidateFinding]:
    source_files = gather_source(server)
    request = build_reason_request(server, source_files, client.models["reason"])
    response = client.complete(
        request,
        context={"source_files": source_files, "server": server, "graph": graph},
    )
    return parse_candidates(response, server.server_id)
