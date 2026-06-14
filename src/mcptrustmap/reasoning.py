"""Integration of the Claude reasoning layer + verification gate into audits.

The reasoner proposes anchored candidates; the gate re-resolves each anchor and
runs a weighted judge panel. Only survivors become `llm-verified` findings. In
`replay` mode everything runs from recorded cassettes (deterministic CI); a
sourceless server skips the layer entirely (nothing to reason over).
"""

from __future__ import annotations

import os
from pathlib import Path

from .agent import run_reasoner
from .agent.llm_client import LLMClient
from .errors import InputError
from .evidence import EvidenceGraph
from .models import Finding, ServerRecord
from .verify import run_gate


def default_cassette_dir() -> Path:
    env = os.environ.get("MTM_CASSETTE_DIR")
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[2] / "tests" / "cassettes"


def _make_client(llm_mode: str, cassette_dir: str | Path | None) -> LLMClient:
    if llm_mode == "replay":
        return LLMClient.replay(cassette_dir or default_cassette_dir())
    if llm_mode == "live":
        return LLMClient.live()
    raise InputError(f"unknown llm mode: {llm_mode!r}")


def run_reasoning_layer(
    server: ServerRecord,
    graph: EvidenceGraph,
    *,
    llm_mode: str = "replay",
    cassette_dir: str | Path | None = None,
    client: LLMClient | None = None,
) -> tuple[list[Finding], str | None]:
    """Return (llm-verified findings, cassette-set hash)."""
    if not server.source_path:
        return [], None
    client = client or _make_client(llm_mode, cassette_dir)
    candidates = run_reasoner(server, graph, client)
    findings = run_gate(candidates, graph, client)
    return findings, client.cassette_set_hash
