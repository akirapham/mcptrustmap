"""Integration point for the Claude reasoning layer + verification gate.

Phase 6 adds the reasoner (candidate findings from server source/descriptions);
Phase 7 adds the gate (anchor re-resolution + weighted judge panel). Until those
land this is a no-op, so `--reason` simply runs the deterministic pipeline and
the report's cassette set is null.
"""

from __future__ import annotations

from .evidence import EvidenceGraph
from .models import Finding, ServerRecord


def run_reasoning_layer(
    server: ServerRecord,
    graph: EvidenceGraph,
    *,
    llm_mode: str = "replay",
) -> tuple[list[Finding], str | None]:
    """Return (llm-verified findings, cassette-set hash). No-op until Phase 6/7."""
    return [], None
