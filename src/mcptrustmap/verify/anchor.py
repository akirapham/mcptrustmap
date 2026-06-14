"""Stage 1: re-resolve a candidate's claimed anchor against the evidence graph.

This is the load-bearing, non-LLM check — the strongest verifier precisely
because it is not a model.
"""

from __future__ import annotations

from ..agent.schemas import CandidateFinding
from ..evidence.graph import EvidenceGraph


def anchor_resolves(candidate: CandidateFinding, graph: EvidenceGraph) -> bool:
    """True if a fact exists at the claimed anchor (matching expect_authority if set)."""
    return graph.resolve(candidate.claimed_anchor.ref, expect_authority=candidate.expect_authority)
