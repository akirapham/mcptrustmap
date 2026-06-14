"""Deterministic evidence layer: pure facts, each pinned to a concrete anchor.

No LLM, no network. This layer is byte-reproducible and is the substrate the
verification gate re-resolves LLM candidate anchors against.
"""

from __future__ import annotations

from .authority import classify_declared_authority
from .graph import Anchor, EvidenceFact, EvidenceGraph
from .prepare import prepare_server
from .roles import assign_role, assign_roles

__all__ = [
    "Anchor",
    "EvidenceFact",
    "EvidenceGraph",
    "assign_role",
    "assign_roles",
    "classify_declared_authority",
    "prepare_server",
]
