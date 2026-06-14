"""Source-derived authority inference (the *actual* side of the mismatch check).

Python is analyzed with stdlib `ast` (line-accurate, high confidence, becomes
deterministic findings). Other languages get curated regex `call` facts that
serve only as anchors for the LLM layer + gate.
"""

from __future__ import annotations

from ...models import ServerRecord
from ..graph import EvidenceGraph
from .generic_regex import add_generic_facts
from .python_ast import analyze_python_source, infer_python_authority


def infer_source_authority(server: ServerRecord, graph: EvidenceGraph) -> None:
    """Seed both Python (ast, per-tool) and non-Python (regex, anchor-only) facts."""
    infer_python_authority(server, graph)
    add_generic_facts(server, graph)


__all__ = [
    "add_generic_facts",
    "analyze_python_source",
    "infer_python_authority",
    "infer_source_authority",
]
