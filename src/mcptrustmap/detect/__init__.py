"""Deterministic detectors: consume the evidence graph, emit Finding[].

Every finding here is `provenance: deterministic`, `confidence: high` — exact by
construction. The LLM layer + gate add `provenance: llm-verified` findings on top.
"""

from __future__ import annotations

from .arguments import detect_argument_findings
from .mismatch import detect_mismatch_findings

__all__ = ["detect_argument_findings", "detect_mismatch_findings"]
