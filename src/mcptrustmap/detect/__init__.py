"""Deterministic detectors: consume the evidence graph, emit Finding[].

Every finding here is `provenance: deterministic`, `confidence: high` — exact by
construction. The LLM layer + gate add `provenance: llm-verified` findings on top.
"""

from __future__ import annotations

from .arguments import detect_argument_findings
from .authz import detect_authz_findings
from .inventory import (
    detect_collision_findings,
    detect_shadow_findings,
    detect_supply_chain_findings,
)
from .mismatch import detect_mismatch_findings
from .oversharing import detect_oversharing_findings
from .poisoning import detect_poisoning_findings

__all__ = [
    "detect_argument_findings",
    "detect_authz_findings",
    "detect_collision_findings",
    "detect_mismatch_findings",
    "detect_oversharing_findings",
    "detect_poisoning_findings",
    "detect_shadow_findings",
    "detect_supply_chain_findings",
]
