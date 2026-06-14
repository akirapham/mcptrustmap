"""Adversarial verification gate.

Stage 1 (anchor, non-LLM) is primary: a candidate whose claimed anchor does not
re-resolve against the evidence graph is dropped before any judge call. Stage 2
is a weighted, refute-biased judge panel. A candidate survives only if both pass.
"""

from __future__ import annotations

from .anchor import anchor_resolves
from .gate import GateResult, evaluate, run_gate
from .judge import run_judge

__all__ = ["GateResult", "anchor_resolves", "evaluate", "run_gate", "run_judge"]
