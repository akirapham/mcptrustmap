"""Claude reasoning layer: an agent that proposes candidate findings.

Every candidate cites a concrete anchor and is only reported if the verification
gate re-resolves that anchor and a weighted judge panel does not refute it. The
client is an abstraction with live / replay / record backends, so the layer runs
deterministically in CI from recorded cassettes.
"""

from __future__ import annotations

from .llm_client import LLMClient
from .reasoner import run_reasoner
from .schemas import CandidateFinding, Verdict

__all__ = ["CandidateFinding", "LLMClient", "Verdict", "run_reasoner"]
