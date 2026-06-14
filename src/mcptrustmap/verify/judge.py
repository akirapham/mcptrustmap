"""Stage 2: the adversarial judge panel (weighted, refute-biased).

One call returns the panel's per-lens verdicts. In live mode the panel spans
model tiers (Opus/Sonnet/Haiku) to resist self-enhancement bias; in replay the
verdicts come from cassettes. The gate logic (gate.evaluate) is tested
independently of any model with stubbed verdicts.
"""

from __future__ import annotations

from typing import Any

from ..agent.llm_client import LLMClient
from ..agent.prompts import PROMPT_VERSION
from ..agent.schemas import CandidateFinding, Verdict, parse_verdicts
from ..evidence.graph import EvidenceGraph


def _judge_model(client: LLMClient) -> str:
    judge = client.models.get("judge", "claude-opus-4-8")
    return judge[0] if isinstance(judge, list) else judge


def build_judge_request(candidate: CandidateFinding, model: str) -> dict[str, Any]:
    return {
        "purpose": "judge",
        "prompt_version": PROMPT_VERSION,
        "model": model,
        "server_id": candidate.server_id,
        "candidate": candidate.to_dict(),
    }


def run_judge(
    candidate: CandidateFinding, graph: EvidenceGraph, client: LLMClient
) -> list[Verdict]:
    request = build_judge_request(candidate, _judge_model(client))
    anchor_facts = [f.to_dict() for f in graph.at(candidate.claimed_anchor.ref)]
    response = client.complete(request, context={"anchor_facts": anchor_facts})
    return parse_verdicts(response)
