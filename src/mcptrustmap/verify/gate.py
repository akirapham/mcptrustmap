"""Combine anchor + weighted panel into survive/drop, and build the finding.

`evaluate` is a pure function (anchor_ok, verdicts) -> GateResult, tested with
stubbed verdicts so gate correctness does not depend on any model.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..agent.llm_client import LLMClient
from ..agent.schemas import CandidateFinding, Verdict
from ..evidence.graph import EvidenceGraph
from ..findings import REGISTRY, make_finding
from ..models import Finding
from .anchor import anchor_resolves
from .judge import run_judge

# weighted aggregation: naive averaging of weak verifiers underperforms, so the
# source lens (closest to the anchor) counts double.
_LENS_WEIGHT = {"source": 2, "declaration": 1, "mapping": 1}


@dataclass
class GateResult:
    survived: bool
    reason: str
    confidence: str | None = None


def evaluate(anchor_ok: bool, verdicts: list[Verdict]) -> GateResult:
    if not anchor_ok:
        return GateResult(False, "anchor did not re-resolve against the evidence graph")
    if not verdicts:
        return GateResult(False, "no judge verdicts")
    total = sum(_LENS_WEIGHT.get(v.lens, 1) for v in verdicts)
    refute = sum(_LENS_WEIGHT.get(v.lens, 1) for v in verdicts if v.refuted)
    if refute * 2 >= total:
        return GateResult(False, f"weighted panel refuted ({refute}/{total} weight)")
    confidence = "high" if refute == 0 else "medium"
    return GateResult(True, f"weighted panel upheld ({refute}/{total} refute weight)", confidence)


def _to_finding(candidate: CandidateFinding, graph: EvidenceGraph, result: GateResult) -> Finding:
    facts = graph.at(candidate.claimed_anchor.ref)
    evidence = [f.evidence_ref() for f in facts] or [
        {
            "kind": candidate.claimed_anchor.kind,
            "ref": candidate.claimed_anchor.ref,
            "detail": candidate.rationale[:100],
        }
    ]
    return make_finding(
        candidate.finding_id,
        candidate.server_id,
        evidence,
        confidence=result.confidence or "medium",
        provenance="llm-verified",
        tool=candidate.tool,
        argument=candidate.argument,
        sub_type=candidate.sub_type,
        title_suffix=candidate.sub_type,
    )


def run_gate(
    candidates: list[CandidateFinding], graph: EvidenceGraph, client: LLMClient
) -> list[Finding]:
    findings: list[Finding] = []
    for candidate in candidates:
        if candidate.finding_id not in REGISTRY:
            continue  # LLM proposed an unknown id — drop
        if not anchor_resolves(candidate, graph):
            continue  # Stage 1 drop (pre-judge)
        verdicts = run_judge(candidate, graph, client)
        result = evaluate(True, verdicts)
        if result.survived:
            findings.append(_to_finding(candidate, graph, result))
    return findings
