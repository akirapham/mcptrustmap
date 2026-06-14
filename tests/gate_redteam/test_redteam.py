"""Gate red-team: known-false candidates the gate MUST kill.

The judge here ALWAYS upholds, so anything that survives proves the non-LLM
anchor stage is doing the work — the test of the gate's discriminative power and
its resistance to self-enhancement bias.
"""

from __future__ import annotations

from typing import Any

from mcptrustmap.agent.llm_client import LLMClient
from mcptrustmap.agent.schemas import CandidateFinding
from mcptrustmap.evidence.graph import Anchor, EvidenceFact, EvidenceGraph
from mcptrustmap.verify.gate import run_gate


def _always_uphold(_request: dict[str, Any], _context: dict[str, Any]) -> dict[str, Any]:
    return {
        "verdicts": [
            {"lens": "source", "refuted": False, "reason": "uphold"},
            {"lens": "declaration", "refuted": False, "reason": "uphold"},
            {"lens": "mapping", "refuted": False, "reason": "uphold"},
        ]
    }


def _graph() -> EvidenceGraph:
    g = EvidenceGraph()
    g.add(
        EvidenceFact(
            kind="call",
            anchor=Anchor("file_line", "server.js:9"),
            detail="fs.unlinkSync",
            authority="filesystem",
        )
    )
    return g


def _candidate(ref: str, *, finding_id="MTM-AUTHORITY-MISMATCH", authority="filesystem"):
    return CandidateFinding(
        finding_id,
        "s:x",
        Anchor("file_line", ref),
        "r",
        tool="read_file",
        expect_authority=authority,
    )


def test_hallucinated_anchor_killed_even_when_judge_upholds():
    client = LLMClient.record(_always_uphold)
    assert run_gate([_candidate("server.js:999")], _graph(), client) == []


def test_wrong_authority_at_real_line_killed():
    client = LLMClient.record(_always_uphold)
    assert run_gate([_candidate("server.js:9", authority="command_exec")], _graph(), client) == []


def test_unknown_finding_id_dropped():
    client = LLMClient.record(_always_uphold)
    assert run_gate([_candidate("server.js:9", finding_id="MTM-NOT-REAL")], _graph(), client) == []


def test_legitimate_candidate_survives():
    client = LLMClient.record(_always_uphold)
    out = run_gate([_candidate("server.js:9")], _graph(), client)
    assert len(out) == 1
    assert out[0].provenance == "llm-verified"
    assert out[0].finding_id == "MTM-AUTHORITY-MISMATCH"
