"""Phase 7: gate logic, tested independently of any model (stubbed verdicts)."""

from __future__ import annotations

from mcptrustmap.agent.schemas import CandidateFinding, Verdict
from mcptrustmap.evidence.graph import Anchor, EvidenceFact, EvidenceGraph
from mcptrustmap.verify import anchor_resolves
from mcptrustmap.verify.gate import evaluate


def _v(lens: str, refuted: bool) -> Verdict:
    return Verdict(lens=lens, refuted=refuted, reason="")


def test_anchor_drop_is_terminal():
    result = evaluate(False, [_v("source", False)])
    assert not result.survived
    assert "anchor" in result.reason


def test_survive_with_no_refute_is_high_confidence():
    result = evaluate(True, [_v("source", False), _v("declaration", False), _v("mapping", False)])
    assert result.survived
    assert result.confidence == "high"


def test_source_lens_refute_alone_drops_by_weight():
    # source weight 2 == half of total 4 -> refute*2 >= total -> dropped
    result = evaluate(True, [_v("source", True), _v("declaration", False), _v("mapping", False)])
    assert not result.survived


def test_minority_refute_survives_medium():
    result = evaluate(True, [_v("source", False), _v("declaration", False), _v("mapping", True)])
    assert result.survived
    assert result.confidence == "medium"


def test_empty_verdicts_drop():
    assert not evaluate(True, []).survived


def test_anchor_resolves_against_graph():
    graph = EvidenceGraph()
    graph.add(
        EvidenceFact(
            kind="call",
            anchor=Anchor("file_line", "server.js:9"),
            detail="fs.unlinkSync",
            authority="filesystem",
        )
    )
    good = CandidateFinding(
        "MTM-AUTHORITY-MISMATCH",
        "s:x",
        Anchor("file_line", "server.js:9"),
        "r",
        expect_authority="filesystem",
    )
    bad_line = CandidateFinding(
        "MTM-AUTHORITY-MISMATCH",
        "s:x",
        Anchor("file_line", "server.js:999"),
        "r",
        expect_authority="filesystem",
    )
    wrong_auth = CandidateFinding(
        "MTM-AUTHORITY-MISMATCH",
        "s:x",
        Anchor("file_line", "server.js:9"),
        "r",
        expect_authority="command_exec",
    )
    assert anchor_resolves(good, graph) is True
    assert anchor_resolves(bad_line, graph) is False
    assert anchor_resolves(wrong_auth, graph) is False
