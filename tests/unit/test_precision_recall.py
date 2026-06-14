"""DVMCP precision/recall over frozen positives + benign negatives.

Positives: the in-scope DVMCP challenges (each should yield its expected finding).
Negatives: the controlled benign server, driven deterministically and by gpt-4o
(each should yield none). This is the first real metric — recall alone was
meaningless without a false-positive denominator.
"""

from __future__ import annotations

import json
from pathlib import Path

from mcptrustmap.runtime.dvmcp import CHALLENGES
from mcptrustmap.runtime.harness import pentest_server
from mcptrustmap.runtime.honey import mint_honey
from mcptrustmap.runtime.metrics import score
from mcptrustmap.runtime.sandbox import FakeSandbox

OBS = Path(__file__).resolve().parents[1] / "fixtures" / "observations"


def _findings(name: str, honey):
    payload = json.loads((OBS / f"{name}.json").read_text(encoding="utf-8"))
    return pentest_server(name, FakeSandbox.from_dict(payload), honey, _declared(name))


def _declared(name: str) -> dict:
    cid = name.split("_")[-1] if name.startswith("dvmcp_") else ""
    return CHALLENGES[cid].declared if cid in CHALLENGES else {}


def _detected(cid: str) -> bool:
    ch = CHALLENGES[cid]
    honey = mint_honey(ch.seed, declared_root="/honey", watch=ch.watch)
    ids = {f.finding_id for f in _findings(f"dvmcp_{cid}", honey)}
    return ch.expect in ids


def _benign_flagged(name: str) -> bool:
    honey = mint_honey("benign", declared_root="/honey")
    return bool(_findings(name, honey))


# --- negatives: the benign server must never be flagged ---


def test_benign_targets_produce_no_findings():
    assert _benign_flagged("benign_deterministic") is False
    assert _benign_flagged("benign_llm") is False


# --- the two honest scoreboards ---


def test_autonomous_blackbox_scoreboard_is_perfect():
    # Every in-scope challenge is detected by the autonomous (multi-round) gpt-4o
    # attacker — including ch3, which the recon loop closed (search -> read).
    assert all(CHALLENGES[cid].llm_blackbox for cid in CHALLENGES)
    positives = [_detected(cid) for cid in CHALLENGES]
    negatives = [_benign_flagged("benign_deterministic"), _benign_flagged("benign_llm")]
    sb = score(positives, negatives)
    assert (sb.tp, sb.fn, sb.fp, sb.tn) == (len(CHALLENGES), 0, 0, 2)
    assert sb.precision == 1.0 and sb.recall == 1.0 and sb.f1 == 1.0
