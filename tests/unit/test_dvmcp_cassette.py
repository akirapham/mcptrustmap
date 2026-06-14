"""DVMCP: prove the *LLM itself* planned the probes that produced each finding.

Once scripts/record_attack_cassettes.py has run (needs a key + DVMCP), the cassette
holds Claude's own attack plans and the frozen observations are the result of
executing them. This test chains the two in CI with no key and no checkout: every
probe executed in a frozen observation must be one the model planned. Combined with
test_dvmcp (frozen observation -> ground-truth finding), that closes the loop:
Claude planned the probe, and that probe produced the runtime-confirmed finding.

Skips until the cassette exists, so it activates the moment recordings land.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CASSETTE = ROOT / "cassettes" / "dvmcp_attack.json"
OBS = ROOT / "fixtures" / "observations"

pytestmark = pytest.mark.skipif(
    not CASSETTE.exists(), reason="run scripts/record_attack_cassettes.py to record LLM plans"
)


def _planned_probes() -> set[tuple[str, str]]:
    cassette = json.loads(CASSETTE.read_text(encoding="utf-8"))
    return {
        (probe["tool"], json.dumps(probe["arguments"], sort_keys=True))
        for entry in cassette.values()
        for probe in entry["response"]["probes"]
    }


def test_every_executed_probe_was_planned_by_the_model():
    from mcptrustmap.runtime.dvmcp import CHALLENGES

    planned = _planned_probes()
    assert planned, "cassette has no probes"

    for cid in CHALLENGES:
        frozen = OBS / f"dvmcp_{cid}.json"
        if not frozen.exists():
            continue
        observation = json.loads(frozen.read_text(encoding="utf-8"))
        for effect in observation["effects"]:
            key = (effect["tool"], json.dumps(effect["arguments"], sort_keys=True))
            assert key in planned, f"{cid}: executed {effect['tool']} probe was not in any LLM plan"
