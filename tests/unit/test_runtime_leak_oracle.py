"""Runtime: context-leak fires on seeded leakage, NOT on reflected attacker input.

Regression for a false positive found via live LLM testing: a model searched for a
honey *marker* as a keyword and the tool echoed it back ("no files containing 'X'");
the reflected marker must not count as a leak.
"""

from __future__ import annotations

from mcptrustmap.runtime.honey import mint_honey
from mcptrustmap.runtime.observe import Observation, ToolEffect
from mcptrustmap.runtime.oracles import run_oracles


def _ids(honey, effect):
    findings = run_oracles("s", Observation(effects=[effect]), honey, declared={})
    return {f.finding_id for f in findings}


def test_reflected_marker_in_args_is_not_a_leak():
    honey = mint_honey("x")
    marker = honey.canary_marker
    # the attacker put the marker in the args; the tool just echoed it back
    eff = ToolEffect(
        tool="search",
        arguments={"keyword": marker},
        response=f"No files found containing '{marker}'.",
    )
    assert "MTM-RT-CONTEXT-LEAK" not in _ids(honey, eff)


def test_seeded_marker_not_in_args_is_a_leak():
    honey = mint_honey("x")
    file_marker = next(iter(honey.files.values()))
    # the tool returned a seeded honeyfile marker the attacker never supplied
    eff = ToolEffect(tool="read_secret", arguments={}, response=f"contents: {file_marker}")
    assert "MTM-RT-CONTEXT-LEAK" in _ids(honey, eff)
