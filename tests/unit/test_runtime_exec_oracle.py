"""Runtime: the computed-canary command-exec oracle distinguishes exec from reflection."""

from __future__ import annotations

from mcptrustmap.runtime.honey import mint_honey
from mcptrustmap.runtime.observe import Observation, ToolEffect
from mcptrustmap.runtime.oracles import run_oracles


def _ids(honey, effect):
    obs = Observation(effects=[effect])
    return {f.finding_id for f in run_oracles("s", obs, honey, declared={})}


def test_computed_product_in_output_proves_command_exec():
    honey = mint_honey("x")
    # the shell evaluated $((a*b)) -> the product (exec_proof) is in the output
    eff = ToolEffect(tool="ping", response=f"PING ...\n{honey.exec_proof}\n")
    assert "MTM-RT-COMMAND-EXEC" in _ids(honey, eff)


def test_reflected_payload_is_not_command_exec():
    honey = mint_honey("x")
    # the tool merely echoed the literal argument back: the un-evaluated expression
    # appears, but NOT its product — so it is reflection, not execution
    eff = ToolEffect(tool="echo", response=f"you said: {honey.exec_payload}")
    ids = _ids(honey, eff)
    assert "MTM-RT-COMMAND-EXEC" not in ids
    # and the literal payload is not a honey marker, so no context-leak either
    assert "MTM-RT-CONTEXT-LEAK" not in ids


def test_canary_in_execs_still_proves_command_exec():
    honey = mint_honey("x")
    eff = ToolEffect(tool="run", execs=[f"echo {honey.canary_marker}"])
    assert "MTM-RT-COMMAND-EXEC" in _ids(honey, eff)
