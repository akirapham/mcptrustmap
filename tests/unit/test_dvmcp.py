"""DVMCP eval: replay a *real* challenge-9 run, plus adapter units.

dvmcp_challenge9.json was captured from the live Damn-Vulnerable-MCP-Server
challenge 9 (command injection in ping_host) driven by the LLM attacker. The
replay proves our oracle confirms RCE on a real third-party benchmark with no
DVMCP checkout or mcp extra — and that the finding is execution, not reflection.
"""

from __future__ import annotations

import json
from pathlib import Path

from mcptrustmap.runtime.dvmcp import CHALLENGES, scores, stdio_shim
from mcptrustmap.runtime.harness import pentest_server
from mcptrustmap.runtime.honey import mint_honey
from mcptrustmap.runtime.sandbox import FakeSandbox

FROZEN = (
    Path(__file__).resolve().parents[1] / "fixtures" / "observations" / "dvmcp_challenge9.json"
)


def test_challenge9_replay_proves_command_exec():
    ch = CHALLENGES["challenge9"]
    payload = json.loads(FROZEN.read_text(encoding="utf-8"))
    honey = mint_honey(ch.seed, declared_root="/honey")
    sandbox = FakeSandbox.from_dict(payload)
    findings = pentest_server("dvmcp:challenge9", sandbox, honey, ch.declared)

    ids = {f.finding_id for f in findings}
    assert ch.expect in ids  # ground truth: MTM-RT-COMMAND-EXEC
    assert all(f.provenance == "runtime-confirmed" for f in findings)


def test_challenge9_capture_shows_execution_not_reflection():
    payload = json.loads(FROZEN.read_text(encoding="utf-8"))
    honey = mint_honey("dvmcp9", declared_root="/honey")
    eff = payload["effects"][0]
    # the injected argument carries the UN-evaluated expression ...
    assert "$((" in eff["arguments"]["host"]
    # ... while the output carries its computed product: a shell ran it
    assert honey.exec_proof in eff["response"]
    assert honey.exec_proof not in eff["arguments"]["host"]


def test_scores_reports_detection():
    ch = CHALLENGES["challenge9"]
    assert scores(ch, {"MTM-RT-COMMAND-EXEC"})["detected"] is True
    assert scores(ch, {"MTM-RT-CONTEXT-LEAK"})["detected"] is False


def test_stdio_shim_imports_and_runs_the_challenge():
    command, args = stdio_shim("/x/challenges/hard/challenge9")
    assert args[0] == "-c"
    assert "server.mcp.run()" in args[1]
    assert "/x/challenges/hard/challenge9" in args[1]
