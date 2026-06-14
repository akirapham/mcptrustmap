"""Runtime base: deterministic oracles turn observed behavior into MTM-RT proof."""

from __future__ import annotations

from mcptrustmap.runtime.honey import mint_honey
from mcptrustmap.runtime.observe import EgressEvent, Observation, ToolEffect
from mcptrustmap.runtime.oracles import run_oracles

HONEY = mint_honey("srv1", declared_root="/workspace", declared_hosts=("api.allowed.test",))
TOKEN_MARKER = next(iter(HONEY.tokens))
FILE_MARKER = next(iter(HONEY.files.values()))


def _ids(effects, declared):
    obs = Observation(effects=effects)
    return {f.finding_id for f in run_oracles("t:s", obs, HONEY, declared=declared)}


def test_authority_violation_readonly_mutates():
    eff = ToolEffect(tool="read_file", fs_deletes=["/workspace/x"])
    ids = _ids([eff], {"read_file": {"read_only": True, "authority": set()}})
    assert "MTM-RT-AUTHORITY-VIOLATION" in ids


def test_authority_violation_undeclared():
    eff = ToolEffect(tool="lookup", egress=[EgressEvent(host="api.allowed.test")])
    ids = _ids([eff], {"lookup": {"read_only": False, "authority": {"read"}}})
    assert "MTM-RT-AUTHORITY-VIOLATION" in ids  # network not declared


def test_credential_exfil():
    eff = ToolEffect(
        tool="sync", egress=[EgressEvent(host="evil.test", payload=f"x={TOKEN_MARKER}")]
    )
    ids = _ids([eff], {})
    assert "MTM-RT-CREDENTIAL-EXFIL" in ids
    assert "MTM-RT-UNEXPECTED-EGRESS" in ids  # evil.test not in declared_hosts


def test_context_leak():
    eff = ToolEffect(tool="dump", response=f"here is the secret {FILE_MARKER}")
    ids = _ids([eff], {})
    assert "MTM-RT-CONTEXT-LEAK" in ids


def test_command_exec_canary():
    eff = ToolEffect(tool="run", execs=[f"sh -c 'echo {HONEY.canary_marker}'"])
    ids = _ids([eff], {})
    assert "MTM-RT-COMMAND-EXEC" in ids


def test_path_escape():
    eff = ToolEffect(tool="read_file", fs_reads=["/etc/passwd"])
    ids = _ids([eff], {"read_file": {"read_only": True}})
    assert "MTM-RT-PATH-ESCAPE" in ids


def test_rug_pull():
    obs = Observation(tool_list_before=["a", "b"], tool_list_after=["a", "b", "evil"])
    ids = {f.finding_id for f in run_oracles("t:s", obs, HONEY, declared={})}
    assert ids == {"MTM-RT-RUG-PULL"}


def test_clean_behavior_no_findings():
    # reads within root, declares read authority, no egress/exec/exfil -> nothing fires
    eff = ToolEffect(tool="read_file", fs_reads=["/workspace/ok.txt"], response="contents")
    ids = _ids([eff], {"read_file": {"read_only": True, "authority": {"read", "filesystem"}}})
    assert ids == set()


def test_all_runtime_findings_are_runtime_confirmed():
    eff = ToolEffect(tool="run", fs_deletes=["/workspace/x"], execs=[HONEY.canary_marker])
    obs = Observation(effects=[eff])
    findings = run_oracles("t:s", obs, HONEY, declared={"run": {"read_only": True}})
    assert findings
    assert all(f.provenance == "runtime-confirmed" for f in findings)
    assert all(f.evidence and f.evidence[0]["kind"] == "runtime" for f in findings)
