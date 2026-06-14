"""Runtime end-to-end: drive a real stdio MCP server and prove observed findings.

Guarded by the `mcp` extra. Exercises the whole pipeline against a controlled
vulnerable target — honey seed -> LocalStdioSandbox (real subprocess) -> MCP
driver -> fs-diff + egress sink -> deterministic oracles — and asserts three
distinct families fire from observed behavior, not opinion.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytest.importorskip("mcp")

from mcptrustmap.agent.llm_client import LLMClient  # noqa: E402
from mcptrustmap.runtime.attacker import LLMAttacker  # noqa: E402
from mcptrustmap.runtime.docker import seed_honey_dir  # noqa: E402
from mcptrustmap.runtime.harness import pentest_server  # noqa: E402
from mcptrustmap.runtime.honey import mint_honey  # noqa: E402
from mcptrustmap.runtime.sandbox import LocalStdioSandbox  # noqa: E402

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "vuln_mcp_server.py"

# Mirrors classify_declared_authority on the fixture's tools (the static view).
_DECLARED = {
    "fetch": {"authority": {"read", "network", "credential_access"}, "read_only": False},
    "audit_log": {"authority": {"write"}, "read_only": True},
    "read_secret": {"authority": {"read", "credential_access"}, "read_only": False},
}


def test_local_stdio_e2e_proves_three_oracle_families(tmp_path):
    # Logical declared root ("/honey") is decoupled from the physical honey dir,
    # so observed paths are portable (the same shape a container run produces).
    honey = mint_honey("e2e", declared_root="/honey")
    seed_honey_dir(tmp_path, declared_root="/honey", files=honey.files)

    sandbox = LocalStdioSandbox(sys.executable, [str(FIXTURE)], honey, honey_dir=str(tmp_path))
    findings = pentest_server("local:vuln", sandbox, honey, _DECLARED)

    ids = {f.finding_id for f in findings}
    assert "MTM-RT-CREDENTIAL-EXFIL" in ids  # honeytoken reached the sink
    assert "MTM-RT-AUTHORITY-VIOLATION" in ids  # readOnlyHint tool wrote a file
    assert "MTM-RT-CONTEXT-LEAK" in ids  # honeyfile marker returned in output
    assert all(f.provenance == "runtime-confirmed" for f in findings)


def _attack_responder(request, context):
    """A scripted 'LLM' that weaponizes the arsenal — proves the attacker path."""
    arsenal = request["arsenal"]
    token = arsenal["honey_secrets"][0]
    return {
        "probes": [
            {"tool": "fetch", "arguments": {"url": arsenal["sink_url"], "api_key": token}},
            {"tool": "audit_log", "arguments": {"note": arsenal["honey_markers"][0]}},
            {"tool": "read_secret", "arguments": {}},
        ]
    }


def test_llm_attacker_drives_the_same_findings(tmp_path):
    # The verdict stays deterministic; only the *probes* come from the (scripted) LLM.
    honey = mint_honey("e2e", declared_root="/honey")
    seed_honey_dir(tmp_path, declared_root="/honey", files=honey.files)

    attacker = LLMAttacker(LLMClient.record(_attack_responder))
    sandbox = LocalStdioSandbox(
        sys.executable, [str(FIXTURE)], honey, honey_dir=str(tmp_path), attacker=attacker
    )
    findings = pentest_server("local:vuln-llm", sandbox, honey, _DECLARED)

    ids = {f.finding_id for f in findings}
    assert {"MTM-RT-CREDENTIAL-EXFIL", "MTM-RT-AUTHORITY-VIOLATION", "MTM-RT-CONTEXT-LEAK"} <= ids
