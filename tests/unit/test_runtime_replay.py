"""Runtime: replay a *frozen real* observation — deterministic CI proof, no mcp.

tests/fixtures/observations/controlled_vuln.json was captured from a live
LocalStdioSandbox run against the controlled vulnerable server (see
test_runtime_e2e). Replaying it through FakeSandbox proves the deterministic
oracles fire on genuine observed behavior with zero runtime dependencies — the
runtime analogue of cassette replay.
"""

from __future__ import annotations

import json
from pathlib import Path

from mcptrustmap.report import build_report, validate_report
from mcptrustmap.runtime.harness import pentest_server
from mcptrustmap.runtime.honey import mint_honey
from mcptrustmap.runtime.sandbox import FakeSandbox

FROZEN = (
    Path(__file__).resolve().parents[1] / "fixtures" / "observations" / "controlled_vuln.json"
)

# Mirrors classify_declared_authority on the frozen target's tools (static view).
_DECLARED = {
    "fetch": {"authority": {"read", "network", "credential_access"}, "read_only": False},
    "audit_log": {"authority": {"write"}, "read_only": True},
    "read_secret": {"authority": {"read", "credential_access"}, "read_only": False},
}


def _replay():
    payload = json.loads(FROZEN.read_text(encoding="utf-8"))
    honey = mint_honey("e2e", declared_root="/honey")
    sandbox = FakeSandbox.from_dict(payload)
    return pentest_server("frozen:vuln", sandbox, honey, _DECLARED)


def test_frozen_run_proves_three_families():
    findings = _replay()
    ids = {f.finding_id for f in findings}
    assert "MTM-RT-CREDENTIAL-EXFIL" in ids
    assert "MTM-RT-AUTHORITY-VIOLATION" in ids
    assert "MTM-RT-CONTEXT-LEAK" in ids
    assert all(f.provenance == "runtime-confirmed" for f in findings)


def test_frozen_run_builds_a_valid_report():
    findings = _replay()
    report = build_report("frozen:vuln", findings, servers=1, tools=3)
    validate_report(report)  # fail-closed: schema + semantic
    assert report["summary"]["by_provenance"].get("runtime-confirmed")
