"""The runtime pentest loop: sandbox -> observe -> oracles -> validated report.

`declared` is the static surface-mapper's view of each tool's claimed authority
(tool -> {"authority": set[str], "read_only": bool}); the oracles confirm when
runtime behavior exceeds it. Swapping FakeSandbox for DockerSandbox is the only
change between the deterministic test loop and the real pentest.
"""

from __future__ import annotations

from typing import Any

from ..audit import dedupe
from ..models import Finding, ToolRecord
from ..report import build_report, validate_report
from .honey import HoneySet
from .oracles import run_oracles
from .sandbox import Sandbox


def declared_from_tools(tools: list[ToolRecord]) -> dict[str, dict[str, Any]]:
    """The static surface-mapper's view, in the shape the oracles compare against.

    Each tool -> {authority: set[str], read_only: bool}: what it *claims* it can
    do (declared authority classes + the readOnlyHint annotation). The runtime
    oracles flag when observed behavior exceeds this.
    """
    from ..evidence.authority import classify_declared_authority

    return {
        tool.name: {
            "authority": set(classify_declared_authority(tool)),
            "read_only": tool.annotations.get("readOnlyHint") is True,
        }
        for tool in tools
    }


def pentest_server(
    server_id: str, sandbox: Sandbox, honey: HoneySet, declared: dict
) -> list[Finding]:
    observation = sandbox.run()
    return dedupe(run_oracles(server_id, observation, honey, declared=declared))


def pentest_to_report(
    server_id: str, sandbox: Sandbox, honey: HoneySet, declared: dict, *, tools: int = 0
) -> dict[str, Any]:
    findings = pentest_server(server_id, sandbox, honey, declared)
    report = build_report(server_id, findings, servers=1, tools=tools)
    validate_report(report)
    return report
