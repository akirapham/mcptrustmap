"""Inventory / shadow-server / supply-chain detectors (Phase 5, first-class).

Supply-chain rules are per-server; shadow and collision rules operate over the
whole configured set.
"""

from __future__ import annotations

from ..evidence.inventory import is_pinned, untrusted_source
from ..findings import make_finding
from ..models import Finding, ServerRecord


def detect_supply_chain_findings(server: ServerRecord) -> list[Finding]:
    findings: list[Finding] = []
    if server.package and not is_pinned(server.package):
        findings.append(
            make_finding(
                "MTM-UNPINNED-SERVER-PACKAGE",
                server.server_id,
                [
                    {
                        "kind": "config_key",
                        "ref": "launch/package",
                        "detail": f"unpinned package spec {server.package!r}",
                    }
                ],
                confidence="high",
                provenance="deterministic",
            )
        )
    reason = untrusted_source(server)
    if reason:
        findings.append(
            make_finding(
                "MTM-UNTRUSTED-SERVER-SOURCE",
                server.server_id,
                [{"kind": "config_key", "ref": "launch/source", "detail": reason}],
                confidence="medium",
                provenance="deterministic",
            )
        )
    return findings


def detect_shadow_findings(
    servers: list[ServerRecord], allowlist: set[str] | None
) -> list[Finding]:
    if allowlist is None:
        return []  # not_applicable: no operator allow-list provided
    findings: list[Finding] = []
    for server in servers:
        if server.server_id not in allowlist:
            findings.append(
                make_finding(
                    "MTM-SHADOW-SERVER",
                    server.server_id,
                    [
                        {
                            "kind": "config_key",
                            "ref": "inventory/allowlist",
                            "detail": f"{server.server_id!r} is not in the operator allow-list",
                        }
                    ],
                    confidence="high",
                    provenance="deterministic",
                )
            )
    return findings


def detect_collision_findings(servers: list[ServerRecord]) -> list[Finding]:
    by_tool: dict[str, set[str]] = {}
    for server in servers:
        for tool in server.tools:
            by_tool.setdefault(tool.name, set()).add(server.server_id)

    findings: list[Finding] = []
    for tool_name, sids in sorted(by_tool.items()):
        if len(sids) > 1:
            for sid in sorted(sids):
                others = ", ".join(sorted(sids - {sid}))
                findings.append(
                    make_finding(
                        "MTM-CROSS-ORIGIN-COLLISION",
                        sid,
                        [
                            {
                                "kind": "config_key",
                                "ref": f"tool/{tool_name}",
                                "detail": f"name {tool_name!r} also exposed by {others}",
                            }
                        ],
                        confidence="high",
                        provenance="deterministic",
                        tool=tool_name,
                    )
                )
    return findings
