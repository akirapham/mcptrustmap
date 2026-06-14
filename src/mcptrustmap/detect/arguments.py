"""Argument-role and high-authority detectors (Phase 2).

Assumes the server has been prepared (roles assigned, declared authority set).
"""

from __future__ import annotations

from ..findings import make_finding
from ..models import Finding, ServerRecord
from ..policy import HIGH_AUTHORITY


def detect_argument_findings(server: ServerRecord) -> list[Finding]:
    findings: list[Finding] = []
    for tool in server.tools:
        for arg in tool.arguments:
            anchor_ref = f"{tool.name}:{arg.schema_path}"
            evidence = [
                {
                    "kind": "schema_path",
                    "ref": anchor_ref,
                    "detail": f"argument {arg.name!r} roled {arg.role}",
                }
            ]
            if arg.role == "command" and not arg.constrained:
                findings.append(
                    make_finding(
                        "MTM-UNCONSTRAINED-COMMAND-ARG",
                        server.server_id,
                        evidence,
                        confidence="high",
                        provenance="deterministic",
                        tool=tool.name,
                        argument=arg.name,
                    )
                )
            elif arg.role == "path" and not arg.constrained:
                findings.append(
                    make_finding(
                        "MTM-UNCONSTRAINED-PATH-ARG",
                        server.server_id,
                        evidence,
                        confidence="high",
                        provenance="deterministic",
                        tool=tool.name,
                        argument=arg.name,
                    )
                )
            if arg.role == "credential":
                findings.append(
                    make_finding(
                        "MTM-CREDENTIAL-ARG-EXPOSED",
                        server.server_id,
                        evidence,
                        confidence="high",
                        provenance="deterministic",
                        tool=tool.name,
                        argument=arg.name,
                    )
                )

        high = [c for c in tool.declared_authority if c in HIGH_AUTHORITY]
        if high:
            findings.append(
                make_finding(
                    "MTM-HIGH-AUTHORITY-TOOL",
                    server.server_id,
                    [
                        {
                            "kind": "schema_path",
                            "ref": f"{tool.name}:annotations",
                            "detail": f"declared authority: {', '.join(tool.declared_authority)}",
                        }
                    ],
                    confidence="high",
                    provenance="deterministic",
                    tool=tool.name,
                    title_suffix=", ".join(high),
                )
            )
    return findings
