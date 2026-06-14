"""Prepare a server for analysis: assign roles + declared authority, seed the graph.

This is the deterministic enrichment step every audit runs first. It mutates the
ServerRecord's tools (roles, declared_authority) and returns an EvidenceGraph
seeded with the schema-side facts (`arg`, `annotation`). Source-derived facts
(`call`) and OAuth/inventory facts are layered on by later phases.
"""

from __future__ import annotations

from ..models import ServerRecord
from .authority import classify_declared_authority
from .graph import Anchor, EvidenceFact, EvidenceGraph
from .roles import assign_roles


def prepare_server(server: ServerRecord, graph: EvidenceGraph | None = None) -> EvidenceGraph:
    graph = graph if graph is not None else EvidenceGraph()
    for tool in server.tools:
        assign_roles(tool)
        tool.declared_authority = classify_declared_authority(tool)
        for arg in tool.arguments:
            graph.add(
                EvidenceFact(
                    kind="arg",
                    anchor=Anchor("schema_path", f"{tool.name}:{arg.schema_path}"),
                    detail=f"argument {arg.name!r} role={arg.role} constrained={arg.constrained}",
                    extra={
                        "tool": tool.name,
                        "arg": arg.name,
                        "role": arg.role,
                        "constrained": arg.constrained,
                    },
                )
            )
        for key, value in tool.annotations.items():
            graph.add(
                EvidenceFact(
                    kind="annotation",
                    anchor=Anchor("schema_path", f"{tool.name}:annotations/{key}"),
                    detail=f"{key}={value!r}",
                    extra={"tool": tool.name, "annotation": key, "value": value},
                )
            )
    return graph
