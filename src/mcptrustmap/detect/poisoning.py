"""Deterministic tool/schema poisoning detector (Phase 5, first-class)."""

from __future__ import annotations

from ..evidence.poisoning import poisoning_markers
from ..findings import make_finding
from ..models import Finding, ServerRecord


def detect_poisoning_findings(server: ServerRecord) -> list[Finding]:
    findings: list[Finding] = []
    for tool in server.tools:
        for sub_type, ref, detail in poisoning_markers(tool):
            findings.append(
                make_finding(
                    "MTM-TOOL-POISONING",
                    server.server_id,
                    [{"kind": "schema_path", "ref": ref, "detail": detail}],
                    confidence="high",
                    provenance="deterministic",
                    tool=tool.name,
                    sub_type=sub_type,
                    title_suffix=sub_type,
                )
            )
    return findings
