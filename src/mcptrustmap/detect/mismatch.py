"""Declared-vs-actual authority mismatch (Phase 3) — the core novelty.

Compares a tool's *annotation* claims against its *source-inferred* authority:
  - readOnlyHint:true but the source mutates state  -> MTM-AUTHORITY-MISMATCH
  - undeclared mutation (no annotation/name says so) -> MTM-UNDECLARED-MUTATION

Deterministic when the inference is `ast` (Python). Cross-language inference is
LLM-reasoned and only reaches here gate-verified (Phase 7).
"""

from __future__ import annotations

from ..findings import make_finding
from ..models import Finding, ServerRecord, ToolRecord
from ..policy import MUTATING_AUTHORITY


def _mutating(tool: ToolRecord) -> list:
    return [ia for ia in tool.inferred_authority if ia.authority in MUTATING_AUTHORITY]


def _confidence(mutating: list) -> str:
    # ast evidence is line-accurate -> high; llm-only would be gate-verified
    return "high" if all(ia.sub_source == "ast" for ia in mutating) else "medium"


def _source_evidence(mutating: list) -> list[dict[str, str]]:
    return [
        {"kind": "file_line", "ref": ia.anchor, "detail": f"{ia.detail} -> {ia.authority}"}
        for ia in mutating
    ]


def detect_mismatch_findings(server: ServerRecord) -> list[Finding]:
    findings: list[Finding] = []
    for tool in server.tools:
        mutating = _mutating(tool)
        if not mutating:
            continue

        declared_readonly = tool.annotations.get("readOnlyHint") is True
        declared_destructive = tool.annotations.get("destructiveHint") is True
        declared_has_mutating = any(c in MUTATING_AUTHORITY for c in tool.declared_authority)
        classes = sorted({ia.authority for ia in mutating})
        confidence = _confidence(mutating)
        provenance = "deterministic" if confidence == "high" else "llm-verified"

        if declared_readonly:
            evidence = [
                {
                    "kind": "schema_path",
                    "ref": f"{tool.name}:annotations/readOnlyHint",
                    "detail": "declared readOnlyHint=true",
                },
                *_source_evidence(mutating),
            ]
            findings.append(
                make_finding(
                    "MTM-AUTHORITY-MISMATCH",
                    server.server_id,
                    evidence,
                    confidence=confidence,
                    provenance=provenance,
                    tool=tool.name,
                    title_suffix=f"declared read-only, source performs {', '.join(classes)}",
                )
            )
        elif not declared_destructive and not declared_has_mutating:
            findings.append(
                make_finding(
                    "MTM-UNDECLARED-MUTATION",
                    server.server_id,
                    _source_evidence(mutating),
                    confidence=confidence,
                    provenance=provenance,
                    tool=tool.name,
                    title_suffix=", ".join(classes),
                )
            )
    return findings
