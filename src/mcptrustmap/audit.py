"""Audit orchestrator: ingest -> evidence -> deterministic detectors -> report.

The LLM reasoning layer + verification gate are layered in by later phases; this
module already produces the full deterministic report, which alone satisfies the
acceptance matrix (the tool degrades safely under --no-reason).
"""

from __future__ import annotations

from .detect import (
    detect_argument_findings,
    detect_authz_findings,
    detect_mismatch_findings,
    detect_oversharing_findings,
    detect_poisoning_findings,
    detect_shadow_findings,
    detect_supply_chain_findings,
)
from .evidence import EvidenceGraph, prepare_server
from .evidence.oauth import infer_oauth_facts
from .evidence.source import infer_source_authority
from .jsonio import load_yaml
from .models import Finding, ServerRecord
from .report import build_report, validate_report

# findings an operator can acknowledge away by asserting a tool's intended authority
_ACKNOWLEDGEABLE = frozenset({"MTM-AUTHORITY-MISMATCH", "MTM-UNDECLARED-MUTATION"})


def load_operator_policy(path: str) -> dict:
    data = load_yaml(path)
    return data if isinstance(data, dict) else {}


def apply_operator_policy(findings: list[Finding], policy: dict | None) -> list[Finding]:
    """Drop mismatch findings for tools whose authority the operator acknowledged."""
    acknowledge = (policy or {}).get("acknowledge", {})
    if not acknowledge:
        return findings
    return [f for f in findings if not (f.finding_id in _ACKNOWLEDGEABLE and f.tool in acknowledge)]


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str, str]] = set()
    out: list[Finding] = []
    for f in findings:
        if f.dedup_key in seen:
            continue
        seen.add(f.dedup_key)
        out.append(f)
    return out


def audit_server(
    server: ServerRecord,
    *,
    allowlist: set[str] | None = None,
    graph: EvidenceGraph | None = None,
) -> tuple[list[Finding], EvidenceGraph]:
    """Run the deterministic evidence + detector pipeline for one server."""
    graph = prepare_server(server, graph)
    infer_source_authority(server, graph)
    infer_oauth_facts(server, graph)

    findings: list[Finding] = []
    findings += detect_argument_findings(server)
    findings += detect_mismatch_findings(server)
    findings += detect_authz_findings(server)
    findings += detect_oversharing_findings(server)
    findings += detect_poisoning_findings(server)
    findings += detect_supply_chain_findings(server)
    if allowlist is not None:
        findings += detect_shadow_findings([server], allowlist)

    return dedupe(findings), graph


def audit_to_report(
    server: ServerRecord,
    *,
    allowlist: set[str] | None = None,
    reason: bool = False,
    llm_mode: str = "replay",
    policy: dict | None = None,
) -> dict:
    """Audit a single server and return a validated report.

    `reason`/`llm_mode` select the Claude reasoning layer + gate; `policy` is an
    optional operator authority-assertion that acknowledges intended authority.
    """
    findings, graph = audit_server(server, allowlist=allowlist)

    cassette_set: str | None = None
    if reason:
        from .reasoning import run_reasoning_layer

        llm_findings, cassette_set = run_reasoning_layer(server, graph, llm_mode=llm_mode)
        findings = dedupe([*findings, *llm_findings])

    findings = apply_operator_policy(findings, policy)

    report = build_report(
        server.server_id,
        findings,
        servers=1,
        tools=len(server.tools),
        cassette_set=cassette_set,
    )
    validate_report(report)
    return report
