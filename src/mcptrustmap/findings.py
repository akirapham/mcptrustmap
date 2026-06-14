"""The finding-ID registry — the single source of truth.

Each id maps to its OWASP MCP item (beta), default severity, spec reference,
title, and recommendation. Detectors never invent ids or severities; they call
`make_finding`, which stamps the registry metadata onto a Finding.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .errors import RegistryError
from .models import Finding


@dataclass(frozen=True)
class FindingSpec:
    owasp: str
    severity: str
    title: str
    recommendation: str
    spec_ref: str | None = None


# fmt: off
REGISTRY: dict[str, FindingSpec] = {
    # --- authority taxonomy ---
    "MTM-HIGH-AUTHORITY-TOOL": FindingSpec(
        "MCP02", "medium",
        "Tool declares high-authority capability",
        "Confirm the tool needs this authority; gate behind consent and least privilege.",
    ),
    "MTM-UNDECLARED-MUTATION": FindingSpec(
        "MCP03", "high",
        "Tool mutates state without declaring it",
        "Declare the destructive/write capability (annotations) or remove the mutation.",
    ),
    # --- argument roles ---
    "MTM-UNCONSTRAINED-COMMAND-ARG": FindingSpec(
        "MCP05", "high",
        "Command argument is unconstrained",
        "Constrain the argument with an enum/allow-list, or remove free-form command execution.",
    ),
    "MTM-UNCONSTRAINED-PATH-ARG": FindingSpec(
        "MCP05", "medium",
        "Path argument is unconstrained",
        "Confine paths to a root and validate against traversal; add a pattern/format constraint.",
    ),
    "MTM-CREDENTIAL-ARG-EXPOSED": FindingSpec(
        "MCP01", "high",
        "Credential accepted as a free-form tool argument",
        "Do not accept secrets as tool inputs; resolve credentials server-side from a vault.",
    ),
    # --- declared-vs-actual mismatch (core novelty) ---
    "MTM-AUTHORITY-MISMATCH": FindingSpec(
        "MCP07", "high",
        "Declared authority contradicts actual (source-inferred) authority",
        "Align the tool's annotations/declaration with what its implementation actually does.",
        spec_ref="tool annotations are untrusted (MCP spec, 2025-06-18)",
    ),
    # --- authorization anti-patterns ---
    "MTM-TOKEN-PASSTHROUGH": FindingSpec(
        "MCP01", "critical",
        "Server forwards the incoming client token upstream",
        "Mint a downstream token scoped to the server; never pass the client's token through.",
        spec_ref="MCP security best practices: token passthrough is forbidden",
    ),
    "MTM-CONFUSED-DEPUTY": FindingSpec(
        "MCP07", "high",
        "Confused-deputy: static client id + dynamic redirect without per-client consent",
        "Require per-client consent and exact redirect-URI matching for every registered client.",
        spec_ref="MCP security best practices: confused deputy",
    ),
    "MTM-SCOPE-CREEP": FindingSpec(
        "MCP02", "medium",
        "Requested OAuth scopes exceed what the exposed tools require",
        "Request the minimum scopes the tools need (scope minimization).",
        spec_ref="MCP security best practices: scope minimization",
    ),
    "MTM-MISSING-CONSENT": FindingSpec(
        "MCP07", "high",
        "Proxy forwards consent without obtaining its own per-client consent",
        "Obtain explicit per-client consent at the proxy before authorizing.",
        spec_ref="MCP security best practices: user consent",
    ),
    "MTM-LAX-REDIRECT-URI": FindingSpec(
        "MCP07", "high",
        "Redirect URI matched by prefix/wildcard rather than exact string",
        "Match redirect URIs by exact string comparison only.",
        spec_ref="MCP security best practices: exact redirect-URI match",
    ),
    "MTM-STATIC-CLIENT-ID": FindingSpec(
        "MCP07", "medium",
        "A single static client id is shared across clients",
        "Register a distinct client id per client/integration.",
    ),
    # --- audit/telemetry ---
    "MTM-MISSING-SCOPE-ELEVATION-LOG": FindingSpec(
        "MCP08", "low",
        "No audit log on a scope-elevation / authorization decision",
        "Emit a correlation-id-tagged audit record on each scope-elevation decision.",
        spec_ref="MCP security best practices: audit telemetry (scope-elevation)",
    ),
    # --- context over-sharing ---
    "MTM-CONTEXT-OVERSHARING": FindingSpec(
        "MCP10", "medium",
        "Tool/resource returns broad context without task/tenant scoping",
        "Scope returned context to the task and tenant; avoid returning whole files/dirs/rows.",
    ),
    "MTM-UNSCOPED-RESOURCE": FindingSpec(
        "MCP10", "medium",
        "Resource exposed without session/tenant scoping",
        "Scope resources to a session/tenant and enforce access control.",
    ),
    # --- tool/schema poisoning ---
    "MTM-TOOL-POISONING": FindingSpec(
        "MCP03", "high",
        "Tool description/schema shows poisoning markers",
        "Treat tool descriptions as untrusted; remove hidden instructions and obfuscation.",
    ),
    # --- inventory / shadow servers ---
    "MTM-SHADOW-SERVER": FindingSpec(
        "MCP09", "medium",
        "Configured server is not in the operator allow-list",
        "Add the server to the allow-list or remove it; investigate unexpected servers.",
    ),
    "MTM-CROSS-ORIGIN-COLLISION": FindingSpec(
        "MCP09", "medium",
        "Tools from different servers share a name (shadowing surface)",
        "Namespace tool names per server; investigate the colliding tools.",
    ),
    # --- supply chain ---
    "MTM-UNPINNED-SERVER-PACKAGE": FindingSpec(
        "MCP04", "low",
        "Server launched from an unpinned package spec",
        "Pin the package to an exact version (and hash where supported).",
    ),
    "MTM-UNTRUSTED-SERVER-SOURCE": FindingSpec(
        "MCP04", "medium",
        "Server launched from an untrusted/unverifiable source",
        "Install servers from a trusted registry; verify provenance before running.",
    ),
}
# fmt: on


def spec_for(finding_id: str) -> FindingSpec:
    try:
        return REGISTRY[finding_id]
    except KeyError as exc:
        raise RegistryError(f"unknown finding id: {finding_id!r}") from exc


def make_finding(
    finding_id: str,
    server_id: str,
    evidence: list[dict[str, Any]],
    *,
    confidence: str,
    provenance: str,
    tool: str | None = None,
    argument: str | None = None,
    status: str = "reproduced",
    sub_type: str | None = None,
    severity: str | None = None,
    title_suffix: str | None = None,
) -> Finding:
    """Build a Finding, stamping OWASP/severity/title/recommendation from the registry."""
    spec = spec_for(finding_id)
    title = spec.title if not title_suffix else f"{spec.title}: {title_suffix}"
    return Finding(
        finding_id=finding_id,
        severity=severity or spec.severity,
        owasp=spec.owasp,
        title=title,
        server_id=server_id,
        evidence=evidence,
        recommendation=spec.recommendation,
        confidence=confidence,
        provenance=provenance,
        status=status,
        spec_ref=spec.spec_ref,
        tool=tool,
        argument=argument,
        sub_type=sub_type,
    )


def registry_rows() -> list[dict[str, str]]:
    """Flat rows for `findings list`."""
    rows = []
    for fid, spec in sorted(REGISTRY.items()):
        rows.append(
            {
                "finding_id": fid,
                "owasp": spec.owasp,
                "severity": spec.severity,
                "title": spec.title,
                "spec_ref": spec.spec_ref or "",
            }
        )
    return rows
