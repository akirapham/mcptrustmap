"""Context over-sharing detectors (Phase 4): resources exposed without scoping."""

from __future__ import annotations

from ..findings import make_finding
from ..models import Finding, ServerRecord

_SCOPING_KEYS = frozenset(
    {"scope", "session", "tenant", "tenant_id", "session_id", "access", "acl"}
)
_SCOPING_PHRASES = ("per-session", "per-tenant", "scoped", "session-scoped", "tenant-scoped")
_BROAD_TOKENS = (
    "all ",
    "entire",
    "whole",
    "everything",
    "env",
    "environment",
    "secrets",
    "full database",
    "every row",
)


def _is_scoped(resource: dict) -> bool:
    if any(key in resource for key in _SCOPING_KEYS):
        return True
    desc = str(resource.get("description", "")).lower()
    return any(phrase in desc for phrase in _SCOPING_PHRASES)


def _broad_uri(uri: str) -> bool:
    return "*" in uri or uri.endswith("/**") or uri in ("/", "~", "file://", "file:///")


def detect_oversharing_findings(server: ServerRecord) -> list[Finding]:
    findings: list[Finding] = []
    for resource in server.resources:
        name = resource.get("name") or resource.get("uri") or "<resource>"
        uri = str(resource.get("uri", ""))
        desc = str(resource.get("description", "")).lower()
        if _is_scoped(resource):
            continue
        broad_desc = any(tok in desc for tok in _BROAD_TOKENS)
        broad_uri = _broad_uri(uri)
        if broad_desc:
            findings.append(
                make_finding(
                    "MTM-CONTEXT-OVERSHARING",
                    server.server_id,
                    [
                        {
                            "kind": "config_key",
                            "ref": f"resource/{name}",
                            "detail": f"broad context: {desc[:60]}",
                        }
                    ],
                    confidence="medium",
                    provenance="deterministic",
                )
            )
        elif broad_uri:
            findings.append(
                make_finding(
                    "MTM-UNSCOPED-RESOURCE",
                    server.server_id,
                    [
                        {
                            "kind": "config_key",
                            "ref": f"resource/{name}",
                            "detail": f"unscoped uri: {uri}",
                        }
                    ],
                    confidence="medium",
                    provenance="deterministic",
                )
            )
    return findings
