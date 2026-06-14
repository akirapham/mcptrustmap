"""Seed OAuth/proxy config facts into the evidence graph (config_key anchors).

The authz detector reads `server.oauth` directly; these facts make the same
information re-resolvable for the gate when the LLM layer proposes authz findings.
"""

from __future__ import annotations

from ..models import ServerRecord
from .graph import Anchor, EvidenceFact, EvidenceGraph


def infer_oauth_facts(server: ServerRecord, graph: EvidenceGraph) -> None:
    o = server.oauth
    if o is None:
        return
    fields: list[tuple[str, object]] = [
        ("client_id", o.client_id),
        ("redirect_uris", o.redirect_uris),
        ("scopes", o.scopes),
        ("is_proxy", o.is_proxy),
        ("redirect_match", o.redirect_match),
        ("forwards_token", o.forwards_token),
    ]
    for field, value in fields:
        if value in (None, [], ""):
            continue
        graph.add(
            EvidenceFact(
                kind="oauth_field",
                anchor=Anchor("config_key", f"oauth/{field}"),
                detail=f"{field}={value!r}",
                extra={"field": field, "value": value},
            )
        )
