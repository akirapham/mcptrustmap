"""Authorization anti-pattern detectors (Phase 4).

Every rule is gated to the OAuth/proxy context it applies to — a server with no
OAuth produces zero authz findings (the MCP-spec MUSTs for redirect-URI/consent
apply to proxy/OAuth servers, and telemetry is scoped to scope-elevation).
"""

from __future__ import annotations

from ..findings import make_finding
from ..models import Finding, OAuthConfig, ServerRecord

# scope substrings that indicate broad/privileged access (scope creep)
_BROAD_SCOPE_MARKERS = ("admin", "write", "delete", "owner", "root", "*", ":org", "full")


def _is_broad_scope(scope: str) -> bool:
    s = scope.lower()
    return any(marker in s for marker in _BROAD_SCOPE_MARKERS)


def _is_lax_redirect(oauth: OAuthConfig) -> bool:
    if oauth.redirect_match in ("prefix", "wildcard"):
        return True
    return any("*" in uri for uri in oauth.redirect_uris)


def _ev(field: str, detail: str) -> list[dict[str, str]]:
    return [{"kind": "config_key", "ref": f"oauth/{field}", "detail": detail}]


def detect_authz_findings(server: ServerRecord) -> list[Finding]:
    oauth = server.oauth
    if oauth is None:
        return []  # not_applicable: no OAuth/proxy context

    sid = server.server_id
    findings: list[Finding] = []
    static_client = bool(oauth.client_id) and oauth.is_proxy
    lax_redirect = _is_lax_redirect(oauth)

    if oauth.forwards_token:
        findings.append(
            make_finding(
                "MTM-TOKEN-PASSTHROUGH",
                sid,
                _ev("forwards_token", "server forwards the incoming client token upstream"),
                confidence="high",
                provenance="deterministic",
            )
        )

    if lax_redirect:
        findings.append(
            make_finding(
                "MTM-LAX-REDIRECT-URI",
                sid,
                _ev(
                    "redirect_uris", f"redirect match: {oauth.redirect_match or 'wildcard pattern'}"
                ),
                confidence="high",
                provenance="deterministic",
            )
        )

    if static_client:
        findings.append(
            make_finding(
                "MTM-STATIC-CLIENT-ID",
                sid,
                _ev("client_id", f"static client id {oauth.client_id!r} shared on a proxy"),
                confidence="high",
                provenance="deterministic",
            )
        )

    if oauth.is_proxy and static_client and lax_redirect:
        findings.append(
            make_finding(
                "MTM-CONFUSED-DEPUTY",
                sid,
                _ev("client_id", "static client id + lax redirect without per-client consent"),
                confidence="high",
                provenance="deterministic",
            )
        )

    broad = sorted(s for s in oauth.scopes if _is_broad_scope(s))
    if broad:
        findings.append(
            make_finding(
                "MTM-SCOPE-CREEP",
                sid,
                _ev("scopes", f"broad scopes requested: {', '.join(broad)}"),
                confidence="medium",
                provenance="deterministic",
                title_suffix=", ".join(broad),
            )
        )

    if oauth.is_proxy and not oauth.raw.get("per_client_consent"):
        findings.append(
            make_finding(
                "MTM-MISSING-CONSENT",
                sid,
                _ev("is_proxy", "proxy authorizes without obtaining its own per-client consent"),
                confidence="medium",
                provenance="deterministic",
            )
        )

    if not oauth.raw.get("audit_log"):
        findings.append(
            make_finding(
                "MTM-MISSING-SCOPE-ELEVATION-LOG",
                sid,
                _ev(
                    "is_proxy" if oauth.is_proxy else "client_id",
                    "no audit log emitted on authorization/scope-elevation decisions",
                ),
                confidence="low",
                provenance="deterministic",
            )
        )

    return findings
