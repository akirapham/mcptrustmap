"""Phase 4: authorization anti-pattern detectors (gated to OAuth context)."""

from __future__ import annotations

from mcptrustmap.detect import detect_authz_findings
from mcptrustmap.ingest.discovery import discover
from mcptrustmap.models import OAuthConfig, ServerRecord


def test_vulnerable_proxy_trips_authz_rules(configs_dir):
    proxy = next(r for r in discover("cursor", configs_dir) if r.server_id == "cursor:github-proxy")
    ids = {f.finding_id for f in detect_authz_findings(proxy)}
    assert {
        "MTM-TOKEN-PASSTHROUGH",
        "MTM-LAX-REDIRECT-URI",
        "MTM-STATIC-CLIENT-ID",
        "MTM-CONFUSED-DEPUTY",
        "MTM-SCOPE-CREEP",
        "MTM-MISSING-CONSENT",
        "MTM-MISSING-SCOPE-ELEVATION-LOG",
    } <= ids
    # spec_ref present where the registry defines it
    by_id = {f.finding_id: f for f in detect_authz_findings(proxy)}
    assert by_id["MTM-TOKEN-PASSTHROUGH"].spec_ref
    assert by_id["MTM-LAX-REDIRECT-URI"].spec_ref


def test_no_oauth_yields_zero_authz_findings():
    server = ServerRecord(server_id="plain:srv", client="generic", transport="stdio")
    assert detect_authz_findings(server) == []  # not_applicable, never a false finding


def test_well_configured_oauth_is_clean():
    oauth = OAuthConfig(
        client_id="per-client-registered",
        redirect_uris=["https://app.example.com/callback"],
        scopes=["read:user"],
        is_proxy=False,
        redirect_match="exact",
        forwards_token=False,
        raw={"per_client_consent": True, "audit_log": True},
    )
    server = ServerRecord(server_id="good:srv", client="cursor", transport="sse", oauth=oauth)
    assert detect_authz_findings(server) == []
