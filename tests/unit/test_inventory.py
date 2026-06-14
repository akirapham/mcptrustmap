"""Phase 5: inventory, shadow-server, supply-chain detectors."""

from __future__ import annotations

from mcptrustmap.detect import (
    detect_collision_findings,
    detect_shadow_findings,
    detect_supply_chain_findings,
)
from mcptrustmap.evidence.inventory import is_pinned, load_allowlist, untrusted_source
from mcptrustmap.ingest.discovery import discover
from mcptrustmap.models import ServerRecord, ToolRecord


def test_unpinned_vs_pinned_package(configs_dir):
    servers = {r.server_id: r for r in discover("all", configs_dir)}
    weather = detect_supply_chain_findings(servers["claude_desktop:weather"])
    assert {f.finding_id for f in weather} == {"MTM-UNPINNED-SERVER-PACKAGE"}
    assert detect_supply_chain_findings(servers["windsurf:notes"]) == []  # pinned ==1.2.3


def test_is_pinned():
    assert is_pinned("notes-mcp==1.2.3")
    assert is_pinned("@scope/pkg@1.2.3")
    assert not is_pinned("@acme/weather-mcp")


def test_untrusted_source():
    server = ServerRecord(
        server_id="x:y",
        client="generic",
        transport="stdio",
        package="git+https://github.com/a/b",
    )
    assert untrusted_source(server)


def test_shadow_server(configs_dir, examples):
    servers = discover("all", configs_dir)
    allow = load_allowlist(examples / "allowlists" / "ops.yml")
    flagged = {f.server_id for f in detect_shadow_findings(servers, allow)}
    assert "generic:shadow" in flagged
    assert "claude_desktop:files" not in flagged
    # no allow-list => not_applicable, never a false finding
    assert detect_shadow_findings(servers, None) == []


def test_cross_origin_collision():
    a = ServerRecord(
        server_id="s:a", client="generic", transport="stdio", tools=[ToolRecord(name="read")]
    )
    b = ServerRecord(
        server_id="s:b", client="generic", transport="stdio", tools=[ToolRecord(name="read")]
    )
    c = ServerRecord(
        server_id="s:c", client="generic", transport="stdio", tools=[ToolRecord(name="unique")]
    )
    findings = detect_collision_findings([a, b, c])
    assert {f.server_id for f in findings} == {"s:a", "s:b"}
    assert all(f.finding_id == "MTM-CROSS-ORIGIN-COLLISION" for f in findings)
