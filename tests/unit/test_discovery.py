"""Phase 1: multi-client config inventory into validated ServerRecord[]."""

from __future__ import annotations

import json

import pytest

from mcptrustmap.errors import InputError
from mcptrustmap.ingest.discovery import detect_package, discover
from mcptrustmap.jsonio import validate


def test_discover_all_clients(configs_dir):
    records = {r.server_id: r for r in discover("all", configs_dir)}
    assert set(records) == {
        "claude_desktop:files",
        "claude_desktop:weather",
        "cursor:github-proxy",
        "windsurf:notes",
        "vscode_cline:db",
        "generic:shadow",
    }
    # output round-trips through the schema
    validate([r.to_dict() for r in records.values()], "server_record")


def test_transport_and_package_detection(configs_dir):
    records = {r.server_id: r for r in discover("all", configs_dir)}
    assert records["claude_desktop:files"].transport == "stdio"
    assert records["claude_desktop:files"].source_path == "examples/servers/vulnerable-mcp"
    assert records["claude_desktop:weather"].package == "@acme/weather-mcp"  # unpinned npx
    assert records["windsurf:notes"].package == "notes-mcp==1.2.3"  # pinned uvx
    assert records["cursor:github-proxy"].transport == "sse"


def test_oauth_passthrough(configs_dir):
    proxy = next(r for r in discover("cursor", configs_dir) if r.server_id == "cursor:github-proxy")
    assert proxy.oauth is not None
    assert proxy.oauth.is_proxy is True
    assert proxy.oauth.forwards_token is True
    assert proxy.oauth.redirect_match == "wildcard"
    assert "admin:org" in proxy.oauth.scopes


def test_single_client_filter(configs_dir):
    records = discover("windsurf", configs_dir)
    assert {r.server_id for r in records} == {"windsurf:notes"}


def test_unknown_client_fails_closed(configs_dir):
    with pytest.raises(InputError):
        discover("emacs", configs_dir)


def test_missing_mcpservers_fails_closed(tmp_path):
    cfg = tmp_path / "generic_mcp.json"
    cfg.write_text(json.dumps({"servers": {}}))
    with pytest.raises(InputError):
        discover("generic", tmp_path)


def test_detect_package_variants():
    assert detect_package("npx", ["-y", "@acme/pkg"]) == "@acme/pkg"
    assert detect_package("uvx", ["pkg==1.0"]) == "pkg==1.0"
    assert detect_package("uv", ["tool", "run", "thing"]) == "thing"
    assert detect_package("python", ["server.py"]) is None
    assert detect_package(None, []) is None
