"""Phase 4: context over-sharing detectors."""

from __future__ import annotations

from mcptrustmap.detect import detect_oversharing_findings
from mcptrustmap.models import ServerRecord


def _server(resources) -> ServerRecord:
    return ServerRecord(server_id="t:s", client="generic", transport="stdio", resources=resources)


def test_unscoped_resource():
    server = _server([{"name": "files", "uri": "file:///"}])
    ids = {f.finding_id for f in detect_oversharing_findings(server)}
    assert "MTM-UNSCOPED-RESOURCE" in ids


def test_context_oversharing_broad_description():
    server = _server(
        [
            {
                "name": "dump",
                "uri": "db://x",
                "description": "Returns the entire database for all tenants",
            }
        ]
    )
    ids = {f.finding_id for f in detect_oversharing_findings(server)}
    assert "MTM-CONTEXT-OVERSHARING" in ids


def test_scoped_resource_is_clean():
    server = _server([{"name": "r", "uri": "file:///x", "scope": "session"}])
    assert detect_oversharing_findings(server) == []


def test_scoped_description_is_clean():
    server = _server([{"name": "r", "uri": "db://x/123", "description": "a single scoped record"}])
    assert detect_oversharing_findings(server) == []
