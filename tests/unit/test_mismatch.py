"""Phase 3: declared-vs-actual mismatch detector."""

from __future__ import annotations

from mcptrustmap.detect import detect_mismatch_findings
from mcptrustmap.evidence import prepare_server
from mcptrustmap.evidence.source import infer_source_authority
from mcptrustmap.ingest.manifest import parse_manifest
from mcptrustmap.models import ServerRecord


def _prep(manifest_path, source_path, sid="t:s") -> ServerRecord:
    s = ServerRecord(
        server_id=sid, client="generic", transport="stdio", source_path=str(source_path)
    )
    s.tools = parse_manifest(manifest_path)
    graph = prepare_server(s)
    infer_source_authority(s, graph)
    return s


def test_vulnerable_mismatches(examples):
    server = _prep(
        examples / "manifests" / "vulnerable.json",
        examples / "servers" / "vulnerable-mcp",
    )
    findings = {f.tool: f for f in detect_mismatch_findings(server)}

    assert findings["read_file"].finding_id == "MTM-AUTHORITY-MISMATCH"  # readOnly + os.remove
    assert findings["store_credential"].finding_id == "MTM-UNDECLARED-MUTATION"  # hidden write
    assert "run_shell" not in findings  # command_exec declared by name -> honest
    assert "echo" not in findings  # faithfully read-only

    mm = findings["read_file"]
    assert mm.provenance == "deterministic"
    assert mm.confidence == "high"
    # at least one evidence ref points at the actual source line
    assert any(e["kind"] == "file_line" and ":" in e["ref"] for e in mm.evidence)


def test_benign_server_no_mismatch(examples):
    server = _prep(
        examples / "servers" / "benign-mcp" / "manifest.json",
        examples / "servers" / "benign-mcp",
    )
    assert detect_mismatch_findings(server) == []
