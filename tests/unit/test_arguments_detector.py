"""Phase 2: argument + high-authority detectors fire correctly and stay quiet."""

from __future__ import annotations

from mcptrustmap.detect import detect_argument_findings
from mcptrustmap.evidence import prepare_server
from mcptrustmap.findings import REGISTRY, registry_rows
from mcptrustmap.ingest.manifest import parse_manifest
from mcptrustmap.models import ServerRecord


def _server(manifest_path, server_id="t:srv") -> ServerRecord:
    s = ServerRecord(server_id=server_id, client="generic", transport="stdio")
    s.tools = parse_manifest(manifest_path)
    prepare_server(s)
    return s


def test_vulnerable_manifest_findings(manifests_dir):
    server = _server(manifests_dir / "vulnerable.json")
    findings = detect_argument_findings(server)
    ids = sorted(f.finding_id for f in findings)

    assert "MTM-UNCONSTRAINED-COMMAND-ARG" in ids  # run_shell.command
    assert "MTM-CREDENTIAL-ARG-EXPOSED" in ids  # store_credential.api_key
    assert "MTM-HIGH-AUTHORITY-TOOL" in ids  # run_shell / store_credential

    # every finding is deterministic, high-confidence, with a resolvable anchor
    for f in findings:
        assert f.provenance == "deterministic"
        assert f.confidence == "high"
        assert f.evidence and all("ref" in e for e in f.evidence)
        assert f.owasp == REGISTRY[f.finding_id].owasp


def test_benign_manifest_no_findings(manifests_dir):
    server = _server(manifests_dir / "benign.json")
    findings = detect_argument_findings(server)
    assert findings == [], [f.finding_id for f in findings]


def test_path_arg_flagged(manifests_dir):
    server = _server(manifests_dir / "vulnerable.json")
    findings = detect_argument_findings(server)
    path_findings = [f for f in findings if f.finding_id == "MTM-UNCONSTRAINED-PATH-ARG"]
    assert path_findings  # read_file.path
    assert path_findings[0].tool == "read_file"


def test_registry_rows_complete():
    rows = registry_rows()
    assert len(rows) == len(REGISTRY)
    for row in rows:
        assert row["owasp"].startswith("MCP")
        assert row["severity"] in {"critical", "high", "medium", "low", "info"}
