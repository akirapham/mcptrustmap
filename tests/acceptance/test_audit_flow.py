"""Phase 8: end-to-end audit orchestration + CLI (deterministic core)."""

from __future__ import annotations

from mcptrustmap.audit import audit_to_report
from mcptrustmap.cli import main
from mcptrustmap.ingest.manifest import parse_manifest
from mcptrustmap.models import ServerRecord
from mcptrustmap.report import validate_report


def _vuln_server(examples) -> ServerRecord:
    s = ServerRecord(
        server_id="manifest:vulnerable",
        client="generic",
        transport="stdio",
        source_path=str(examples / "servers" / "vulnerable-mcp"),
    )
    s.tools = parse_manifest(examples / "manifests" / "vulnerable.json")
    return s


def test_audit_vulnerable_report(examples):
    report = audit_to_report(_vuln_server(examples))
    validate_report(report)
    ids = {f["finding_id"] for f in report["findings"]}
    assert {
        "MTM-AUTHORITY-MISMATCH",
        "MTM-UNCONSTRAINED-COMMAND-ARG",
        "MTM-UNCONSTRAINED-PATH-ARG",
        "MTM-CREDENTIAL-ARG-EXPOSED",
        "MTM-UNDECLARED-MUTATION",
        "MTM-HIGH-AUTHORITY-TOOL",
    } <= ids
    by_prov = report["summary"]["by_provenance"]
    assert by_prov.get("deterministic", 0) == report["summary"]["total_findings"]


def test_audit_benign_is_clean(examples):
    s = ServerRecord(server_id="manifest:benign", client="generic", transport="stdio")
    s.tools = parse_manifest(examples / "manifests" / "benign.json")
    report = audit_to_report(s)
    validate_report(report)
    assert report["summary"]["total_findings"] == 0


def test_reason_flag_is_safe_until_llm_layer(examples):
    report = audit_to_report(_vuln_server(examples), reason=True)
    validate_report(report)
    assert report["reproducibility"]["cassette_set"] is None


def test_cli_audit_end_to_end(examples, tmp_path):
    out = tmp_path / "report.json"
    rc = main(
        [
            "audit",
            "--manifest",
            str(examples / "manifests" / "vulnerable.json"),
            "--source",
            str(examples / "servers" / "vulnerable-mcp"),
            "--out",
            str(out),
        ]
    )
    assert rc == 0
    assert out.exists()
    assert main(["report", "validate", str(out)]) == 0

    sarif_out = tmp_path / "report.sarif"
    assert main(["report", "render", str(out), "--format", "sarif", "--out", str(sarif_out)]) == 0
    assert sarif_out.exists()

    md_out = tmp_path / "report.md"
    assert main(["report", "render", str(out), "--format", "md", "--out", str(md_out)]) == 0
    assert "MTM-AUTHORITY-MISMATCH" in md_out.read_text()


def test_cli_fail_on(examples, tmp_path):
    rc = main(
        [
            "audit",
            "--manifest",
            str(examples / "manifests" / "vulnerable.json"),
            "--source",
            str(examples / "servers" / "vulnerable-mcp"),
            "--fail-on",
            "high",
            "--out",
            str(tmp_path / "r.json"),
        ]
    )
    assert rc == 1  # vulnerable server has high-severity findings

    rc_clean = main(
        [
            "audit",
            "--manifest",
            str(examples / "manifests" / "benign.json"),
            "--fail-on",
            "high",
            "--out",
            str(tmp_path / "r2.json"),
        ]
    )
    assert rc_clean == 0
