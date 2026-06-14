"""Phase 5: deterministic tool/schema poisoning detector."""

from __future__ import annotations

from mcptrustmap.detect import detect_poisoning_findings
from mcptrustmap.evidence import prepare_server
from mcptrustmap.ingest.manifest import parse_manifest
from mcptrustmap.models import ServerRecord


def _server(manifest_path) -> ServerRecord:
    s = ServerRecord(server_id="t:s", client="generic", transport="stdio")
    s.tools = parse_manifest(manifest_path)
    prepare_server(s)
    return s


def test_poisoned_manifest_subtypes(manifests_dir):
    findings = detect_poisoning_findings(_server(manifests_dir / "poisoned.json"))
    pairs = {(f.tool, f.sub_type) for f in findings}
    assert ("search", "hidden-instruction") in pairs
    assert ("fetch_notes", "unicode-obfuscation") in pairs
    assert ("official_helper", "name-spoofing") in pairs
    for f in findings:
        assert f.finding_id == "MTM-TOOL-POISONING"
        assert f.confidence == "high"
        assert f.provenance == "deterministic"


def test_benign_manifest_no_poisoning(manifests_dir):
    # imperative-but-legit descriptions must not trip the hidden-instruction rule
    findings = detect_poisoning_findings(_server(manifests_dir / "benign.json"))
    assert findings == []


def test_vulnerable_manifest_no_poisoning_false_positive(manifests_dir):
    findings = detect_poisoning_findings(_server(manifests_dir / "vulnerable.json"))
    assert findings == []
