"""Phases 6-7: the hybrid flow end-to-end via recorded cassettes."""

from __future__ import annotations

import pytest

from mcptrustmap.audit import audit_to_report
from mcptrustmap.errors import LlmReplayMiss
from mcptrustmap.ingest.manifest import parse_manifest
from mcptrustmap.models import ServerRecord
from mcptrustmap.report import validate_report


def _js_server(examples) -> ServerRecord:
    s = ServerRecord(
        server_id="manifest:js-vulnerable",
        client="generic",
        transport="stdio",
        source_path=str(examples / "servers" / "js-vulnerable"),
    )
    s.tools = parse_manifest(examples / "manifests" / "js-vulnerable.json")
    return s


def test_hybrid_llm_verified_mismatch(examples):
    report = audit_to_report(_js_server(examples), reason=True, llm_mode="replay")
    validate_report(report)

    mismatches = [f for f in report["findings"] if f["finding_id"] == "MTM-AUTHORITY-MISMATCH"]
    assert len(mismatches) == 1, "only read_file survives; echo + hallucination are dropped"
    f = mismatches[0]
    assert f["provenance"] == "llm-verified"
    assert f["tool"] == "read_file"
    assert any(e["ref"].startswith("server.js:") for e in f["evidence"])
    assert report["summary"]["by_provenance"].get("llm-verified") == 1
    assert report["reproducibility"]["cassette_set"]


def test_replay_miss_fails_loud(examples, tmp_path, monkeypatch):
    # point the cassette dir at an empty directory: the reason request misses
    monkeypatch.setenv("MTM_CASSETTE_DIR", str(tmp_path))
    with pytest.raises(LlmReplayMiss):
        audit_to_report(_js_server(examples), reason=True, llm_mode="replay")


def test_sourceless_server_skips_llm_layer(examples):
    s = ServerRecord(server_id="manifest:benign", client="generic", transport="stdio")
    s.tools = parse_manifest(examples / "manifests" / "benign.json")
    report = audit_to_report(s, reason=True, llm_mode="replay")
    validate_report(report)
    assert report["reproducibility"]["cassette_set"] is None  # nothing to reason over
