"""Phase 8: report build / validate (fail-closed) / render JSON-MD-SARIF."""

from __future__ import annotations

import pytest

from mcptrustmap.errors import SchemaValidationError
from mcptrustmap.findings import make_finding
from mcptrustmap.jsonio import validate
from mcptrustmap.report import build_report, render_markdown, render_sarif, validate_report


def _finding():
    return make_finding(
        "MTM-UNCONSTRAINED-COMMAND-ARG",
        "t:s",
        [{"kind": "schema_path", "ref": "x:properties/command", "detail": "free-form"}],
        confidence="high",
        provenance="deterministic",
        tool="x",
        argument="command",
    )


def test_build_and_validate():
    report = build_report("t:s", [_finding()], servers=1, tools=1)
    validate_report(report)
    assert report["summary"]["total_findings"] == 1
    assert report["summary"]["by_provenance"] == {"deterministic": 1}
    assert report["security_claims"][0]["finding_id"] == "MTM-UNCONSTRAINED-COMMAND-ARG"


def test_render_markdown_and_sarif():
    report = build_report("t:s", [_finding()], servers=1, tools=1)
    md = render_markdown(report)
    assert "MTM-UNCONSTRAINED-COMMAND-ARG" in md
    sarif = render_sarif(report)
    validate(sarif, "sarif_subset")  # SARIF subset schema
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "MTM-UNCONSTRAINED-COMMAND-ARG"
    assert result["level"] == "error"


def test_validate_rejects_unknown_id():
    report = build_report("t:s", [_finding()], servers=1, tools=1)
    report["findings"][0]["finding_id"] = "MTM-BOGUS"
    with pytest.raises(SchemaValidationError):
        validate_report(report)


def test_validate_rejects_missing_evidence():
    report = build_report("t:s", [_finding()], servers=1, tools=1)
    report["findings"][0]["evidence"] = []
    with pytest.raises(SchemaValidationError):
        validate_report(report)


def test_validate_rejects_summary_mismatch():
    report = build_report("t:s", [_finding()], servers=1, tools=1)
    report["summary"]["total_findings"] = 5
    with pytest.raises(SchemaValidationError):
        validate_report(report)


def test_validate_rejects_unbacked_claim():
    report = build_report("t:s", [_finding()], servers=1, tools=1)
    report["security_claims"].append({"finding_id": "MTM-TOKEN-PASSTHROUGH", "claim": "x"})
    with pytest.raises(SchemaValidationError):
        validate_report(report)


def test_not_applicable_not_counted():
    na = make_finding(
        "MTM-MISSING-CONSENT",
        "t:s",
        [{"kind": "config_key", "ref": "oauth/is_proxy", "detail": "n/a"}],
        confidence="low",
        provenance="deterministic",
        status="not_applicable",
    )
    report = build_report("t:s", [na], servers=1, tools=0)
    validate_report(report)
    assert report["summary"]["total_findings"] == 0
    assert report["summary"]["not_applicable"] == 1
