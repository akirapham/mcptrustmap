"""Report engine: build, validate (fail-closed), and render JSON / Markdown / SARIF.

A report is the audit's contract. Validation is schema + semantic: unknown ids,
unknown severities/OWASP/provenance, missing evidence, mismatched summary counts,
unbacked security claims, or `not_applicable` miscounted as a finding all fail.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from . import SCHEMA_VERSION, __version__
from .errors import SchemaValidationError
from .findings import REGISTRY, spec_for
from .jsonio import dumps, validate
from .models import Finding
from .policy import CONFIDENCES, OWASP_MCP_IDS, PROVENANCES, SEVERITIES

OWASP_MATURITY = "OWASP MCP Top 10 (beta/v0.1 Incubator)"

_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _counts(items: list[str]) -> dict[str, int]:
    return dict(sorted(Counter(items).items()))


def build_report(
    target: str,
    findings: list[Finding],
    *,
    servers: int,
    tools: int,
    cassette_set: str | None = None,
) -> dict[str, Any]:
    active = [f for f in findings if f.status != "not_applicable"]
    not_applicable = [f for f in findings if f.status == "not_applicable"]

    distinct_ids = sorted({f.finding_id for f in active})
    security_claims = [{"finding_id": fid, "claim": spec_for(fid).title} for fid in distinct_ids]

    return {
        "report_id": f"mtm-report:{target}",
        "tool_version": __version__,
        "schema_version": SCHEMA_VERSION,
        "target": target,
        "owasp_maturity": OWASP_MATURITY,
        "findings": [f.to_dict() for f in findings],
        "summary": {
            "total_findings": len(active),
            "not_applicable": len(not_applicable),
            "by_severity": _counts([f.severity for f in active]),
            "by_owasp": _counts([f.owasp for f in active]),
            "by_provenance": _counts([f.provenance for f in active]),
        },
        "inventory": {"servers": servers, "tools": tools},
        "security_claims": security_claims,
        "reproducibility": {"deterministic_core": __version__, "cassette_set": cassette_set},
    }


def validate_report(report: dict[str, Any]) -> None:
    """Schema-validate then apply fail-closed semantic checks."""
    validate(report, "report")

    active_ids: list[str] = []
    for finding in report["findings"]:
        fid = finding["finding_id"]
        if fid not in REGISTRY:
            raise SchemaValidationError(f"unknown finding id in report: {fid!r}")
        if finding["severity"] not in SEVERITIES:
            raise SchemaValidationError(f"unknown severity: {finding['severity']!r}")
        if finding["owasp"] not in OWASP_MCP_IDS:
            raise SchemaValidationError(f"unknown OWASP id: {finding['owasp']!r}")
        if finding["confidence"] not in CONFIDENCES:
            raise SchemaValidationError(f"unknown confidence: {finding['confidence']!r}")
        if finding["provenance"] not in PROVENANCES:
            raise SchemaValidationError(f"unknown provenance: {finding['provenance']!r}")
        if not finding["evidence"]:
            raise SchemaValidationError(f"finding {fid!r} has no evidence")
        if finding["status"] != "not_applicable":
            active_ids.append(fid)

    summary = report["summary"]
    if summary["total_findings"] != len(active_ids):
        raise SchemaValidationError(
            f"summary.total_findings ({summary['total_findings']}) "
            f"!= active findings ({len(active_ids)})"
        )

    backed = set(active_ids)
    for claim in report["security_claims"]:
        if claim["finding_id"] not in REGISTRY:
            raise SchemaValidationError(
                f"security claim references unknown id: {claim['finding_id']!r}"
            )
        if claim["finding_id"] not in backed:
            raise SchemaValidationError(
                f"security claim {claim['finding_id']!r} is not backed by an active finding"
            )


def render_json(report: dict[str, Any]) -> str:
    return dumps(report)


def render_markdown(report: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"# MCPTrustMap report — `{report['target']}`")
    lines.append("")
    lines.append(f"_{report['owasp_maturity']}_ · tool v{report['tool_version']}")
    lines.append("")
    summary = report["summary"]
    inv = report["inventory"]
    lines.append(
        f"**{summary['total_findings']} findings** "
        f"({inv['servers']} server(s), {inv['tools']} tool(s); "
        f"{summary['not_applicable']} not-applicable)"
    )
    lines.append("")
    if summary["by_severity"]:
        sev = ", ".join(f"{k}: {v}" for k, v in summary["by_severity"].items())
        lines.append(f"- By severity: {sev}")
    if summary["by_owasp"]:
        ow = ", ".join(f"{k}: {v}" for k, v in summary["by_owasp"].items())
        lines.append(f"- By OWASP MCP: {ow}")
    if summary["by_provenance"]:
        pr = ", ".join(f"{k}: {v}" for k, v in summary["by_provenance"].items())
        lines.append(f"- By provenance: {pr}")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    active = [f for f in report["findings"] if f["status"] != "not_applicable"]
    if not active:
        lines.append("_No findings._")
    for f in active:
        loc = f.get("tool") or f["server_id"]
        lines.append(f"### `{f['finding_id']}` — {f['title']}")
        lines.append("")
        lines.append(
            f"- **{f['severity']}** · {f['owasp']} · confidence {f['confidence']} "
            f"· {f['provenance']} · `{loc}`"
        )
        if f.get("spec_ref"):
            lines.append(f"- Spec: {f['spec_ref']}")
        for ev in f["evidence"]:
            detail = f" — {ev['detail']}" if ev.get("detail") else ""
            lines.append(f"- Evidence (`{ev['kind']}`): `{ev['ref']}`{detail}")
        lines.append(f"- Recommendation: {f['recommendation']}")
        lines.append("")
    return "\n".join(lines) + "\n"


def render_sarif(report: dict[str, Any]) -> dict[str, Any]:
    active = [f for f in report["findings"] if f["status"] != "not_applicable"]
    rule_ids = sorted({f["finding_id"] for f in active})
    rules = [
        {
            "id": fid,
            "name": fid,
            "shortDescription": {"text": spec_for(fid).title},
        }
        for fid in rule_ids
    ]
    results = []
    for f in active:
        locations = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": ev["ref"]},
                }
            }
            for ev in f["evidence"]
        ]
        results.append(
            {
                "ruleId": f["finding_id"],
                "level": _SARIF_LEVEL[f["severity"]],
                "message": {"text": f"{f['title']} ({f['owasp']}) — {f['recommendation']}"},
                "locations": locations,
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MCPTrustMap",
                        "version": report["tool_version"],
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
