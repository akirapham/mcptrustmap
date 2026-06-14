"""Corpus / batch mode: audit every entry under a directory and aggregate.

Each entry is a directory with an `entry.json` describing how to build the
server (manifest [+source], or a server-record), plus the `expected` outcomes
(the authoritative oracle — hand-authored from the threat, never derived from a
cassette). The aggregate is itself a valid report, with a `corpus` block of
per-entry pass/fail and family coverage.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .audit import audit_to_report
from .errors import InputError
from .evidence.inventory import load_allowlist
from .ingest.manifest import parse_manifest
from .jsonio import load_json
from .models import Finding, ServerRecord
from .report import build_report, validate_report


def _find_repo_root(start: Path) -> Path:
    for parent in [start, *start.resolve().parents]:
        if (parent / "pyproject.toml").exists():
            return parent
    return start.resolve()


def _build_from_spec(spec: dict[str, Any], root: Path) -> tuple[ServerRecord, set[str] | None]:
    server_id = spec["server_id"]
    if spec.get("server_record"):
        record = load_json(root / spec["server_record"])
        server = ServerRecord.from_dict(record)
        server.server_id = server_id
    elif spec.get("manifest"):
        source = str(root / spec["source"]) if spec.get("source") else None
        server = ServerRecord(
            server_id=server_id, client="generic", transport="stdio", source_path=source
        )
        server.tools = parse_manifest(root / spec["manifest"])
    else:
        raise InputError(f"corpus entry {server_id!r} needs a manifest or server_record")
    allowlist = load_allowlist(root / spec["allowlist"]) if spec.get("allowlist") else None
    return server, allowlist


def _evaluate_entry(
    findings: list[dict[str, Any]], expected: dict[str, Any]
) -> tuple[bool, list[str]]:
    active = [f for f in findings if f["status"] != "not_applicable"]
    actual_ids = {f["finding_id"] for f in active}
    reasons: list[str] = []

    if expected.get("benign"):
        if active:
            reasons.append(f"benign control produced findings: {sorted(actual_ids)}")
        return (not reasons), reasons

    for required in expected.get("finding_ids", []):
        if required not in actual_ids:
            reasons.append(f"missing expected finding: {required}")

    for required in expected.get("llm_verified", []):
        ok = any(f["finding_id"] == required and f["provenance"] == "llm-verified" for f in active)
        if not ok:
            reasons.append(f"missing expected llm-verified finding: {required}")

    return (not reasons), reasons


def _families_summary(findings: list[Finding]) -> dict[str, Any]:
    families: dict[str, Any] = {}
    for f in findings:
        if f.status == "not_applicable":
            continue
        entry = families.setdefault(
            f.finding_id, {"count": 0, "provenances": set(), "confidences": set()}
        )
        entry["count"] += 1
        entry["provenances"].add(f.provenance)
        entry["confidences"].add(f.confidence)
    return {
        fid: {
            "count": e["count"],
            "provenances": sorted(e["provenances"]),
            "confidences": sorted(e["confidences"]),
        }
        for fid, e in sorted(families.items())
    }


def run_corpus(
    corpus_dir: str | Path, *, llm_mode: str = "replay", repo_root: str | Path | None = None
) -> dict[str, Any]:
    corpus_path = Path(corpus_dir)
    root = Path(repo_root) if repo_root else _find_repo_root(corpus_path)
    entry_dirs = sorted(
        p for p in corpus_path.iterdir() if p.is_dir() and (p / "entry.json").is_file()
    )
    if not entry_dirs:
        raise InputError(f"no corpus entries (dirs with entry.json) under {corpus_path}")

    all_findings: list[Finding] = []
    per_server: list[dict[str, Any]] = []
    total_tools = 0

    for entry_dir in entry_dirs:
        spec = load_json(entry_dir / "entry.json")
        server, allowlist = _build_from_spec(spec, root)
        report = audit_to_report(
            server, allowlist=allowlist, reason=bool(spec.get("reason", False)), llm_mode=llm_mode
        )
        findings = report["findings"]
        total_tools += report["inventory"]["tools"]
        all_findings.extend(Finding.from_dict(f) for f in findings)
        expected = spec.get("expected", {})
        passed, reasons = _evaluate_entry(findings, expected)
        active = [f for f in findings if f["status"] != "not_applicable"]
        per_server.append(
            {
                "entry": entry_dir.name,
                "server_id": server.server_id,
                "findings": report["summary"]["total_findings"],
                "finding_ids": sorted({f["finding_id"] for f in active}),
                "provenances": sorted({f["provenance"] for f in active}),
                "pass": passed,
                "reasons": reasons,
            }
        )

    summary = build_report(
        f"corpus:{corpus_path.name}", all_findings, servers=len(entry_dirs), tools=total_tools
    )
    summary["corpus"] = {
        "per_server": per_server,
        "families": _families_summary(all_findings),
        "metrics": {
            "servers": len(entry_dirs),
            "passed": sum(1 for s in per_server if s["pass"]),
        },
    }
    validate_report(summary)
    return summary
