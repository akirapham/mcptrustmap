"""Dispatch parsed CLI args to phase handlers."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from .audit import audit_to_report
from .corpus import run_corpus
from .errors import InputError, NotImplementedYet
from .evidence.inventory import load_allowlist
from .findings import registry_rows
from .ingest import discover
from .ingest.manifest import parse_manifest
from .jsonio import dumps, load_json, validate, write_json
from .models import ServerRecord
from .policy import at_or_above
from .report import render_markdown, render_sarif, validate_report


def dispatch(args: argparse.Namespace) -> int:
    handler = _HANDLERS.get(args.command)
    if handler is None:  # pragma: no cover - argparse guards this
        raise NotImplementedYet(f"command {args.command!r} is not wired yet")
    return handler(args)


def _emit(payload: Any, out: str | None) -> None:
    if out:
        write_json(payload, out)
    else:
        sys.stdout.write(dumps(payload))


def _write_text(text: str, out: str | None) -> None:
    if out:
        path = Path(out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)


def _not_yet(name: str):
    def _handler(_args: argparse.Namespace) -> int:
        raise NotImplementedYet(f"`mcptrustmap {name}` is planned but not implemented yet")

    return _handler


def cmd_discover(args: argparse.Namespace) -> int:
    if not args.config_root:
        raise InputError("discover requires --config-root (OS-default search is post-v0.1)")
    records = discover(args.client, args.config_root)
    payload = [r.to_dict() for r in records]
    validate(payload, "server_record")
    _emit(payload, args.out)
    return 0


def _build_audit_target(args: argparse.Namespace) -> tuple[ServerRecord, set[str] | None]:
    allowlist = load_allowlist(args.allowlist) if args.allowlist else None

    if args.connect:
        raise NotImplementedYet("live --connect ingestion arrives in Phase 10")

    if args.manifest:
        stem = Path(args.manifest).stem
        server = ServerRecord(
            server_id=f"manifest:{stem}",
            client="generic",
            transport="stdio",
            source_path=args.source,
        )
        server.tools = parse_manifest(args.manifest)
        return server, allowlist

    if args.server_record:
        if "#" not in args.server_record:
            raise InputError("--server-record must be PATH#server_id")
        path, _, sid = args.server_record.partition("#")
        records = load_json(path)
        match = next((r for r in records if r.get("server_id") == sid), None)
        if match is None:
            raise InputError(f"server_id {sid!r} not found in {path}")
        return ServerRecord.from_dict(match), allowlist

    raise InputError("audit requires one of --manifest, --server-record, or --connect")


def cmd_audit(args: argparse.Namespace) -> int:
    server, allowlist = _build_audit_target(args)
    report = audit_to_report(
        server, allowlist=allowlist, reason=args.reason, llm_mode=args.llm_mode
    )
    _emit(report, args.out)
    if args.fail_on:
        for finding in report["findings"]:
            if finding["status"] == "not_applicable":
                continue
            if at_or_above(finding["severity"], args.fail_on):
                return 1
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    report = load_json(args.path)
    if args.report_command == "validate":
        validate_report(report)
        sys.stdout.write(f"ok: {report.get('report_id', '<report>')}\n")
        return 0
    if args.report_command == "render":
        if args.format == "json":
            _write_text(dumps(report), args.out)
        elif args.format == "md":
            _write_text(render_markdown(report), args.out)
        elif args.format == "sarif":
            sarif = render_sarif(report)
            validate(sarif, "sarif_subset")
            _write_text(dumps(sarif), args.out)
        return 0
    raise NotImplementedYet(f"report {args.report_command}")  # pragma: no cover


def cmd_corpus(args: argparse.Namespace) -> int:
    if args.corpus_command == "run":
        summary = run_corpus(args.dir, llm_mode=args.llm_mode)
        _emit(summary, args.out)
        return 0
    raise NotImplementedYet(f"corpus {args.corpus_command}")  # pragma: no cover


def cmd_findings(args: argparse.Namespace) -> int:
    if args.findings_command == "list":
        _emit(registry_rows(), getattr(args, "out", None))
        return 0
    raise NotImplementedYet(f"findings {args.findings_command}")  # pragma: no cover


_HANDLERS = {
    "discover": cmd_discover,
    "audit": cmd_audit,
    "corpus": cmd_corpus,
    "study": _not_yet("study"),
    "report": cmd_report,
    "findings": cmd_findings,
    "serve": _not_yet("serve"),
}
