"""Single entry point: `mcptrustmap`.

The parser defines the complete v0.1 surface up front (Phase 0); handlers are
wired in as each phase lands. Unbuilt commands raise `NotImplementedYet` and
exit non-zero rather than pretending to succeed.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from . import __version__
from .errors import MtmError


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mcptrustmap",
        description="Audit the authority/authorization trust boundary of MCP servers.",
    )
    p.add_argument("--version", action="version", version=f"mcptrustmap {__version__}")
    sub = p.add_subparsers(dest="command", required=True, metavar="<command>")

    # --- discover: multi-client inventory ---
    d = sub.add_parser("discover", help="inventory configured MCP servers across clients")
    d.add_argument(
        "--client",
        default="all",
        help="claude_desktop|cursor|windsurf|vscode_cline|generic|all",
    )
    d.add_argument("--config-root", help="root to search for client configs (default: OS defaults)")
    d.add_argument("--out", help="write ServerRecord[] JSON here")

    # --- audit: the core flow ---
    a = sub.add_parser("audit", help="audit a server's authority/authz trust boundary")
    a.add_argument("--manifest", help="tools/list JSON manifest")
    a.add_argument("--source", help="server source directory (enables ast/llm inference)")
    a.add_argument("--policy", help="operator authority-assertion YAML")
    a.add_argument("--allowlist", help="operator server allow-list YAML (shadow-server)")
    a.add_argument("--server-record", help="path#server_id into a discover output")
    a.add_argument("--connect", action="store_true", help="ingest a live MCP server")
    a.add_argument("--transport", default="stdio", help="live transport (stdio|http|sse)")
    a.add_argument(
        "--command",
        dest="launch_command",
        help="live server launch command (with --connect)",
    )
    a.add_argument(
        "--reason",
        dest="reason",
        action="store_true",
        default=True,
        help="run the Claude reasoning layer (default on)",
    )
    a.add_argument(
        "--no-reason",
        dest="reason",
        action="store_false",
        help="deterministic-only audit (no LLM layer)",
    )
    a.add_argument(
        "--llm-mode",
        choices=["live", "replay"],
        default="replay",
        help="drive the reasoning layer live or from recorded cassettes",
    )
    a.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "info"],
        help="exit non-zero if a finding at/above this severity exists",
    )
    a.add_argument("--out", help="write the report JSON here")

    # --- corpus: batch mode ---
    c = sub.add_parser("corpus", help="batch audit over a directory of fixtures")
    csub = c.add_subparsers(dest="corpus_command", required=True, metavar="<subcommand>")
    cr = csub.add_parser("run", help="audit every server under --dir and aggregate")
    cr.add_argument("--dir", required=True, help="corpus directory")
    cr.add_argument("--llm-mode", choices=["live", "replay"], default="replay")
    cr.add_argument("--out", help="write the corpus summary JSON here")

    # --- study: empirical study harness ---
    s = sub.add_parser("study", help="empirical study over a real-server corpus")
    ssub = s.add_subparsers(dest="study_command", required=True, metavar="<subcommand>")
    sr = ssub.add_parser("run", help="run the corpus tooling and report prevalence")
    sr.add_argument("--dir", required=True, help="real-server corpus directory")
    sr.add_argument("--llm-mode", choices=["live", "replay"], default="replay")
    sr.add_argument("--out", help="write the study summary JSON here")

    # --- report: validate / render ---
    r = sub.add_parser("report", help="validate or render a report")
    rsub = r.add_subparsers(dest="report_command", required=True, metavar="<subcommand>")
    rv = rsub.add_parser("validate", help="schema-validate a report or corpus summary")
    rv.add_argument("path", help="report JSON path")
    rr = rsub.add_parser("render", help="render a report to a human format")
    rr.add_argument("path", help="report JSON path")
    rr.add_argument("--format", choices=["json", "md", "sarif"], default="md")
    rr.add_argument("--out", help="output path")

    # --- findings: registry introspection ---
    f = sub.add_parser("findings", help="introspect the finding registry")
    fsub = f.add_subparsers(dest="findings_command", required=True, metavar="<subcommand>")
    fsub.add_parser("list", help="list finding ids with OWASP mapping + severity")

    # --- serve: MCP-server entrypoint ---
    sv = sub.add_parser("serve", help="expose `audit` as an MCP tool for a host agent")
    sv.add_argument("--transport", default="stdio", help="MCP transport (stdio)")
    sv.add_argument("--self-test", action="store_true", help="start, self-check, and exit 0")

    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    from . import commands

    try:
        return commands.dispatch(args)
    except MtmError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
