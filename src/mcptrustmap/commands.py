"""Dispatch parsed CLI args to phase handlers.

Handlers are added as phases land. Until then a command raises
`NotImplementedYet`, so the surface is complete (Phase 0) while the behavior
fills in incrementally.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from .errors import InputError, NotImplementedYet
from .ingest import discover
from .jsonio import dumps, validate, write_json


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


_HANDLERS = {
    "discover": cmd_discover,
    "audit": _not_yet("audit"),
    "corpus": _not_yet("corpus"),
    "study": _not_yet("study"),
    "report": _not_yet("report"),
    "findings": _not_yet("findings"),
    "serve": _not_yet("serve"),
}
