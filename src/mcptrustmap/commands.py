"""Dispatch parsed CLI args to phase handlers.

Handlers are added as phases land. Until then a command raises
`NotImplementedYet`, so the surface is complete (Phase 0) while the behavior
fills in incrementally.
"""

from __future__ import annotations

import argparse

from .errors import NotImplementedYet


def dispatch(args: argparse.Namespace) -> int:
    handler = _HANDLERS.get(args.command)
    if handler is None:  # pragma: no cover - argparse guards this
        raise NotImplementedYet(f"command {args.command!r} is not wired yet")
    return handler(args)


def _not_yet(name: str):
    def _handler(_args: argparse.Namespace) -> int:
        raise NotImplementedYet(f"`mcptrustmap {name}` is planned but not implemented yet")

    return _handler


# Wired incrementally per phase. Phase 0 ships the surface; behavior follows.
_HANDLERS = {
    "discover": _not_yet("discover"),
    "audit": _not_yet("audit"),
    "corpus": _not_yet("corpus"),
    "study": _not_yet("study"),
    "report": _not_yet("report"),
    "findings": _not_yet("findings"),
    "serve": _not_yet("serve"),
}
