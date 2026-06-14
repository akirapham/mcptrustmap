"""Inventory / shadow-server / supply-chain facts (Phase 5).

Pinning and source-trust are structural properties of the launch spec; shadow
detection compares the configured set against an operator allow-list.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..jsonio import load_yaml
from ..models import ServerRecord

_PINNED = re.compile(r"(==|@[\dv]|#[0-9a-f]{7,}|@sha\d+:)")
_UNTRUSTED_MARKERS = ("://", "git+", "github.com/", "gitlab.com/", "http:", "https:")


def is_pinned(package: str) -> bool:
    return bool(_PINNED.search(package))


def untrusted_source(server: ServerRecord) -> str | None:
    """Return a reason if the server's *install source* (package spec) is unverifiable.

    Only the package/install spec is considered — a server's endpoint URL is its
    transport, not its provenance, so it is not flagged here.
    """
    pkg = (server.package or "").lower()
    if not pkg:
        return None
    if any(marker in pkg for marker in _UNTRUSTED_MARKERS) and "registry" not in pkg:
        return f"package installs from a remote/unverifiable source: {server.package!r}"
    return None


def load_allowlist(path: str | Path) -> set[str]:
    """Load an operator allow-list (YAML `allow: [server_id, ...]`)."""
    data = load_yaml(path)
    if isinstance(data, dict):
        allow = data.get("allow", data.get("servers", []))
    elif isinstance(data, list):
        allow = data
    else:
        allow = []
    return {str(s) for s in allow}
