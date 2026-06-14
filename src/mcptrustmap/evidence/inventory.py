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
    """Return a reason string if the server launches from an untrusted source."""
    candidates = [server.package or "", server.url or "", *server.args]
    for value in candidates:
        v = value.lower()
        if any(marker in v for marker in _UNTRUSTED_MARKERS) and "registry" not in v:
            return f"launch references a remote/untrusted source: {value!r}"
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
