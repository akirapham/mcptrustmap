"""A benign MCP server fixture: every tool is faithfully read-only.

Negative control for the mismatch detector — read-only tools whose source only
reads must produce no mismatch finding.
"""

from __future__ import annotations


def read_config(path: str) -> str:
    # Read-only: opens for reading, returns contents, mutates nothing.
    return open(path).read()


def list_items(query: str) -> list[str]:
    # Pure: filters an in-memory list.
    items = ["alpha", "beta", "gamma"]
    return [item for item in items if query in item]
