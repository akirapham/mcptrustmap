"""Ingestion (I/O boundary): offline manifest, multi-client discovery, live MCP."""

from __future__ import annotations

from .discovery import CLIENT_CONFIG_NAMES, discover, parse_client_config
from .manifest import arguments_from_schema, parse_manifest

__all__ = [
    "CLIENT_CONFIG_NAMES",
    "arguments_from_schema",
    "discover",
    "parse_client_config",
    "parse_manifest",
]
