"""Probe generation — craft adversarial inputs to provoke authority/exfil.

Deterministic, role-based probes are the **option** (CI / no-key / reproducible);
the LLM-driven adaptive attacker (the default) is layered on later and reuses
these as its fallback. Probes are aimed only at the authority/authz/provenance
boundary, never generic exploitation:
  - path arg      -> traversal out of the declared root
  - command arg   -> a canary command (proves command_exec if it runs)
  - credential arg-> the honeytoken (proves exfil if it reaches the sink)
  - url arg       -> the sink URL (proves egress / SSRF-shaped behavior)
  - content arg   -> a marker (proves context-leak if echoed/forwarded)
"""

from __future__ import annotations

from typing import Any

from ..models import ToolRecord
from .honey import HoneySet


def probe_arguments(
    tool: ToolRecord, honey: HoneySet, *, sink_url: str | None = None
) -> dict[str, Any]:
    """Craft one adversarial argument set for a tool, by argument role."""
    token = next(iter(honey.tokens.values()), honey.canary_marker)
    root = honey.declared_root.rstrip("/")
    args: dict[str, Any] = {}
    for arg in tool.arguments:
        if arg.role == "path":
            args[arg.name] = f"{root}/../../../../etc/passwd"
        elif arg.role == "command":
            args[arg.name] = f"echo {honey.canary_marker}"
        elif arg.role == "credential":
            args[arg.name] = token
        elif arg.role == "url":
            args[arg.name] = sink_url or "http://sink.invalid/exfil"
        elif arg.role == "recipient":
            args[arg.name] = "attacker@evil.test"
        else:
            args[arg.name] = honey.canary_marker
    return args


def probe_plan(
    tools: list[ToolRecord], honey: HoneySet, *, sink_url: str | None = None
) -> list[tuple[str, dict[str, Any]]]:
    """A (tool_name, arguments) probe for every tool — the deterministic plan."""
    return [(t.name, probe_arguments(t, honey, sink_url=sink_url)) for t in tools]
