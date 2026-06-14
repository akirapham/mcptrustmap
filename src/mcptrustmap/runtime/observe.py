"""The observation model — the contract between sandbox observers and oracles.

Effects are attributed per tool invocation (we drive one tool per probe, so the
behavior observed during that call belongs to that tool). A Sandbox backend fills
these from real telemetry (fs diff, egress sink, syscall/canary); FakeSandbox
fills them from a script.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class EgressEvent:
    host: str
    payload: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"host": self.host, "payload": self.payload}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> EgressEvent:
        return cls(host=d["host"], payload=d.get("payload", ""))


@dataclass
class ToolEffect:
    """What one tool invocation did, as observed in the sandbox."""

    tool: str
    arguments: dict = field(default_factory=dict)
    response: str = ""
    fs_writes: list[str] = field(default_factory=list)
    fs_deletes: list[str] = field(default_factory=list)
    fs_reads: list[str] = field(default_factory=list)
    egress: list[EgressEvent] = field(default_factory=list)
    execs: list[str] = field(default_factory=list)

    def mutating_authorities(self) -> set[str]:
        """Authority classes the tool actually exercised (mutating only)."""
        actual: set[str] = set()
        if self.fs_writes or self.fs_deletes:
            actual.add("filesystem")
        if self.execs:
            actual.add("command_exec")
        if self.egress:
            actual.add("network")
        return actual

    def fs_touches(self) -> list[str]:
        return [*self.fs_reads, *self.fs_writes, *self.fs_deletes]

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "arguments": self.arguments,
            "response": self.response,
            "fs_writes": self.fs_writes,
            "fs_deletes": self.fs_deletes,
            "fs_reads": self.fs_reads,
            "egress": [e.to_dict() for e in self.egress],
            "execs": self.execs,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ToolEffect:
        return cls(
            tool=d["tool"],
            arguments=d.get("arguments", {}),
            response=d.get("response", ""),
            fs_writes=list(d.get("fs_writes", [])),
            fs_deletes=list(d.get("fs_deletes", [])),
            fs_reads=list(d.get("fs_reads", [])),
            egress=[EgressEvent.from_dict(e) for e in d.get("egress", [])],
            execs=list(d.get("execs", [])),
        )


@dataclass
class Observation:
    effects: list[ToolEffect] = field(default_factory=list)
    tool_list_before: list[str] = field(default_factory=list)
    tool_list_after: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "effects": [e.to_dict() for e in self.effects],
            "tool_list_before": self.tool_list_before,
            "tool_list_after": self.tool_list_after,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Observation:
        return cls(
            effects=[ToolEffect.from_dict(e) for e in d.get("effects", [])],
            tool_list_before=list(d.get("tool_list_before", [])),
            tool_list_after=list(d.get("tool_list_after", [])),
        )
