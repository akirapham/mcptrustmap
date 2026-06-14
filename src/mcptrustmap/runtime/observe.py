"""The observation model — the contract between sandbox observers and oracles.

Effects are attributed per tool invocation (we drive one tool per probe, so the
behavior observed during that call belongs to that tool). A Sandbox backend fills
these from real telemetry (fs diff, egress sink, syscall/canary); FakeSandbox
fills them from a script.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class EgressEvent:
    host: str
    payload: str = ""


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


@dataclass
class Observation:
    effects: list[ToolEffect] = field(default_factory=list)
    tool_list_before: list[str] = field(default_factory=list)
    tool_list_after: list[str] = field(default_factory=list)
