"""Sandbox backends — where the untrusted server runs and behavior is observed.

`Sandbox.run()` returns an Observation. `FakeSandbox` replays a scripted one (the
deterministic test/oracle path). `DockerSandbox` runs a real untrusted server in
an isolated container with honey seeding + an egress sink + a driver — the
production backend, filled in the next runtime increment.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..errors import NotImplementedYet
from .honey import HoneySet
from .observe import Observation


class Sandbox(ABC):
    @abstractmethod
    def run(self) -> Observation:
        """Exercise the server and return what was observed."""


class FakeSandbox(Sandbox):
    """A scripted sandbox: returns a preset Observation (for tests + oracle dev)."""

    def __init__(self, observation: Observation) -> None:
        self._observation = observation

    def run(self) -> Observation:
        return self._observation


class DockerSandbox(Sandbox):
    """Run an untrusted MCP server in Docker: honey-seeded fs, egress sink, driver.

    Non-root, dropped caps, read-only rootfs except the honey dir, seccomp,
    no host mounts, network routed only to the sink, resource/time limits.
    Implemented in the next increment (Docker runner + sink + driver).
    """

    def __init__(self, image: str, honey: HoneySet, *, probes: list | None = None) -> None:
        self.image = image
        self.honey = honey
        self.probes = probes or []

    def run(self) -> Observation:  # pragma: no cover - lands in the next increment
        raise NotImplementedYet(
            "DockerSandbox runner (container + egress sink + driver) is the next runtime increment"
        )
