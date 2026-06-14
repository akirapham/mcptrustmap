"""Runtime pentest harness: sandbox -> drive -> observe -> prove.

The base loop is deterministic given an Observation: oracles turn observed
behavior (honeytoken markers reaching sinks, filesystem effects, canary execs)
into MTM-RT-* findings (provenance: runtime-confirmed). The Docker sandbox
backend (which produces real Observations from untrusted servers) is a swappable
Sandbox implementation; FakeSandbox replays a scripted Observation for tests.
"""

from __future__ import annotations

from .harness import pentest_server, pentest_to_report
from .honey import HoneySet, mint_honey
from .observe import EgressEvent, Observation, ToolEffect
from .oracles import run_oracles
from .sandbox import DockerSandbox, FakeSandbox, Sandbox

__all__ = [
    "DockerSandbox",
    "EgressEvent",
    "FakeSandbox",
    "HoneySet",
    "Observation",
    "Sandbox",
    "ToolEffect",
    "mint_honey",
    "pentest_server",
    "pentest_to_report",
    "run_oracles",
]
