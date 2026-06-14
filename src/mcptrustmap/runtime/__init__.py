"""Runtime pentest harness: sandbox -> drive -> observe -> prove.

The base loop is deterministic given an Observation: oracles turn observed
behavior (honeytoken markers reaching sinks, filesystem effects, canary execs)
into MTM-RT-* findings (provenance: runtime-confirmed). The Docker sandbox
backend (which produces real Observations from untrusted servers) is a swappable
Sandbox implementation; FakeSandbox replays a scripted Observation for tests.
"""

from __future__ import annotations

from .attacker import LLMAttacker, build_attack_request, parse_attack_plan
from .harness import pentest_server, pentest_to_report
from .honey import HoneySet, mint_honey
from .observe import EgressEvent, Observation, ToolEffect
from .oracles import run_oracles
from .probes import probe_arguments, probe_plan
from .sandbox import DockerSandbox, FakeSandbox, LocalStdioSandbox, Sandbox
from .sink import EgressSink

__all__ = [
    "DockerSandbox",
    "EgressEvent",
    "EgressSink",
    "FakeSandbox",
    "HoneySet",
    "LLMAttacker",
    "LocalStdioSandbox",
    "Observation",
    "Sandbox",
    "build_attack_request",
    "parse_attack_plan",
    "ToolEffect",
    "mint_honey",
    "pentest_server",
    "pentest_to_report",
    "probe_arguments",
    "probe_plan",
    "run_oracles",
]
