"""DVMCP eval adapter — drive real Damn-Vulnerable-MCP-Server challenges.

DVMCP is a labeled third-party benchmark (10 challenges). Most are *agent-level*
attacks (poisoned descriptions / hidden resources that only fire when an LLM agent
acts on them) and fall outside our authority/provenance scope. The subset we score
is the one whose **tools misbehave on a directly-crafted call**: command injection,
excessive authority, path traversal.

This module is metadata + recipe, not third-party code: each challenge knows its
in-scope verdict (ground truth), how to launch it over stdio (a shim that imports
the challenge's FastMCP object and runs it on stdin/stdout instead of uvicorn), and
the scripted attack that exposes the flaw — so the eval reproduces without a live
API. Running it needs a checkout of DVMCP (path via arg/env) and the `mcp` extra;
the captured Observation then replays deterministically in CI.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..models import Finding
from .honey import mint_honey

Attack = Callable[[dict[str, Any]], list[dict[str, Any]]]


@dataclass(frozen=True)
class DvmcpChallenge:
    cid: str  # e.g. "challenge9"
    title: str
    subpath: str  # path under the DVMCP repo root
    expect: str  # ground-truth MTM-RT finding id this challenge should yield
    attack: Attack  # arsenal -> probe list (the known exploit, scripted)
    seed: str
    declared: dict[str, dict[str, Any]] = field(default_factory=dict)
    watch: tuple[str, ...] = ()  # the challenge's own planted secrets to taint on


def stdio_shim(challenge_dir: str) -> tuple[str, list[str]]:
    """(command, args) that run a challenge's FastMCP server over stdio.

    DVMCP servers ship a uvicorn/SSE `__main__`; importing the module instead gives
    us the module-level `mcp` object, which we run on stdio without touching the
    challenge's tool logic.
    """
    src = f"import sys; sys.path.insert(0, {challenge_dir!r}); import server; server.mcp.run()"
    return sys.executable, ["-c", src]


def _ch9_attack(arsenal: dict[str, Any]) -> list[dict[str, Any]]:
    # Command injection through ping_host's shell=True; the computed canary in the
    # output proves a shell evaluated it (execution, not reflection).
    payload = arsenal["exec_payload"]
    return [
        {
            "tool": "ping_host",
            "arguments": {"host": f"127.0.0.1; echo {payload}", "count": 1},
            "rationale": "shell metacharacter injection via the host argument",
        }
    ]


# Challenge 3 plants this credential in a private file read_file should never serve.
_CH3_SECRET = "ak_live_7y2JHGd8sKlM9nPzXqRt5vWx"
_CH3_PRIVATE = "/tmp/dvmcp_challenge3/private/system_credentials.txt"  # noqa: S108 - target path


def _ch3_attack(_arsenal: dict[str, Any]) -> list[dict[str, Any]]:
    # read_file does no path confinement: read the private credential file directly.
    return [
        {
            "tool": "read_file",
            "arguments": {"filename": _CH3_PRIVATE},
            "rationale": "path-unconfined read of a private file (excessive scope)",
        }
    ]


# Challenge 7 stores this service api_key; check_email leaks it in an error log.
_CH7_SECRET = "epro_api_5f4e3d2c1b0a9z8y7x"


def _ch7_attack(_arsenal: dict[str, Any]) -> list[dict[str, Any]]:
    # An unknown folder takes the error path, which dumps the bearer token + api key.
    return [
        {
            "tool": "check_email",
            "arguments": {"folder": "audit"},
            "rationale": "error-path token disclosure via an unknown folder",
        }
    ]


def _ch8_attack(arsenal: dict[str, Any]) -> list[dict[str, Any]]:
    # Arbitrary Python execution: compute the canary in Python (not shell), so the
    # product proves the code ran. Components only — never the proof string itself.
    tag = arsenal["exec_tag"]
    a, b = arsenal["exec_factors"]
    return [
        {
            "tool": "execute_python_code",
            "arguments": {"code": f"print('{tag}' + str({a} * {b}))"},
            "rationale": "arbitrary code execution; computed canary proves the code ran",
        }
    ]


# The in-scope subset (tools that misbehave on a direct call). Extend as challenges
# are wired; out-of-scope agent-level challenges are intentionally omitted.
CHALLENGES: dict[str, DvmcpChallenge] = {
    "challenge3": DvmcpChallenge(
        cid="challenge3",
        title="Excessive Permission Scope — unconfined read_file",
        subpath="challenges/easy/challenge3",
        expect="MTM-RT-CONTEXT-LEAK",
        attack=_ch3_attack,
        seed="dvmcp3",
        watch=(_CH3_SECRET,),
    ),
    "challenge7": DvmcpChallenge(
        cid="challenge7",
        title="Token Theft — error-path leak in check_email",
        subpath="challenges/medium/challenge7",
        expect="MTM-RT-CONTEXT-LEAK",
        attack=_ch7_attack,
        seed="dvmcp7",
        watch=(_CH7_SECRET,),
    ),
    "challenge8": DvmcpChallenge(
        cid="challenge8",
        title="Malicious Code Execution — execute_python_code",
        subpath="challenges/hard/challenge8",
        expect="MTM-RT-COMMAND-EXEC",
        attack=_ch8_attack,
        seed="dvmcp8",
    ),
    "challenge9": DvmcpChallenge(
        cid="challenge9",
        title="Remote Access Control — command injection in ping_host",
        subpath="challenges/hard/challenge9",
        expect="MTM-RT-COMMAND-EXEC",
        attack=_ch9_attack,
        seed="dvmcp9",
    ),
}


def _scripted_attacker(challenge: DvmcpChallenge):  # pragma: no cover - used by live run
    from ..agent.llm_client import LLMClient
    from .attacker import LLMAttacker

    def responder(request: dict[str, Any], _ctx: dict[str, Any]) -> dict[str, Any]:
        return {"probes": challenge.attack(request["arsenal"])}

    return LLMAttacker(LLMClient.record(responder))


def capture_challenge(
    challenge: DvmcpChallenge, dvmcp_root: str, *, attacker: Any = None
):  # pragma: no cover - needs a DVMCP checkout + the mcp extra
    """Launch one challenge over stdio, drive the attack, return (Observation, honey).

    `attacker` defaults to the scripted recipe; pass a live LLMAttacker to record
    what the model itself plans. The Observation can be frozen for CI replay.
    """
    import tempfile
    from pathlib import Path

    from .sandbox import LocalStdioSandbox

    challenge_dir = str(Path(dvmcp_root) / challenge.subpath)
    command, args = stdio_shim(challenge_dir)
    honey = mint_honey(challenge.seed, declared_root="/honey", watch=challenge.watch)
    with tempfile.TemporaryDirectory(prefix="mtm-dvmcp-") as honey_dir:
        sandbox = LocalStdioSandbox(
            command,
            args,
            honey,
            honey_dir=honey_dir,
            attacker=attacker or _scripted_attacker(challenge),
        )
        return sandbox.run(), honey


def run_challenge(
    challenge: DvmcpChallenge, dvmcp_root: str, *, attacker: Any = None
) -> list[Finding]:  # pragma: no cover - needs a DVMCP checkout + the mcp extra
    """Launch one challenge and return the runtime-confirmed findings."""
    observation, honey = capture_challenge(challenge, dvmcp_root, attacker=attacker)
    from ..audit import dedupe
    from .oracles import run_oracles

    return dedupe(
        run_oracles(f"dvmcp:{challenge.cid}", observation, honey, declared=challenge.declared)
    )


def scores(challenge: DvmcpChallenge, finding_ids: set[str]) -> dict[str, Any]:
    """Did the run surface the ground-truth finding? (detection, not yet full P/R)."""
    return {
        "challenge": challenge.cid,
        "expected": challenge.expect,
        "detected": challenge.expect in finding_ids,
        "found": sorted(finding_ids),
    }
