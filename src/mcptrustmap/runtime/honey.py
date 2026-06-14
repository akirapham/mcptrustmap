"""Honeytokens, honeyfiles, and canaries — the taint sources.

Each marker is unique but deterministic from a seed (so tests and replays are
reproducible). A finding is *proven* when one of these markers is observed at a
sink (egress payload, tool output, executed command).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

_PREFIX = "MTMHONEY"


def _marker(seed: str, label: str) -> str:
    digest = hashlib.sha256(f"{seed}:{label}".encode()).hexdigest()[:12]
    return f"{_PREFIX}-{label}-{digest}"


@dataclass
class HoneySet:
    """The decoys seeded into the sandbox + the server's declared boundary."""

    seed: str
    tokens: dict[str, str] = field(default_factory=dict)  # marker -> secret value
    files: dict[str, str] = field(default_factory=dict)  # path -> marker content
    canary_marker: str = ""
    declared_root: str = "/workspace"
    declared_hosts: tuple[str, ...] = ()
    exec_payload: str = ""  # an UN-evaluated shell expression to inject
    exec_proof: str = ""  # the value that appears ONLY if code evaluated it
    exec_tag: str = ""  # the proof's prefix; pair with exec_factors to build any-language probes
    exec_factors: tuple[int, int] = (0, 0)  # (a, b); the proof is tag + str(a*b)
    watch: tuple[str, ...] = ()  # known *external* secret substrings to taint on

    def markers(self) -> set[str]:
        # exec_proof is deliberately excluded: only the command-exec oracle keys on
        # it, so a computed-canary hit is execution, not a generic context leak.
        # `watch` carries real secrets a third-party target already holds (the
        # substring-taint case) — leaking one is a context leak / exfil just the same.
        return {*self.tokens, self.canary_marker, *self.files.values(), *self.watch}

    def secrets(self) -> set[str]:
        return set(self.tokens.values())


def _exec_canary(seed: str) -> tuple[int, int, str]:
    """The computed-canary components: factors (a, b) and a unique tag.

    A probe injects an un-evaluated product (shell `$((a*b))`, Python `a*b`, ...);
    if it is *reflected* the literal expression appears, but if code *executes* it
    the product `tag+str(a*b)` appears. So that string in the output ⟹ execution,
    with no syscall tracing. The attacker is given the components, never the proof —
    otherwise it could echo the proof and reflection would masquerade as execution.
    """
    digest = hashlib.sha256(f"{seed}:EXEC".encode()).hexdigest()
    a = 1000 + int(digest[:4], 16) % 9000
    b = 1000 + int(digest[4:8], 16) % 9000
    return a, b, f"MTMX{digest[8:16]}"


def mint_honey(
    seed: str,
    *,
    declared_root: str = "/workspace",
    declared_hosts: tuple[str, ...] = (),
    watch: tuple[str, ...] = (),
) -> HoneySet:
    """Deterministically mint a honey set for a server."""
    token_marker = _marker(seed, "TOKEN")
    file_marker = _marker(seed, "FILE")
    a, b, tag = _exec_canary(seed)
    return HoneySet(
        seed=seed,
        tokens={token_marker: f"sk-{token_marker}"},
        files={f"{declared_root.rstrip('/')}/secret.txt": file_marker},
        canary_marker=_marker(seed, "CANARY"),
        declared_root=declared_root,
        declared_hosts=tuple(declared_hosts),
        exec_payload=f"{tag}$(({a}*{b}))",
        exec_proof=f"{tag}{a * b}",
        exec_tag=tag,
        exec_factors=(a, b),
        watch=tuple(watch),
    )
