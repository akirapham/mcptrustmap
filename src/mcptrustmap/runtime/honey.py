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
    exec_proof: str = ""  # the value that appears ONLY if a shell evaluated it

    def markers(self) -> set[str]:
        # exec_proof is deliberately excluded: only the command-exec oracle keys on
        # it, so a computed-canary hit is execution, not a generic context leak.
        return {*self.tokens, self.canary_marker, *self.files.values()}

    def secrets(self) -> set[str]:
        return set(self.tokens.values())


def _exec_canary(seed: str) -> tuple[str, str]:
    """A computed canary: (payload to inject, proof string only a shell can produce).

    The payload carries an un-evaluated `$((a*b))`; if it is *reflected* the literal
    expression appears, but if a shell *executes* it the product appears — which is
    exactly `exec_proof`. So `exec_proof in output` ⟹ command execution, with no
    syscall tracing.
    """
    digest = hashlib.sha256(f"{seed}:EXEC".encode()).hexdigest()
    a = 1000 + int(digest[:4], 16) % 9000
    b = 1000 + int(digest[4:8], 16) % 9000
    tag = f"MTMX{digest[8:16]}"
    return f"{tag}$(({a}*{b}))", f"{tag}{a * b}"


def mint_honey(
    seed: str,
    *,
    declared_root: str = "/workspace",
    declared_hosts: tuple[str, ...] = (),
) -> HoneySet:
    """Deterministically mint a honey set for a server."""
    token_marker = _marker(seed, "TOKEN")
    file_marker = _marker(seed, "FILE")
    exec_payload, exec_proof = _exec_canary(seed)
    return HoneySet(
        seed=seed,
        tokens={token_marker: f"sk-{token_marker}"},
        files={f"{declared_root.rstrip('/')}/secret.txt": file_marker},
        canary_marker=_marker(seed, "CANARY"),
        declared_root=declared_root,
        declared_hosts=tuple(declared_hosts),
        exec_payload=exec_payload,
        exec_proof=exec_proof,
    )
