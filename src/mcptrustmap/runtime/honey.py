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

    def markers(self) -> set[str]:
        return {*self.tokens, self.canary_marker, *self.files.values()}

    def secrets(self) -> set[str]:
        return set(self.tokens.values())


def mint_honey(
    seed: str,
    *,
    declared_root: str = "/workspace",
    declared_hosts: tuple[str, ...] = (),
) -> HoneySet:
    """Deterministically mint a honey set for a server."""
    token_marker = _marker(seed, "TOKEN")
    file_marker = _marker(seed, "FILE")
    return HoneySet(
        seed=seed,
        tokens={token_marker: f"sk-{token_marker}"},
        files={f"{declared_root.rstrip('/')}/secret.txt": file_marker},
        canary_marker=_marker(seed, "CANARY"),
        declared_root=declared_root,
        declared_hosts=tuple(declared_hosts),
    )
