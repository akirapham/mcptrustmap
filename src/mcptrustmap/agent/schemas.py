"""Structured outputs for the reasoning layer: CandidateFinding and Verdict.

Dataclasses + JSON Schema validation (stdlib only, so the core needs no pydantic).
In `live` mode these are produced via the Anthropic structured-output / strict
`emit_finding` tool; in `replay` mode they come from recorded cassettes. Either
way they validate against the checked-in schemas before the gate sees them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..evidence.graph import Anchor
from ..jsonio import validate


@dataclass
class CandidateFinding:
    """A proposed finding from the LLM layer. Never reported without gate approval."""

    finding_id: str
    server_id: str
    claimed_anchor: Anchor
    rationale: str
    tool: str | None = None
    argument: str | None = None
    proposed_severity: str | None = None
    sub_type: str | None = None
    expect_authority: str | None = None  # authority class to confirm at the anchor

    def key(self) -> str:
        return f"{self.server_id}|{self.finding_id}|{self.tool or ''}|{self.claimed_anchor.ref}"

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "finding_id": self.finding_id,
            "server_id": self.server_id,
            "claimed_anchor": self.claimed_anchor.to_dict(),
            "rationale": self.rationale,
        }
        for k in ("tool", "argument", "proposed_severity", "sub_type", "expect_authority"):
            v = getattr(self, k)
            if v is not None:
                d[k] = v
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CandidateFinding:
        return cls(
            finding_id=d["finding_id"],
            server_id=d["server_id"],
            claimed_anchor=Anchor.from_dict(d["claimed_anchor"]),
            rationale=d["rationale"],
            tool=d.get("tool"),
            argument=d.get("argument"),
            proposed_severity=d.get("proposed_severity"),
            sub_type=d.get("sub_type"),
            expect_authority=d.get("expect_authority"),
        )


@dataclass
class Verdict:
    """One judge vote, from a distinct lens."""

    lens: str  # source | declaration | mapping
    refuted: bool
    reason: str
    anchor_confirmed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "lens": self.lens,
            "refuted": self.refuted,
            "reason": self.reason,
            "anchor_confirmed": self.anchor_confirmed,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Verdict:
        return cls(
            lens=d["lens"],
            refuted=bool(d["refuted"]),
            reason=d.get("reason", ""),
            anchor_confirmed=bool(d.get("anchor_confirmed", False)),
        )


def parse_candidates(payload: dict[str, Any], server_id: str) -> list[CandidateFinding]:
    """Validate a reason-response payload and return CandidateFinding[]."""
    validate(payload, "candidate_finding")
    return [
        CandidateFinding.from_dict({**c, "server_id": server_id}) for c in payload["candidates"]
    ]


def parse_verdicts(payload: dict[str, Any]) -> list[Verdict]:
    validate(payload, "verdict")
    return [Verdict.from_dict(v) for v in payload["verdicts"]]
