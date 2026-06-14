"""The evidence graph: anchored facts produced by the deterministic layer.

An Anchor is a concrete, re-checkable pointer (`file:line`, a schema path, or a
config key). The graph indexes facts by anchor so the verification gate can
re-resolve a candidate finding's claimed anchor — the load-bearing, non-LLM
check that keeps the reasoning layer honest.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

ANCHOR_KINDS = frozenset({"file_line", "schema_path", "config_key"})
FACT_KINDS = frozenset(
    {"call", "arg", "oauth_field", "poison_marker", "inventory", "annotation", "resource"}
)


@dataclass(frozen=True)
class Anchor:
    kind: str  # file_line | schema_path | config_key
    ref: str  # e.g. "server.py:42", "run_shell:properties/command", "oauth/redirect_uris"

    def __str__(self) -> str:
        return self.ref

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "ref": self.ref}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Anchor:
        return cls(kind=d["kind"], ref=d["ref"])


@dataclass
class EvidenceFact:
    """A single deterministic fact, pinned to an anchor."""

    kind: str  # one of FACT_KINDS
    anchor: Anchor
    detail: str
    authority: str | None = None  # for `call` facts: the authority class implied
    language: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "kind": self.kind,
            "anchor": self.anchor.to_dict(),
            "detail": self.detail,
        }
        if self.authority is not None:
            d["authority"] = self.authority
        if self.language is not None:
            d["language"] = self.language
        if self.extra:
            d["extra"] = self.extra
        return d

    def evidence_ref(self) -> dict[str, str]:
        """The shape findings embed as resolved evidence."""
        return {"kind": self.anchor.kind, "ref": self.anchor.ref, "detail": self.detail}


class EvidenceGraph:
    """Facts indexed by anchor ref, for emission and gate re-resolution."""

    def __init__(self) -> None:
        self._facts: list[EvidenceFact] = []
        self._by_ref: dict[str, list[EvidenceFact]] = {}

    def add(self, fact: EvidenceFact) -> EvidenceFact:
        self._facts.append(fact)
        self._by_ref.setdefault(fact.anchor.ref, []).append(fact)
        return fact

    @property
    def facts(self) -> list[EvidenceFact]:
        return list(self._facts)

    def by_kind(self, kind: str) -> list[EvidenceFact]:
        return [f for f in self._facts if f.kind == kind]

    def at(self, ref: str) -> list[EvidenceFact]:
        """Facts at an exact anchor ref."""
        return list(self._by_ref.get(ref, []))

    def resolve(self, ref: str, *, expect_authority: str | None = None) -> bool:
        """Does a fact exist at `ref` (optionally implying `expect_authority`)?

        This is the gate's Stage-1 check: an LLM candidate whose claimed anchor
        does not resolve here is dropped before any judge call.
        """
        facts = self._by_ref.get(ref)
        if not facts:
            return False
        if expect_authority is None:
            return True
        return any(f.authority == expect_authority for f in facts)

    def to_dict(self) -> dict[str, Any]:
        return {"facts": [f.to_dict() for f in self._facts]}
