#!/usr/bin/env python
"""Assert the acceptance matrix over a corpus summary.

Exits non-zero unless every required finding family has a passing positive
fixture, every entry matches its hand-authored expected outcome (zero findings
on benign controls), at least one required family is llm-verified, and both
provenances and confidence tiers are represented.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REQUIRED_FAMILIES = [
    "MTM-AUTHORITY-MISMATCH",
    "MTM-UNCONSTRAINED-COMMAND-ARG",
    "MTM-UNCONSTRAINED-PATH-ARG",
    "MTM-CREDENTIAL-ARG-EXPOSED",
    "MTM-HIGH-AUTHORITY-TOOL",
    "MTM-TOKEN-PASSTHROUGH",
    "MTM-CONFUSED-DEPUTY",
    "MTM-SCOPE-CREEP",
    "MTM-LAX-REDIRECT-URI",
    "MTM-CONTEXT-OVERSHARING",
    "MTM-TOOL-POISONING",
    "MTM-SHADOW-SERVER",
    "MTM-UNPINNED-SERVER-PACKAGE",
]


def check(summary: dict) -> list[str]:
    corpus = summary.get("corpus", {})
    families = corpus.get("families", {})
    per_server = corpus.get("per_server", [])
    errors: list[str] = []

    for fam in REQUIRED_FAMILIES:
        if fam not in families:
            errors.append(f"required family has no positive fixture: {fam}")

    for entry in per_server:
        if not entry["pass"]:
            errors.append(f"entry {entry['entry']!r} failed: {entry['reasons']}")

    provenances: set[str] = set()
    confidences: set[str] = set()
    for meta in families.values():
        provenances |= set(meta["provenances"])
        confidences |= set(meta["confidences"])

    if not any("llm-verified" in m["provenances"] for m in families.values()):
        errors.append("no llm-verified required family present (hybrid path unproven)")
    if "deterministic" not in provenances:
        errors.append("no deterministic findings represented")
    if "llm-verified" not in provenances:
        errors.append("no llm-verified findings represented")
    if len(confidences) < 2:
        errors.append(f"fewer than two confidence tiers represented: {sorted(confidences)}")

    return errors


def main(path: str) -> int:
    summary = json.loads(Path(path).read_text(encoding="utf-8"))
    errors = check(summary)
    if errors:
        print("ACCEPTANCE MATRIX FAILED:")
        for e in errors:
            print(f"  - {e}")
        return 1
    per_server = summary.get("corpus", {}).get("per_server", [])
    print(
        f"acceptance matrix OK: {len(REQUIRED_FAMILIES)} required families covered, "
        f"{len(per_server)} corpus entries passed"
    )
    return 0


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "build/evaluation/summary.json"
    raise SystemExit(main(target))
